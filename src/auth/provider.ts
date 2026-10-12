import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import {
  InvalidGrantError,
  InvalidTargetError,
  InvalidTokenError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type {
  AuthorizationParams,
  OAuthServerProvider,
} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type { Response } from 'express';
import { renderConsentPage } from './consent-page.js';

export const SCOPES = {
  read: 'tasks:read',
  write: 'tasks:write',
} as const;
export const ALL_SCOPES = [SCOPES.read, SCOPES.write];

/** The single resource owner of this template. Replace with real user ids when you add an IdP. */
export const OWNER_ID = 'owner';

const AUTHORIZATION_CODE_TTL_S = 300;
const PENDING_REQUEST_TTL_S = 600;
const MAX_PASSWORD_ATTEMPTS = 5;

interface PendingAuthorization {
  client: OAuthClientInformationFull;
  params: AuthorizationParams;
  scopes: string[];
  expiresAt: number;
  failedAttempts: number;
}

interface AuthorizationCode {
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
  scopes: string[];
  resource: string;
  ownerId: string;
  expiresAt: number;
}

interface TokenRecord {
  kind: 'access' | 'refresh';
  clientId: string;
  scopes: string[];
  resource: string;
  ownerId: string;
  expiresAt: number;
  /** Refresh tokens point at the access token issued with them, so revoking one revokes both. */
  pairedHash: string;
}

export interface ProviderOptions {
  ownerPassword: string;
  /** Canonical URL of the MCP endpoint, e.g. https://example.com/mcp. Tokens are bound to it. */
  resourceUrl: URL;
  accessTokenTtl: number;
  refreshTokenTtl: number;
  now?: () => number;
}

export type ConsentDecision =
  | { kind: 'redirect'; location: string }
  | { kind: 'retry'; html: string }
  | { kind: 'expired' };

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const opaqueToken = () => randomBytes(32).toString('base64url');

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(sha256(a));
  const right = Buffer.from(sha256(b));
  return timingSafeEqual(left, right);
}

class InMemoryClientsStore implements OAuthRegisteredClientsStore {
  readonly #clients = new Map<string, OAuthClientInformationFull>();

  getClient(clientId: string) {
    return this.#clients.get(clientId);
  }

  registerClient(client: OAuthClientInformationFull) {
    this.#clients.set(client.client_id, client);
    return client;
  }
}

/**
 * A complete OAuth 2.1 authorization server for a single owner:
 * dynamic client registration, PKCE, a password-protected consent screen,
 * audience-bound opaque tokens (RFC 8707) and refresh-token rotation.
 *
 * Everything lives in memory and tokens are stored hashed. Restarting the
 * process signs every client out; plug a database in behind the same
 * interface for production use.
 */
export class OwnerOAuthProvider implements OAuthServerProvider {
  readonly clientsStore = new InMemoryClientsStore();
  readonly #pending = new Map<string, PendingAuthorization>();
  readonly #codes = new Map<string, AuthorizationCode>();
  readonly #tokens = new Map<string, TokenRecord>();
  readonly #options: ProviderOptions;
  readonly #now: () => number;

  constructor(options: ProviderOptions) {
    this.#options = options;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  get resource(): string {
    return this.#options.resourceUrl.href;
  }

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response,
  ): Promise<void> {
    this.#assertResource(params.resource);
    const requested = params.scopes?.length ? params.scopes : ALL_SCOPES;
    const unknown = requested.filter((s) => !ALL_SCOPES.includes(s as never));
    const scopes = requested.filter((s) => ALL_SCOPES.includes(s as never));

    if (unknown.length > 0 || scopes.length === 0) {
      const target = new URL(params.redirectUri);
      target.searchParams.set('error', 'invalid_scope');
      target.searchParams.set('error_description', `Unsupported scope: ${unknown.join(' ')}`);
      if (params.state) target.searchParams.set('state', params.state);
      res.redirect(302, target.href);
      return;
    }

    this.#sweep();
    const requestId = opaqueToken();
    this.#pending.set(requestId, {
      client,
      params,
      scopes,
      expiresAt: this.#now() + PENDING_REQUEST_TTL_S,
      failedAttempts: 0,
    });
    sendConsentPage(res, renderConsentPage({ requestId, client, scopes }));
  }

  /**
   * Handles the form posted by the consent page. The request id is a single-use,
   * unguessable value tied to the original /authorize call, so it doubles as a CSRF token.
   */
  decideConsent(input: {
    requestId: string;
    password: string;
    approve: boolean;
    grantWrite: boolean;
  }): ConsentDecision {
    const pending = this.#pending.get(input.requestId);
    if (!pending || pending.expiresAt < this.#now()) {
      this.#pending.delete(input.requestId);
      return { kind: 'expired' };
    }

    const target = new URL(pending.params.redirectUri);
    if (pending.params.state) target.searchParams.set('state', pending.params.state);

    if (!input.approve) {
      this.#pending.delete(input.requestId);
      target.searchParams.set('error', 'access_denied');
      return { kind: 'redirect', location: target.href };
    }

    if (!safeEqual(input.password, this.#options.ownerPassword)) {
      pending.failedAttempts += 1;
      if (pending.failedAttempts >= MAX_PASSWORD_ATTEMPTS) {
        this.#pending.delete(input.requestId);
        target.searchParams.set('error', 'access_denied');
        target.searchParams.set('error_description', 'Too many failed attempts');
        return { kind: 'redirect', location: target.href };
      }
      return {
        kind: 'retry',
        html: renderConsentPage({
          requestId: input.requestId,
          client: pending.client,
          scopes: pending.scopes,
          error: 'Wrong password.',
        }),
      };
    }

    this.#pending.delete(input.requestId);
    const scopes = input.grantWrite
      ? pending.scopes
      : pending.scopes.filter((s) => s !== SCOPES.write);
    if (scopes.length === 0) {
      target.searchParams.set('error', 'access_denied');
      target.searchParams.set('error_description', 'No scopes were granted');
      return { kind: 'redirect', location: target.href };
    }

    const code = opaqueToken();
    this.#codes.set(sha256(code), {
      clientId: pending.client.client_id,
      codeChallenge: pending.params.codeChallenge,
      redirectUri: pending.params.redirectUri,
      scopes,
      resource: this.resource,
      ownerId: OWNER_ID,
      expiresAt: this.#now() + AUTHORIZATION_CODE_TTL_S,
    });
    target.searchParams.set('code', code);
    return { kind: 'redirect', location: target.href };
  }

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    return this.#readCode(client, authorizationCode).codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const record = this.#readCode(client, authorizationCode);
    // Codes are single use: delete before issuing so a replay can never mint a second pair.
    this.#codes.delete(sha256(authorizationCode));
    if (redirectUri !== undefined && redirectUri !== record.redirectUri) {
      throw new InvalidGrantError('redirect_uri does not match the authorization request');
    }
    this.#assertResource(resource);
    return this.#issueTokens(client.client_id, record.scopes, record.ownerId);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const hash = sha256(refreshToken);
    const record = this.#tokens.get(hash);
    if (!record || record.kind !== 'refresh' || record.clientId !== client.client_id) {
      throw new InvalidGrantError('Invalid refresh token');
    }
    if (record.expiresAt < this.#now()) {
      this.#tokens.delete(hash);
      throw new InvalidGrantError('Refresh token expired');
    }
    this.#assertResource(resource);
    const narrowed = scopes?.length ? scopes : record.scopes;
    if (narrowed.some((s) => !record.scopes.includes(s))) {
      throw new InvalidGrantError('Requested scopes exceed the original grant');
    }
    // Rotation: the old refresh token and its access token stop working immediately.
    this.#tokens.delete(hash);
    this.#tokens.delete(record.pairedHash);
    return this.#issueTokens(client.client_id, narrowed, record.ownerId);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const record = this.#tokens.get(sha256(token));
    if (!record || record.kind !== 'access') throw new InvalidTokenError('Unknown access token');
    if (record.expiresAt < this.#now()) {
      this.#tokens.delete(sha256(token));
      throw new InvalidTokenError('Access token expired');
    }
    return {
      token,
      clientId: record.clientId,
      scopes: record.scopes,
      expiresAt: record.expiresAt,
      resource: new URL(record.resource),
      extra: { ownerId: record.ownerId },
    };
  }

  async revokeToken(
    client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest,
  ): Promise<void> {
    const hash = sha256(request.token);
    const record = this.#tokens.get(hash);
    if (!record || record.clientId !== client.client_id) return;
    this.#tokens.delete(hash);
    this.#tokens.delete(record.pairedHash);
  }

  #issueTokens(clientId: string, scopes: string[], ownerId: string): OAuthTokens {
    this.#sweep();
    const accessToken = opaqueToken();
    const refreshToken = opaqueToken();
    const accessHash = sha256(accessToken);
    const refreshHash = sha256(refreshToken);
    const base = { clientId, scopes, ownerId, resource: this.resource };
    this.#tokens.set(accessHash, {
      ...base,
      kind: 'access',
      expiresAt: this.#now() + this.#options.accessTokenTtl,
      pairedHash: refreshHash,
    });
    this.#tokens.set(refreshHash, {
      ...base,
      kind: 'refresh',
      expiresAt: this.#now() + this.#options.refreshTokenTtl,
      pairedHash: accessHash,
    });
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.#options.accessTokenTtl,
      refresh_token: refreshToken,
      scope: scopes.join(' '),
    };
  }

  #readCode(client: OAuthClientInformationFull, code: string): AuthorizationCode {
    const record = this.#codes.get(sha256(code));
    if (!record || record.clientId !== client.client_id) {
      throw new InvalidGrantError('Invalid authorization code');
    }
    if (record.expiresAt < this.#now()) {
      this.#codes.delete(sha256(code));
      throw new InvalidGrantError('Authorization code expired');
    }
    return record;
  }

  #assertResource(resource: URL | undefined): void {
    // RFC 8707: a client may omit `resource`, but if it names one it must be this server.
    if (resource && stripFragment(resource) !== this.resource) {
      throw new InvalidTargetError(`This server only issues tokens for ${this.resource}`);
    }
  }

  /** Drops expired entries so long-running processes do not grow without bound. */
  #sweep(): void {
    const now = this.#now();
    for (const map of [this.#pending, this.#codes, this.#tokens] as Map<
      string,
      { expiresAt: number }
    >[]) {
      for (const [key, value] of map) if (value.expiresAt < now) map.delete(key);
    }
  }
}

function stripFragment(url: URL): string {
  const copy = new URL(url.href);
  copy.hash = '';
  return copy.href;
}

export function sendConsentPage(res: Response, html: string, status = 200): void {
  res
    .status(status)
    .set({
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Frame-Options': 'DENY',
      'Content-Security-Policy':
        // No form-action: Chrome applies it to the post-consent redirect to the client.
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
      'Referrer-Policy': 'no-referrer',
    })
    .send(html);
}
