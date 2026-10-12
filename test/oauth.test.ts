import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  authorize,
  exchangeCode,
  type Harness,
  PASSWORD,
  pkcePair,
  registerClient,
  requestIdFrom,
  startAuthorization,
  startServer,
  submitConsent,
} from './helpers.js';

let h: Harness;
beforeEach(async () => {
  h = await startServer();
});
afterEach(async () => {
  await h.close();
});

describe('discovery', () => {
  it('answers /mcp without a token with 401 and a resource_metadata pointer', async () => {
    const res = await fetch(`${h.baseUrl}/mcp`, { method: 'POST', body: '{}' });
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain(
      `resource_metadata="${h.baseUrl}/.well-known/oauth-protected-resource/mcp"`,
    );
  });

  it('publishes protected resource and authorization server metadata', async () => {
    const prm = await (await fetch(`${h.baseUrl}/.well-known/oauth-protected-resource/mcp`)).json();
    expect(prm).toMatchObject({
      resource: `${h.baseUrl}/mcp`,
      authorization_servers: [`${h.baseUrl}/`],
      scopes_supported: ['tasks:read', 'tasks:write'],
    });
    const as = await (await fetch(`${h.baseUrl}/.well-known/oauth-authorization-server`)).json();
    expect(as).toMatchObject({
      issuer: `${h.baseUrl}/`,
      registration_endpoint: `${h.baseUrl}/register`,
      code_challenge_methods_supported: ['S256'],
    });
  });
});

describe('authorization code flow', () => {
  it('issues tokens after the owner approves', async () => {
    const { tokens } = await authorize(h.baseUrl);
    expect(tokens.access_token).toMatch(/^[\w-]{40,}$/);
    expect(tokens.refresh_token).toBeTruthy();
    expect(tokens.scope).toBe('tasks:read tasks:write');
    expect(tokens.expires_in).toBe(3600);
  });

  it('escapes the client name on the consent page', async () => {
    const { client_id } = await registerClient(h.baseUrl, '<script>alert(1)</script>');
    const page = await startAuthorization(h.baseUrl, client_id, pkcePair().challenge);
    const html = await page.text();
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
    expect(page.headers.get('x-frame-options')).toBe('DENY');
  });

  it('re-prompts on a wrong password and locks after five attempts', async () => {
    const { client_id } = await registerClient(h.baseUrl);
    const page = await startAuthorization(h.baseUrl, client_id, pkcePair().challenge);
    const requestId = requestIdFrom(await page.text());
    for (let i = 0; i < 4; i++) {
      const retry = await submitConsent(h.baseUrl, requestId, { password: 'nope' });
      expect(retry.status).toBe(401);
    }
    const locked = await submitConsent(h.baseUrl, requestId, { password: 'nope' });
    expect(new URL(locked.headers.get('location') ?? '').searchParams.get('error')).toBe(
      'access_denied',
    );
    const afterLock = await submitConsent(h.baseUrl, requestId, { password: PASSWORD });
    expect(afterLock.status).toBe(400);
  });

  it('redirects with access_denied when the owner denies', async () => {
    const { client_id } = await registerClient(h.baseUrl);
    const page = await startAuthorization(h.baseUrl, client_id, pkcePair().challenge);
    const res = await submitConsent(h.baseUrl, requestIdFrom(await page.text()), {
      decision: 'deny',
    });
    const location = new URL(res.headers.get('location') ?? '');
    expect(location.searchParams.get('error')).toBe('access_denied');
    expect(location.searchParams.get('state')).toBe('xyz');
  });

  it('rejects a wrong PKCE verifier and single-uses codes', async () => {
    const { client_id } = await registerClient(h.baseUrl);
    const { verifier, challenge } = pkcePair();
    const page = await startAuthorization(h.baseUrl, client_id, challenge);
    const consent = await submitConsent(h.baseUrl, requestIdFrom(await page.text()));
    const code = new URL(consent.headers.get('location') ?? '').searchParams.get('code') ?? '';

    const bad = await exchangeCode(h.baseUrl, client_id, code, pkcePair().verifier);
    expect(bad.status).toBe(400);
    expect((await bad.json()).error).toBe('invalid_grant');

    const good = await exchangeCode(h.baseUrl, client_id, code, verifier);
    expect(good.status).toBe(200);
    const replay = await exchangeCode(h.baseUrl, client_id, code, verifier);
    expect(replay.status).toBe(400);
  });

  it('rejects tokens for another resource (RFC 8707)', async () => {
    const { client_id } = await registerClient(h.baseUrl);
    const res = await startAuthorization(h.baseUrl, client_id, pkcePair().challenge, {
      resource: 'https://evil.example/mcp',
    });
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get('location') ?? '').searchParams.get('error')).toBe(
      'invalid_target',
    );
  });

  it('rejects unknown scopes', async () => {
    const { client_id } = await registerClient(h.baseUrl);
    const res = await startAuthorization(h.baseUrl, client_id, pkcePair().challenge, {
      scope: 'admin:everything',
    });
    expect(new URL(res.headers.get('location') ?? '').searchParams.get('error')).toBe(
      'invalid_scope',
    );
  });

  it('expires authorization codes after five minutes', async () => {
    const { client_id } = await registerClient(h.baseUrl);
    const { verifier, challenge } = pkcePair();
    const page = await startAuthorization(h.baseUrl, client_id, challenge);
    const consent = await submitConsent(h.baseUrl, requestIdFrom(await page.text()));
    const code = new URL(consent.headers.get('location') ?? '').searchParams.get('code') ?? '';
    h.clock.now += 301;
    expect((await exchangeCode(h.baseUrl, client_id, code, verifier)).status).toBe(400);
  });
});

describe('refresh and revocation', () => {
  const refresh = (clientId: string, refreshToken: string) =>
    fetch(`${h.baseUrl}/token`, {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: clientId,
        refresh_token: refreshToken,
      }),
    });
  const mcpStatus = async (token: string) =>
    (
      await fetch(`${h.baseUrl}/mcp`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }),
      })
    ).status;

  it('rotates refresh tokens and kills the previous pair', async () => {
    const { clientId, tokens } = await authorize(h.baseUrl);
    const res = await refresh(clientId, tokens.refresh_token);
    expect(res.status).toBe(200);
    const next = await res.json();
    expect(next.access_token).not.toBe(tokens.access_token);

    expect(await mcpStatus(tokens.access_token)).toBe(401);
    expect(await mcpStatus(next.access_token)).toBe(200);
    expect((await refresh(clientId, tokens.refresh_token)).status).toBe(400);
  });

  it('expires access tokens', async () => {
    const { tokens } = await authorize(h.baseUrl);
    expect(await mcpStatus(tokens.access_token)).toBe(200);
    h.clock.now += 3601;
    expect(await mcpStatus(tokens.access_token)).toBe(401);
  });

  it('revokes both tokens of a pair', async () => {
    const { clientId, tokens } = await authorize(h.baseUrl);
    const res = await fetch(`${h.baseUrl}/revoke`, {
      method: 'POST',
      body: new URLSearchParams({ client_id: clientId, token: tokens.refresh_token }),
    });
    expect(res.status).toBe(200);
    expect(await mcpStatus(tokens.access_token)).toBe(401);
  });
});
