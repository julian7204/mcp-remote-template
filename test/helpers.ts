import { createHash, randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';

export const PASSWORD = 'correct-horse-battery-staple';
export const REDIRECT_URI = 'http://127.0.0.1:9/callback';

export interface Harness {
  baseUrl: string;
  clock: { now: number };
  close: () => Promise<void>;
}

export async function startServer(): Promise<Harness> {
  // Starts at real time: the SDK bearer middleware also checks expiry against Date.now().
  const clock = { now: Math.floor(Date.now() / 1000) };
  // PUBLIC_URL must match the address the tests call, so we bind first and build the app after.
  const { createServer } = await import('node:http');
  const http = createServer();
  await new Promise<void>((resolve) => http.listen(0, '127.0.0.1', resolve));
  const { port } = http.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;
  const config = loadConfig({ PUBLIC_URL: baseUrl, OWNER_PASSWORD: PASSWORD });
  const { app } = createApp(config, { now: () => clock.now });
  http.on('request', app);
  return {
    baseUrl,
    clock,
    close: () => new Promise((resolve) => http.close(() => resolve())),
  };
}

export function pkcePair() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export async function registerClient(baseUrl: string, name = 'Test client') {
  const res = await fetch(`${baseUrl}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: name,
      redirect_uris: [REDIRECT_URI],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    }),
  });
  if (res.status !== 201) throw new Error(`register failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as { client_id: string };
}

export async function startAuthorization(
  baseUrl: string,
  clientId: string,
  challenge: string,
  extra: Record<string, string> = {},
) {
  const url = new URL('/authorize', baseUrl);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'xyz',
    resource: `${baseUrl}/mcp`,
    ...extra,
  }).toString();
  return fetch(url, { redirect: 'manual' });
}

export function requestIdFrom(html: string): string {
  const match = html.match(/name="request_id" value="([^"]+)"/);
  if (!match?.[1]) throw new Error('consent page without request_id');
  return match[1];
}

export async function submitConsent(
  baseUrl: string,
  requestId: string,
  fields: { password?: string; decision?: 'approve' | 'deny'; grantWrite?: boolean } = {},
) {
  const body = new URLSearchParams({
    request_id: requestId,
    password: fields.password ?? PASSWORD,
    decision: fields.decision ?? 'approve',
  });
  if (fields.grantWrite ?? true) body.set('grant_write', '1');
  return fetch(`${baseUrl}/oauth/consent`, { method: 'POST', body, redirect: 'manual' });
}

export async function exchangeCode(
  baseUrl: string,
  clientId: string,
  code: string,
  verifier: string,
) {
  return fetch(`${baseUrl}/token`, {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      code,
      code_verifier: verifier,
      redirect_uri: REDIRECT_URI,
      resource: `${baseUrl}/mcp`,
    }),
  });
}

export interface Tokens {
  access_token: string;
  refresh_token: string;
  scope: string;
  expires_in: number;
}

/** Runs the whole browser dance a connector like Claude performs, and returns tokens. */
export async function authorize(baseUrl: string, opts: { grantWrite?: boolean } = {}) {
  const { client_id } = await registerClient(baseUrl);
  const { verifier, challenge } = pkcePair();
  const page = await startAuthorization(baseUrl, client_id, challenge);
  const consent = await submitConsent(baseUrl, requestIdFrom(await page.text()), opts);
  const location = new URL(consent.headers.get('location') ?? '');
  const code = location.searchParams.get('code');
  if (!code) throw new Error(`no code in ${location.href}`);
  const res = await exchangeCode(baseUrl, client_id, code, verifier);
  return { clientId: client_id, tokens: (await res.json()) as Tokens };
}

export async function connectMcp(baseUrl: string, accessToken: string) {
  const client = new Client({ name: 'test', version: '0.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL('/mcp', baseUrl), {
    requestInit: { headers: { Authorization: `Bearer ${accessToken}` } },
  });
  await client.connect(transport);
  return client;
}

export function parseText<T>(result: unknown): T {
  const content = (result as { content: { type: string; text: string }[] }).content;
  return JSON.parse(content[0]?.text ?? 'null') as T;
}
