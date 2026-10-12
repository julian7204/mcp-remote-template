import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import {
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthRouter,
} from '@modelcontextprotocol/sdk/server/auth/router.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express, { type Express } from 'express';
import { z } from 'zod';
import { ALL_SCOPES, OwnerOAuthProvider, sendConsentPage } from './auth/provider.js';
import type { Config } from './config.js';
import { InMemoryTaskStore, type TaskStore } from './store/tasks.js';
import { registerTaskTools } from './tools.js';

export const SERVER_NAME = 'mcp-remote-template';
export const SERVER_VERSION = '1.0.0';

const ConsentForm = z.object({
  request_id: z.string().min(1),
  password: z.string().default(''),
  decision: z.enum(['approve', 'deny']),
  grant_write: z.literal('1').optional(),
});

export interface AppDeps {
  store?: TaskStore;
  now?: () => number;
}

export function createApp(
  config: Config,
  deps: AppDeps = {},
): { app: Express; provider: OwnerOAuthProvider } {
  const issuerUrl = new URL(config.PUBLIC_URL);
  const mcpUrl = new URL('/mcp', issuerUrl);
  const store = deps.store ?? new InMemoryTaskStore();
  const provider = new OwnerOAuthProvider({
    ownerPassword: config.OWNER_PASSWORD,
    resourceUrl: mcpUrl,
    accessTokenTtl: config.ACCESS_TOKEN_TTL,
    refreshTokenTtl: config.REFRESH_TOKEN_TTL,
    now: deps.now,
  });

  const app = express();
  app.disable('x-powered-by');
  if (config.TRUST_PROXY) app.set('trust proxy', 1);

  app.get('/healthz', (_req, res) => {
    res.json({ ok: true, name: SERVER_NAME, version: SERVER_VERSION });
  });

  // /.well-known/oauth-authorization-server, /.well-known/oauth-protected-resource/mcp,
  // /authorize, /token, /register and /revoke — all rate limited by the SDK.
  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl,
      resourceServerUrl: mcpUrl,
      scopesSupported: ALL_SCOPES,
      resourceName: 'Task manager (MCP template)',
    }),
  );

  app.post('/oauth/consent', express.urlencoded({ extended: false, limit: '8kb' }), (req, res) => {
    const form = ConsentForm.safeParse(req.body);
    if (!form.success) {
      res.status(400).type('text/plain').send('Malformed consent form.');
      return;
    }
    const result = provider.decideConsent({
      requestId: form.data.request_id,
      password: form.data.password,
      approve: form.data.decision === 'approve',
      grantWrite: form.data.grant_write === '1',
    });
    if (result.kind === 'redirect') res.redirect(302, result.location);
    else if (result.kind === 'retry') sendConsentPage(res, result.html, 401);
    else
      res
        .status(400)
        .type('text/plain')
        .send('This authorization request expired. Start again from your client.');
  });

  const bearer = requireBearerAuth({
    verifier: provider,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpUrl),
  });

  // Stateless Streamable HTTP: a fresh server + transport per request. No session affinity,
  // so the service scales horizontally and survives restarts without breaking clients.
  app.post('/mcp', bearer, express.json({ limit: '1mb' }), async (req, res) => {
    const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });
    registerTaskTools(server, store);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      console.error('MCP request failed', error);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: { code: -32603, message: 'Internal server error' },
          id: null,
        });
      }
    }
  });

  // Stateless mode has no server-initiated stream or session to delete.
  const methodNotAllowed: express.RequestHandler = (_req, res) => {
    res
      .status(405)
      .set('Allow', 'POST')
      .json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Method not allowed.' },
        id: null,
      });
  };
  app.get('/mcp', bearer, methodNotAllowed);
  app.delete('/mcp', bearer, methodNotAllowed);

  return { app, provider };
}
