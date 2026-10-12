# mcp-remote-template

[![CI](https://github.com/julian7204/mcp-remote-template/actions/workflows/ci.yml/badge.svg)](https://github.com/julian7204/mcp-remote-template/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A production-shaped **remote [Model Context Protocol](https://modelcontextprotocol.io) server** in TypeScript that
Claude (and any MCP client) can add as a custom connector — with **its own OAuth 2.1 authorization server built in**.

Most MCP examples run over stdio on your laptop. Going remote is where the real work is: discovery metadata, dynamic
client registration, PKCE, consent, token audience, refresh rotation, scopes per tool. This template does all of it in
under 900 lines you can read in one sitting, with 21 tests covering the full browser flow.

```
Claude ──► POST /mcp ──401──► discovers /.well-known/* ──► registers ──► /authorize (consent page)
       ◄── tokens ◄── /token (PKCE) ◄── code ◄── owner approves ──┘
Claude ──► POST /mcp  Authorization: Bearer … ──► list_tasks / create_task / …
```

## Features

- **Streamable HTTP transport, stateless** — a fresh server per request, no sticky sessions; scale it horizontally.
- **OAuth 2.1 authorization server** — RFC 8414 metadata, RFC 9728 protected-resource metadata, RFC 7591 dynamic
  client registration, PKCE (S256 only), RFC 8707 resource indicators, revocation.
- **Consent screen** protected by an owner password, with an opt-out for write access, brute-force lockout,
  HTML escaping of client-supplied names and anti-clickjacking headers.
- **Hardened tokens** — opaque 256-bit tokens stored only as SHA-256 hashes, single-use 5-minute codes, refresh-token
  rotation that kills the previous pair, audience bound to `/mcp`.
- **Scopes enforced per tool** — `tasks:read` / `tasks:write`; a read-only grant gets a readable error, not a crash.
- **Example domain** — a small task manager with five tools carrying MCP annotations (`readOnlyHint`,
  `destructiveHint`, `idempotentHint`), Zod-validated input and a swappable `TaskStore` interface.
- **Ship it** — multi-stage Dockerfile (non-root, healthcheck), `docker-compose.yml`, one-click Render blueprint,
  GitHub Actions running lint, typecheck, tests on Node 22/24 and a Docker smoke test.

## Quick start

```bash
pnpm install
cp .env.example .env            # set OWNER_PASSWORD to something long
pnpm dev                        # http://localhost:3000
pnpm verify                     # biome + tsc + vitest
```

Try it with the MCP Inspector: `npx @modelcontextprotocol/inspector`, transport **Streamable HTTP**, URL
`http://localhost:3000/mcp`, then run its OAuth flow. Your browser lands on the consent page.

## Connect it to Claude

1. Deploy it somewhere with HTTPS (see below) and set `PUBLIC_URL` to that origin.
2. In Claude: **Settings → Connectors → Add custom connector**, paste `https://<your-host>/mcp`.
3. Claude opens the consent page. Enter your `OWNER_PASSWORD`, choose whether to allow writes, approve.
4. Ask: *"What are my high-priority tasks this week?"* or *"Add a task to renew the domain by Friday."*

## Deploy

| Option | How |
|---|---|
| Render | [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/julian7204/mcp-remote-template) — then set `PUBLIC_URL` to the service URL. |
| Docker | `docker compose up --build` with `OWNER_PASSWORD` and `PUBLIC_URL` in `.env`. |
| Anything with Node 22 | `pnpm build && pnpm start`. |

Behind a proxy set `TRUST_PROXY=1` so rate limiting sees client IPs.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PUBLIC_URL` | — | Public origin. Becomes the OAuth issuer; `${PUBLIC_URL}/mcp` is the token audience. |
| `OWNER_PASSWORD` | — | Required on the consent page. Minimum 12 characters. |
| `PORT` | `3000` | HTTP port. |
| `ACCESS_TOKEN_TTL` | `3600` | Seconds. |
| `REFRESH_TOKEN_TTL` | `2592000` | Seconds (30 days). |
| `TRUST_PROXY` | `0` | `1` behind Render, Fly, Railway, nginx… |

## Make it yours

- **Your own tools**: copy a block in [`src/tools.ts`](src/tools.ts). Call `guard(extra.authInfo, scope)` first.
- **Real storage**: implement the `TaskStore` interface in [`src/store/tasks.ts`](src/store/tasks.ts) with Postgres,
  SQLite or a third-party API. Every method receives the `ownerId` from the token.
- **Real users**: keep the resource-server half (`requireBearerAuth`, metadata) and replace `OwnerOAuthProvider`
  with the SDK's `ProxyOAuthServerProvider` pointing at Auth0, Clerk, Keycloak or your IdP.
- **Persistent sessions**: clients, codes and tokens live in memory, so a restart asks users to reconnect. Move the
  three maps in [`src/auth/provider.ts`](src/auth/provider.ts) to Redis or a table when that matters.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design decisions and the security model.

## Project layout

```
src/
  index.ts            process entry, graceful shutdown
  app.ts              Express wiring: OAuth router, consent POST, /mcp
  config.ts           env validation with Zod
  tools.ts            MCP tools + per-tool scope guard
  auth/provider.ts    OAuth 2.1 authorization server (owner-only)
  auth/consent-page.ts
  store/tasks.ts      TaskStore interface + in-memory implementation
test/                 store, OAuth flow and tool tests (vitest, real HTTP)
```

## License

MIT © Julian Coronel
