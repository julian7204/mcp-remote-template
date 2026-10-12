import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';

const SCOPE_LABELS: Record<string, string> = {
  'tasks:read': 'Read your tasks',
  'tasks:write': 'Create, edit and delete your tasks',
};

export function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function renderConsentPage(input: {
  requestId: string;
  client: OAuthClientInformationFull;
  scopes: string[];
  error?: string;
}): string {
  // client_name and redirect_uris come from an unauthenticated registration call: always escape.
  const name = escapeHtml(input.client.client_name ?? 'An unnamed client');
  const redirect = escapeHtml(input.client.redirect_uris[0] ?? '');
  const items = input.scopes
    .map((s) => `<li>${escapeHtml(SCOPE_LABELS[s] ?? s)} <code>${escapeHtml(s)}</code></li>`)
    .join('');
  const writeToggle = input.scopes.includes('tasks:write')
    ? `<label class="check"><input type="checkbox" name="grant_write" value="1" checked> Allow write access</label>`
    : '';
  const error = input.error ? `<p class="error" role="alert">${escapeHtml(input.error)}</p>` : '';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize ${name}</title>
<style>
  :root { color-scheme: light dark; --fg:#1b1b1f; --muted:#5d5d66; --bg:#f6f6f3; --card:#fff; --line:#deded8; --accent:#1f5f4a; }
  @media (prefers-color-scheme: dark) { :root { --fg:#ececea; --muted:#a3a3a8; --bg:#141416; --card:#1d1d20; --line:#323236; --accent:#6cc4a1; } }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:grid; place-items:center; padding:16px; background:var(--bg); color:var(--fg); font:16px/1.5 system-ui, sans-serif; }
  main { width:100%; max-width:420px; background:var(--card); border:1px solid var(--line); border-radius:12px; padding:28px; }
  h1 { font-size:1.25rem; margin:0 0 4px; }
  p.sub { color:var(--muted); margin:0 0 20px; font-size:.9rem; word-break:break-all; }
  ul { padding-left:20px; margin:0 0 20px; } code { font-size:.8rem; color:var(--muted); }
  label { display:block; font-weight:600; margin-bottom:6px; } label.check { font-weight:400; margin:0 0 20px; }
  input[type=password] { width:100%; padding:10px 12px; border:1px solid var(--line); border-radius:8px; background:transparent; color:inherit; font:inherit; margin-bottom:16px; }
  .row { display:flex; gap:8px; } button { flex:1; padding:10px; border-radius:8px; font:inherit; font-weight:600; cursor:pointer; border:1px solid var(--line); background:transparent; color:inherit; }
  button.primary { background:var(--accent); border-color:var(--accent); color:var(--card); }
  .error { color:#b42318; font-weight:600; }
</style>
</head>
<body>
<main>
  <h1>${name} wants access</h1>
  <p class="sub">It will be sent back to ${redirect}</p>
  <p>This client is asking to:</p>
  <ul>${items}</ul>
  <form method="post" action="/oauth/consent">
    <input type="hidden" name="request_id" value="${escapeHtml(input.requestId)}">
    ${writeToggle}
    <label for="password">Owner password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" autofocus>
    ${error}
    <div class="row">
      <button type="submit" name="decision" value="deny">Deny</button>
      <button type="submit" name="decision" value="approve" class="primary">Approve</button>
    </div>
  </form>
</main>
</body>
</html>`;
}
