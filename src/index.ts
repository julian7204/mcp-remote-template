import { createApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const { app } = createApp(config);

const server = app.listen(config.PORT, () => {
  console.log(`MCP server listening on :${config.PORT}`);
  console.log(`Connect clients to ${config.PUBLIC_URL}/mcp`);
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
