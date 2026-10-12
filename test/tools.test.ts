import type { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Task } from '../src/store/tasks.js';
import { authorize, connectMcp, type Harness, parseText, startServer } from './helpers.js';

let h: Harness;
let client: Client;

beforeEach(async () => {
  h = await startServer();
});
afterEach(async () => {
  await client?.close();
  await h.close();
});

describe('tools over Streamable HTTP', () => {
  it('lists the tools with annotations', async () => {
    client = await connectMcp(h.baseUrl, (await authorize(h.baseUrl)).tokens.access_token);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      'create_task',
      'delete_task',
      'get_task',
      'list_tasks',
      'update_task',
    ]);
    expect(tools.find((t) => t.name === 'delete_task')?.annotations?.destructiveHint).toBe(true);
    expect(tools.find((t) => t.name === 'list_tasks')?.annotations?.readOnlyHint).toBe(true);
  });

  it('runs a full create → list → update → delete cycle', async () => {
    client = await connectMcp(h.baseUrl, (await authorize(h.baseUrl)).tokens.access_token);
    const created = parseText<Task>(
      await client.callTool({
        name: 'create_task',
        arguments: { title: 'Ship v1', priority: 'high', dueDate: '2026-11-01' },
      }),
    );
    expect(created).toMatchObject({ title: 'Ship v1', status: 'open', priority: 'high' });

    const listed = parseText<{ count: number; tasks: Task[] }>(
      await client.callTool({ name: 'list_tasks', arguments: { status: 'open' } }),
    );
    expect(listed.count).toBe(1);

    const done = parseText<Task>(
      await client.callTool({ name: 'update_task', arguments: { id: created.id, status: 'done' } }),
    );
    expect(done.status).toBe('done');

    await client.callTool({ name: 'delete_task', arguments: { id: created.id } });
    const missing = await client.callTool({ name: 'get_task', arguments: { id: created.id } });
    expect(missing.isError).toBe(true);
  });

  it('validates arguments', async () => {
    client = await connectMcp(h.baseUrl, (await authorize(h.baseUrl)).tokens.access_token);
    const res = await client.callTool({
      name: 'create_task',
      arguments: { title: 'x', dueDate: 'next tuesday' },
    });
    expect(res.isError).toBe(true);
  });

  it('enforces scopes: a read-only grant cannot write', async () => {
    const { tokens } = await authorize(h.baseUrl, { grantWrite: false });
    expect(tokens.scope).toBe('tasks:read');
    client = await connectMcp(h.baseUrl, tokens.access_token);
    const res = await client.callTool({ name: 'create_task', arguments: { title: 'nope' } });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toContain('tasks:write');
    const list = await client.callTool({ name: 'list_tasks', arguments: {} });
    expect(list.isError).toBeFalsy();
  });
});
