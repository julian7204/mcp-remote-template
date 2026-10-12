import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { OWNER_ID, SCOPES } from './auth/provider.js';
import { TaskPriority, TaskStatus, type TaskStore } from './store/tasks.js';

const isoDate = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, 'Use YYYY-MM-DD')
  .describe('Due date as YYYY-MM-DD');

const json = (value: unknown): CallToolResult => ({
  content: [{ type: 'text', text: JSON.stringify(value, null, 2) }],
});

const failure = (message: string): CallToolResult => ({
  isError: true,
  content: [{ type: 'text', text: message }],
});

/**
 * Scope check at the tool boundary. The bearer middleware already proved the token is valid;
 * this decides what that token may do. Returning an error result (instead of throwing)
 * lets the model read the reason and explain it to the user.
 */
function guard(auth: AuthInfo | undefined, scope: string): { ownerId: string } | CallToolResult {
  if (!auth) return failure('Not authenticated.');
  if (!auth.scopes.includes(scope)) {
    return failure(`This connection was not granted "${scope}". Reconnect and allow it.`);
  }
  const ownerId = typeof auth.extra?.ownerId === 'string' ? auth.extra.ownerId : OWNER_ID;
  return { ownerId };
}

const denied = (value: { ownerId: string } | CallToolResult): value is CallToolResult =>
  'content' in value;

export function registerTaskTools(server: McpServer, store: TaskStore): void {
  server.registerTool(
    'list_tasks',
    {
      title: 'List tasks',
      description:
        'List tasks, highest priority and nearest due date first. Optionally filter by status, priority or a text query matched against title and notes.',
      inputSchema: {
        status: TaskStatus.optional(),
        priority: TaskPriority.optional(),
        query: z.string().max(200).optional().describe('Case-insensitive text search'),
        limit: z.number().int().min(1).max(100).default(20),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async (args, extra) => {
      const access = guard(extra.authInfo, SCOPES.read);
      if (denied(access)) return access;
      const tasks = await store.list(access.ownerId, args);
      return json({ count: tasks.length, tasks });
    },
  );

  server.registerTool(
    'get_task',
    {
      title: 'Get a task',
      description: 'Fetch one task by id.',
      inputSchema: { id: z.string().describe('Task id returned by list_tasks or create_task') },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ id }, extra) => {
      const access = guard(extra.authInfo, SCOPES.read);
      if (denied(access)) return access;
      const task = await store.get(access.ownerId, id);
      return task ? json(task) : failure(`No task with id ${id}.`);
    },
  );

  server.registerTool(
    'create_task',
    {
      title: 'Create a task',
      description: 'Create a new open task.',
      inputSchema: {
        title: z.string().min(1).max(200),
        notes: z.string().max(2000).optional(),
        priority: TaskPriority.default('medium'),
        dueDate: isoDate.optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    async (args, extra) => {
      const access = guard(extra.authInfo, SCOPES.write);
      if (denied(access)) return access;
      return json(await store.create(access.ownerId, args));
    },
  );

  server.registerTool(
    'update_task',
    {
      title: 'Update a task',
      description:
        'Change any field of an existing task. Only the fields you pass are modified. Use status "done" to complete a task.',
      inputSchema: {
        id: z.string(),
        title: z.string().min(1).max(200).optional(),
        notes: z.string().max(2000).optional(),
        priority: TaskPriority.optional(),
        dueDate: isoDate.nullable().optional().describe('YYYY-MM-DD, or null to clear it'),
        status: TaskStatus.optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true },
    },
    async ({ id, ...patch }, extra) => {
      const access = guard(extra.authInfo, SCOPES.write);
      if (denied(access)) return access;
      const task = await store.update(access.ownerId, id, patch);
      return task ? json(task) : failure(`No task with id ${id}.`);
    },
  );

  server.registerTool(
    'delete_task',
    {
      title: 'Delete a task',
      description:
        'Permanently delete a task. Prefer update_task with status "done" to complete it.',
      inputSchema: { id: z.string() },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
    },
    async ({ id }, extra) => {
      const access = guard(extra.authInfo, SCOPES.write);
      if (denied(access)) return access;
      const deleted = await store.delete(access.ownerId, id);
      return deleted ? json({ deleted: id }) : failure(`No task with id ${id}.`);
    },
  );
}
