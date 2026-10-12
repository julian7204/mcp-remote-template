import { randomUUID } from 'node:crypto';
import { z } from 'zod';

export const TaskStatus = z.enum(['open', 'done']);
export const TaskPriority = z.enum(['low', 'medium', 'high']);

export const TaskSchema = z.object({
  id: z.string(),
  title: z.string(),
  notes: z.string(),
  status: TaskStatus,
  priority: TaskPriority,
  dueDate: z.string().nullable(),
  createdAt: z.string(),
  updatedAt: z.string(),
});

export type Task = z.infer<typeof TaskSchema>;

export type NewTask = Pick<Task, 'title'> & Partial<Pick<Task, 'notes' | 'priority' | 'dueDate'>>;
export type TaskPatch = Partial<Pick<Task, 'title' | 'notes' | 'priority' | 'dueDate' | 'status'>>;

export interface TaskFilter {
  status?: Task['status'];
  priority?: Task['priority'];
  query?: string;
  limit?: number;
}

/**
 * Storage boundary for the example domain. Swap the in-memory implementation for
 * Postgres, SQLite or a third-party API without touching the MCP tool layer.
 * Every method is scoped by `ownerId` so one deployment can serve several users.
 */
export interface TaskStore {
  list(ownerId: string, filter?: TaskFilter): Promise<Task[]>;
  get(ownerId: string, id: string): Promise<Task | undefined>;
  create(ownerId: string, input: NewTask): Promise<Task>;
  update(ownerId: string, id: string, patch: TaskPatch): Promise<Task | undefined>;
  delete(ownerId: string, id: string): Promise<boolean>;
}

export class InMemoryTaskStore implements TaskStore {
  readonly #byOwner = new Map<string, Map<string, Task>>();
  readonly #now: () => Date;

  constructor(now: () => Date = () => new Date()) {
    this.#now = now;
  }

  #bucket(ownerId: string): Map<string, Task> {
    let bucket = this.#byOwner.get(ownerId);
    if (!bucket) {
      bucket = new Map();
      this.#byOwner.set(ownerId, bucket);
    }
    return bucket;
  }

  async list(ownerId: string, filter: TaskFilter = {}): Promise<Task[]> {
    const query = filter.query?.trim().toLowerCase();
    const rank = { high: 0, medium: 1, low: 2 } as const;
    return [...this.#bucket(ownerId).values()]
      .filter((t) => !filter.status || t.status === filter.status)
      .filter((t) => !filter.priority || t.priority === filter.priority)
      .filter(
        (t) =>
          !query || t.title.toLowerCase().includes(query) || t.notes.toLowerCase().includes(query),
      )
      .sort(
        (a, b) =>
          rank[a.priority] - rank[b.priority] ||
          (a.dueDate ?? '9999').localeCompare(b.dueDate ?? '9999') ||
          a.createdAt.localeCompare(b.createdAt),
      )
      .slice(0, filter.limit ?? 50);
  }

  async get(ownerId: string, id: string): Promise<Task | undefined> {
    return this.#bucket(ownerId).get(id);
  }

  async create(ownerId: string, input: NewTask): Promise<Task> {
    const now = this.#now().toISOString();
    const task: Task = {
      id: randomUUID(),
      title: input.title,
      notes: input.notes ?? '',
      status: 'open',
      priority: input.priority ?? 'medium',
      dueDate: input.dueDate ?? null,
      createdAt: now,
      updatedAt: now,
    };
    this.#bucket(ownerId).set(task.id, task);
    return task;
  }

  async update(ownerId: string, id: string, patch: TaskPatch): Promise<Task | undefined> {
    const bucket = this.#bucket(ownerId);
    const current = bucket.get(id);
    if (!current) return undefined;
    const defined = Object.fromEntries(Object.entries(patch).filter(([, v]) => v !== undefined));
    const next: Task = { ...current, ...defined, updatedAt: this.#now().toISOString() };
    bucket.set(id, next);
    return next;
  }

  async delete(ownerId: string, id: string): Promise<boolean> {
    return this.#bucket(ownerId).delete(id);
  }
}
