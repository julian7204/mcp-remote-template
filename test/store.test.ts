import { describe, expect, it } from 'vitest';
import { InMemoryTaskStore } from '../src/store/tasks.js';

describe('InMemoryTaskStore', () => {
  it('creates tasks with defaults', async () => {
    const store = new InMemoryTaskStore(() => new Date('2026-01-01T00:00:00Z'));
    const task = await store.create('a', { title: 'Write README' });
    expect(task).toMatchObject({
      title: 'Write README',
      notes: '',
      status: 'open',
      priority: 'medium',
      dueDate: null,
      createdAt: '2026-01-01T00:00:00.000Z',
    });
  });

  it('isolates owners', async () => {
    const store = new InMemoryTaskStore();
    const task = await store.create('alice', { title: 'secret' });
    expect(await store.list('bob')).toEqual([]);
    expect(await store.get('bob', task.id)).toBeUndefined();
    expect(await store.delete('bob', task.id)).toBe(false);
    expect(await store.update('bob', task.id, { title: 'pwned' })).toBeUndefined();
    expect((await store.get('alice', task.id))?.title).toBe('secret');
  });

  it('sorts by priority, then due date, and filters', async () => {
    const store = new InMemoryTaskStore();
    await store.create('a', { title: 'low', priority: 'low' });
    await store.create('a', { title: 'high later', priority: 'high', dueDate: '2026-12-01' });
    await store.create('a', {
      title: 'high soon',
      priority: 'high',
      dueDate: '2026-01-01',
      notes: 'invoice',
    });
    const titles = (await store.list('a')).map((t) => t.title);
    expect(titles).toEqual(['high soon', 'high later', 'low']);
    expect((await store.list('a', { query: 'INVOICE' })).map((t) => t.title)).toEqual([
      'high soon',
    ]);
    expect((await store.list('a', { priority: 'low' })).length).toBe(1);
    expect((await store.list('a', { limit: 1 })).length).toBe(1);
  });

  it('ignores undefined fields on update', async () => {
    const store = new InMemoryTaskStore();
    const task = await store.create('a', { title: 't', notes: 'keep me' });
    const updated = await store.update('a', task.id, { status: 'done', notes: undefined });
    expect(updated).toMatchObject({ status: 'done', notes: 'keep me' });
  });
});
