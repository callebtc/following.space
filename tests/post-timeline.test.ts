import { afterEach, describe, expect, it, vi } from 'vitest';
import { BehaviorSubject, EMPTY, Observable } from 'rxjs';
import { finalizeEvent, getPublicKey, type OutboxMap } from 'applesauce-core/helpers';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { createPostTimeline } from '../src/lib/features/timeline/posts';
import { alice, bob, NOW } from './fixtures';

const history = vi.hoisted(() => ({ maps: [] as unknown[], statuses: [] as BehaviorSubject<any[]>[] }));
vi.mock('applesauce-loaders/loaders', async (original) => ({
  ...await original<typeof import('applesauce-loaders/loaders')>(),
  createOutboxTimelineLoader: (_pool: unknown, maps$: Observable<OutboxMap>) => {
    const loader = () => maps$;
    history.maps.push(maps$);
    const status$ = new BehaviorSubject<any[]>([]);
    history.statuses.push(status$);
    return Object.assign(loader, { status$: status$ });
  }
}));

const dispose: (() => void)[] = [];
afterEach(() => { dispose.splice(0).forEach((fn) => fn()); history.maps.length = 0; history.statuses.length = 0; });
function setup(keys = [alice, bob]) {
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} }, relays: ['wss://fallback.example.com'] });
  runtime.eventStore.eventLoader = () => EMPTY;
  const unhealthy$ = new BehaviorSubject<string[]>([]);
  runtime.liveness.unhealthy$ = unhealthy$;
  const maps: OutboxMap[] = [];
  const stopped = vi.fn();
  vi.spyOn(runtime.pool, 'outboxSubscription').mockImplementation((source) => new Observable<never>(() => {
    const sub = (source as Observable<OutboxMap>).subscribe((map) => maps.push(map));
    return () => { sub.unsubscribe(); stopped(); };
  }));
  const timeline = createPostTimeline(runtime, keys.map(getPublicKey));
  const states: import('../src/lib/features/timeline/posts').PostState[] = [];
  const sub = timeline.state$.subscribe((state) => states.push(state));
  dispose.push(() => { sub.unsubscribe(); runtime.dispose(); });
  const mailbox = (key: Uint8Array, tags: string[][], timestamp = NOW) => runtime.eventStore.add(finalizeEvent({ kind: 10002, content: '', tags, created_at: timestamp }, key));
  return { runtime, maps, mailbox, unhealthy$, sub, stopped, states };
}

describe('follow pack post outbox selection', () => {
  it('shares the reactive relay map between history and live loading and honors NIP-65 markers', async () => {
    const ctx = setup();
    ctx.mailbox(alice, [['r', 'wss://write.example.com', 'write'], ['r', 'wss://both.example.com'], ['r', 'wss://read.example.com', 'read']]);
    await new Promise((resolve) => setTimeout(resolve, 0));
    const map = ctx.maps.at(-1)!;
    expect(Object.keys(map).sort()).toEqual(['wss://both.example.com/', 'wss://fallback.example.com/', 'wss://write.example.com/']);
    expect(map['wss://write.example.com/'].map((p) => p.pubkey)).toEqual([getPublicKey(alice)]);
    expect(map['wss://fallback.example.com/'].map((p) => p.pubkey)).toEqual([getPublicKey(bob)]);
    expect(ctx.runtime.pool.outboxSubscription).toHaveBeenCalledWith(history.maps[0], expect.objectContaining({ kinds: [1] }));
    ctx.mailbox(alice, [['r', 'wss://new.example.com', 'write']], NOW + 1);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(Object.keys(ctx.maps.at(-1)!)).toEqual(['wss://new.example.com/', 'wss://fallback.example.com/']);
  });
  it('reselects on failure and recovery and uses healthy fallback relays when all outboxes fail', async () => {
    const ctx = setup([alice]);
    ctx.mailbox(alice, [['r', 'wss://one.example.com'], ['r', 'wss://two.example.com']]);
    await new Promise((resolve) => setTimeout(resolve, 0));
    ctx.unhealthy$.next(['wss://one.example.com/']);
    expect(Object.keys(ctx.maps.at(-1)!)).toEqual(['wss://two.example.com/']);
    ctx.unhealthy$.next(['wss://one.example.com/', 'wss://two.example.com/']);
    expect(Object.keys(ctx.maps.at(-1)!)).toEqual(['wss://fallback.example.com/']);
    ctx.unhealthy$.next(['wss://one.example.com/', 'wss://two.example.com/', 'wss://fallback.example.com/']);
    expect(ctx.maps.at(-1)).toEqual({});
    ctx.unhealthy$.next([]);
    expect(Object.keys(ctx.maps.at(-1)!)).toEqual(['wss://one.example.com/', 'wss://two.example.com/']);
    ctx.sub.unsubscribe();
    expect(ctx.stopped).toHaveBeenCalledOnce();
  });
  it('does not start relay work for an empty pack', () => {
    const ctx = setup([]);
    expect(ctx.runtime.pool.outboxSubscription).not.toHaveBeenCalled();
    expect(history.maps).toHaveLength(0);
  });
});

it('only reports total post failure while empty and clears it when data arrives', () => {
  const ctx = setup([alice]);
  const status = history.statuses.at(-1)!;
  const failed = { source: 'wss://failed', state: 'incomplete', reason: 'request' };
  status.next([failed, { source: 'wss://healthy', state: 'covered' }]);
  expect(ctx.states.at(-1)?.warning).toBeUndefined();
  status.next([failed, { source: 'cache', state: 'covered' }]);
  expect(ctx.states.at(-1)?.warning).toContain('Unable to load posts');
  ctx.runtime.eventStore.add(finalizeEvent({ kind: 1, content: 'hello', tags: [], created_at: Math.floor(Date.now() / 1000) }, alice));
  expect(ctx.states.at(-1)?.events).toHaveLength(1);
  expect(ctx.states.at(-1)?.warning).toBeUndefined();
  status.next([failed]);
  expect(ctx.states.at(-1)?.warning).toBeUndefined();
});
