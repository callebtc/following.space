import { afterEach, describe, expect, it, vi } from 'vitest';
import { EMPTY, Observable, Subject, of, type Subscription } from 'rxjs';
import type { SyncLoaderStatus } from 'applesauce-loaders/loaders';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { createPackFeed, type PackFeedState } from '../src/lib/features/packs/feed';
import { createPackDirectory, getPackDirectory } from '../src/lib/features/packs/directory';
import { NOW, signedPack } from './fixtures';

const disposers: (() => void)[] = [];
afterEach(() => { disposers.splice(0).forEach((dispose) => dispose()); vi.useRealTimers(); });
const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
function setup(cacheRead = vi.fn(async () => [signedPack()])) {
  const runtime = createNostrRuntime({ cache: { read: cacheRead, write: async () => {} }, relays: ['wss://relay.example.com'] });
  const liveStopped = vi.fn();
  vi.spyOn(runtime.pool, 'subscription').mockReturnValue(new Observable(() => liveStopped));
  const status = new Subject<SyncLoaderStatus>();
  const syncStarted = vi.spyOn(runtime, 'syncLoader').mockImplementation(() => ({ status$: status, events$: EMPTY }));
  const directory = getPackDirectory(runtime, NOW);
  const feed = createPackFeed(runtime, {}, { directory });
  const states: PackFeedState[] = [];
  const subscriptions: Subscription[] = [];
  const subscribe = () => {
    const subscription = feed.state$.subscribe((state) => states.push(state));
    subscriptions.push(subscription); return subscription;
  };
  disposers.push(() => { subscriptions.forEach((sub) => sub.unsubscribe()); runtime.dispose(); });
  return { runtime, directory, feed, states, subscribe, syncStarted, liveStopped, status };
}

describe('shared pack directory lifecycle', () => {
  it('renders cache before sync settles and shares work between subscribers', async () => {
    const ctx = setup(); const a = ctx.subscribe(); const b = ctx.subscribe(); await tick();
    expect(ctx.states.at(-1)?.packs).toHaveLength(1);
    expect(ctx.states.at(-1)?.loading).toBe(true);
    expect(ctx.syncStarted).toHaveBeenCalledTimes(2); // Packs and deletion layer, each once.
    expect(ctx.runtime.pool.subscription).toHaveBeenCalledTimes(1);
    a.unsubscribe(); expect(ctx.liveStopped).not.toHaveBeenCalled();
    b.unsubscribe(); expect(ctx.liveStopped).toHaveBeenCalledTimes(1);
  });
  it('keeps discovery alive at the root while routes/filters change, without new requests', async () => {
    const ctx = setup(); const root = ctx.directory.state$.subscribe();
    const first = ctx.subscribe(); await tick(); first.unsubscribe();
    const second = createPackFeed(ctx.runtime, { authors: [signedPack().pubkey] }).state$.subscribe();
    await tick();
    expect(ctx.syncStarted).toHaveBeenCalledTimes(2);
    expect(ctx.runtime.pool.subscription).toHaveBeenCalledTimes(1);
    expect(ctx.liveStopped).not.toHaveBeenCalled();
    second.unsubscribe(); root.unsubscribe();
    expect(ctx.liveStopped).toHaveBeenCalledTimes(1);
  });
  it('does not start sync when unmounted during asynchronous hydration', async () => {
    let resolve!: (events: ReturnType<typeof signedPack>[]) => void;
    const ctx = setup(vi.fn(() => new Promise((done) => { resolve = done; })));
    ctx.subscribe().unsubscribe(); resolve([signedPack()]); await tick();
    expect(ctx.syncStarted).not.toHaveBeenCalled();
    expect(ctx.liveStopped).toHaveBeenCalledTimes(1);
  });
  it('tolerates per-relay failures and continues streaming packs', async () => {
    const ctx = setup(vi.fn(async () => [])); ctx.subscribe(); await tick();
    ctx.status.next({ relays: { 'wss://relay.example.com/': { relay: 'wss://relay.example.com/', state: 'error', count: 0, error: new Error('offline') } }, loaded: 0, done: true });
    expect(ctx.states.at(-1)).toMatchObject({ packs: [], loading: false });
    expect(ctx.states.at(-1)?.warning).toContain('Unable to load packs');
    ctx.runtime.eventStore.add(signedPack());
    expect(ctx.states.at(-1)?.packs).toHaveLength(1);
    expect(ctx.states.at(-1)?.warning).toBeUndefined();
    expect(ctx.liveStopped).not.toHaveBeenCalled();
  });
  it.each([false, true])('keeps partial failures silent with cached data: %s', async (cached) => {
    const ctx = setup(vi.fn(async () => cached ? [signedPack()] : [])); ctx.subscribe(); await tick();
    ctx.status.next({ done: true, loaded: 0, relays: {
      'wss://failed': { relay: 'wss://failed', state: 'error', count: 0 },
      'wss://healthy': { relay: 'wss://healthy', state: 'complete', count: 0 }
    } });
    expect(ctx.states.at(-1)?.loading).toBe(false);
    expect(ctx.states.at(-1)?.warning).toBeUndefined();
  });
  it('keeps total failure silent when cached packs exist', async () => {
    const ctx = setup(); ctx.subscribe(); await tick();
    ctx.status.error(new Error('offline'));
    expect(ctx.states.at(-1)?.packs).toHaveLength(1);
    expect(ctx.states.at(-1)?.warning).toBeUndefined();
  });
  it('widens empty history without restarting live coverage', async () => {
    const ctx = setup(vi.fn(async () => [])); ctx.subscribe(); await tick();
    const since = ctx.states.at(-1)!.since; ctx.feed.loadMore();
    expect(ctx.states.at(-1)!.since).toBeLessThan(since);
    expect(ctx.runtime.pool.subscription).toHaveBeenCalledTimes(1);
  });
  it('continues sync if cache hydration fails', async () => {
    const ctx = setup(vi.fn(async () => { throw new Error('storage unavailable'); })); ctx.subscribe(); await tick();
    expect(ctx.syncStarted).toHaveBeenCalledTimes(2);
    expect(ctx.states.at(-1)?.warning).toBeUndefined();
  });
  it('an empty author filter never falls through to global discovery', () => {
    const ctx = setup(); const states: PackFeedState[] = [];
    createPackFeed(ctx.runtime, { authors: [] }).state$.subscribe((state) => states.push(state));
    expect(states.at(-1)).toMatchObject({ packs: [], loading: false, canLoadOlder: false });
    expect(ctx.runtime.pool.subscription).not.toHaveBeenCalled();
    expect(ctx.syncStarted).not.toHaveBeenCalled();
  });
  it('coalesces bulk insert rendering while displaying the first cached result immediately', async () => {
    vi.useFakeTimers(); const ctx = setup(); ctx.subscribe(); await vi.advanceTimersByTimeAsync(0);
    expect(ctx.states.at(-1)?.packs).toHaveLength(1);
    ctx.runtime.eventStore.add(signedPack({ identifier: 'two' }));
    ctx.runtime.eventStore.add(signedPack({ identifier: 'three' }));
    expect(ctx.states.at(-1)?.packs).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(500);
    expect(ctx.states.at(-1)?.packs).toHaveLength(3);
  });
  it('does not rebuild feed views for sync progress counters', async () => {
    const ctx = setup(); ctx.subscribe(); await tick();
    const count = ctx.states.length;
    ctx.status.next({ relays: {}, loaded: 1, done: false });
    ctx.status.next({ relays: {}, loaded: 2, done: false });
    expect(ctx.states).toHaveLength(count);
    ctx.status.next({ relays: {}, loaded: 2, done: true });
    expect(ctx.states.at(-1)?.loading).toBe(false);
  });
});


it('isolates live outbox errors, retries in the background, and cancels retries on teardown', async () => {
  vi.useFakeTimers();
  const ctx = setup(vi.fn(async () => []));
  const healthy = new Subject<ReturnType<typeof signedPack>>();
  const failed = new Subject<ReturnType<typeof signedPack>>();
  let attempts = 0;
  vi.mocked(ctx.runtime.pool.subscription).mockImplementation((relays) => {
    if (Array.isArray(relays) && relays[0] === 'wss://healthy.example.com') return healthy;
    return new Observable((observer) => { attempts++; return failed.subscribe(observer); });
  });
  const directory = createPackDirectory(ctx.runtime, NOW, of([
    { relays: ['wss://healthy.example.com'] }, { relays: ['wss://failed.example.com'] }
  ]));
  const states: PackFeedState[] = [];
  const sub = createPackFeed(ctx.runtime, {}, { directory }).state$.subscribe((state) => states.push(state));
  disposers.push(() => sub.unsubscribe());
  await vi.advanceTimersByTimeAsync(0);
  failed.error(new Error('relay refused subscription'));
  expect(states.at(-1)?.warning).toBeUndefined();
  healthy.next(signedPack());
  expect(states.at(-1)?.packs).toHaveLength(1);
  await vi.advanceTimersByTimeAsync(5000);
  expect(attempts).toBe(2);
  sub.unsubscribe();
  await vi.advanceTimersByTimeAsync(10000);
  expect(attempts).toBe(2);
});
