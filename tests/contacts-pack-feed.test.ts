import { afterEach, expect, it, vi } from 'vitest';
import { EMPTY, Observable, of } from 'rxjs';
import { finalizeEvent } from 'applesauce-core/helpers';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { createPackFeed } from '../src/lib/features/packs/feed';
import { alice, bob, NOW, signedPack } from './fixtures';

afterEach(() => vi.useRealTimers());

it('syncs packs and deletions from contact write outboxes, updates routing, and tears down', async () => {
  vi.useFakeTimers();
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} } });
  const pack = signedPack();
  const other = signedPack({ key: bob });
  const mailbox = (key: Uint8Array, relay: string, created_at = NOW) => finalizeEvent({
    kind: 10002, created_at, content: '', tags: [['r', relay, 'write'], ['r', 'wss://inbox.example.com', 'read']]
  }, key);
  runtime.eventStore.add(mailbox(alice, 'wss://alice.example.com'));
  runtime.eventStore.add(mailbox(bob, 'wss://bob.example.com'));
  const stopped = vi.fn();
  const live = vi.spyOn(runtime.pool, 'subscription').mockReturnValue(new Observable(() => stopped));
  const sync = vi.spyOn(runtime, 'syncLoader').mockImplementation(({ filter }) => {
    if (filter.kinds?.includes(pack.kind)) runtime.eventStore.add(filter.authors?.includes(pack.pubkey) ? pack : other);
    return { status$: of({ done: true, loaded: 1, relays: {} }), events$: EMPTY };
  });
  const feed = createPackFeed(runtime, { authors: [pack.pubkey, other.pubkey], contactOutboxes: true }, { now: NOW });
  let state = feed.initial;
  const sub = feed.state$.subscribe((next) => { state = next; });
  try {
    await vi.advanceTimersByTimeAsync(1000);
    expect(sync).toHaveBeenCalledTimes(4);
    for (const [{ relays, filter }] of sync.mock.calls) {
      if (!Array.isArray(relays)) throw new Error('Expected fixed relay targets');
      const isAlice = relays[0] === 'wss://alice.example.com/';
      expect(relays).toEqual([isAlice ? 'wss://alice.example.com/' : 'wss://bob.example.com/']);
      expect(filter.authors).toEqual([isAlice ? pack.pubkey : other.pubkey]);
    }
    expect(state.packs).toHaveLength(2);
    expect(state.loading).toBe(false);
    const since = state.since;
    feed.loadMore();
    await vi.advanceTimersByTimeAsync(0);
    expect(state.since).toBeLessThan(since);
    expect(live).toHaveBeenCalledTimes(2);
    runtime.eventStore.add(mailbox(alice, 'wss://new.example.com', NOW + 1));
    await vi.advanceTimersByTimeAsync(500);
    expect(live.mock.calls.some(([relays]) => Array.isArray(relays) && relays.includes('wss://new.example.com/'))).toBe(true);
    sub.unsubscribe();
    expect(stopped).toHaveBeenCalledTimes(live.mock.calls.length);
    const count = sync.mock.calls.length;
    runtime.eventStore.add(mailbox(alice, 'wss://later.example.com', NOW + 2));
    await vi.advanceTimersByTimeAsync(1000);
    expect(sync).toHaveBeenCalledTimes(count);
  } finally { sub.unsubscribe(); runtime.dispose(); }
});

it('uses fallback relays when a contact has no write outbox and cancels pending hydration', async () => {
  vi.useFakeTimers();
  const pack = signedPack();
  let finishHydration!: (events: typeof pack[]) => void;
  const runtime = createNostrRuntime({
    relays: ['wss://fallback.example.com'],
    cache: { read: () => new Promise((resolve) => { finishHydration = resolve; }), write: async () => {} }
  });
  // An inbox-only list must not route pack discovery to the private inbox.
  runtime.eventStore.add(finalizeEvent({
    kind: 10002, created_at: NOW, content: '', tags: [['r', 'wss://inbox.example.com', 'read']]
  }, alice));
  const stopped = vi.fn();
  const live = vi.spyOn(runtime.pool, 'subscription').mockReturnValue(new Observable(() => stopped));
  const sync = vi.spyOn(runtime, 'syncLoader');
  const feed = createPackFeed(runtime, { authors: [pack.pubkey], contactOutboxes: true }, { now: NOW });
  const sub = feed.state$.subscribe();
  try {
    await vi.advanceTimersByTimeAsync(500);
    expect(live).toHaveBeenCalledTimes(1);
    expect(live.mock.calls[0][0]).toEqual(['wss://fallback.example.com/']);
    expect(live.mock.calls[0][1]).toEqual(expect.arrayContaining([
      expect.objectContaining({ kinds: [39089], authors: [pack.pubkey] }),
      expect.objectContaining({ kinds: [5], authors: [pack.pubkey], '#k': ['39089'] })
    ]));
    sub.unsubscribe();
    finishHydration([]);
    await vi.advanceTimersByTimeAsync(0);
    expect(sync).not.toHaveBeenCalled();
    expect(stopped).toHaveBeenCalledTimes(1);
  } finally { sub.unsubscribe(); runtime.dispose(); }
});
