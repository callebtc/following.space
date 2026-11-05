import { afterEach, describe, expect, it, vi } from 'vitest';
import { PrivateKeyAccount } from 'applesauce-accounts/accounts';
import { castUser } from 'applesauce-common/casts';
import { finalizeEvent, type NostrEvent } from 'applesauce-core/helpers';
import { concat, EMPTY, NEVER, Observable, of, throwError } from 'rxjs';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { updateContacts } from '../src/lib/features/contacts/commands';
import { loadOutboxRelays } from '../src/lib/nostr/outboxes';
import { alice, NOW } from './fixtures';

type Message = NostrEvent | 'EOSE';
const app = 'wss://app.example.com/';
const lookup = 'wss://lookup.example.com/';
const personal = 'wss://personal.example.com/';
const friend = 'b'.repeat(64);
const added = 'c'.repeat(64);
const cleanup: (() => void)[] = [];
afterEach(() => { cleanup.splice(0).forEach((fn) => fn()); vi.useRealTimers(); });

function setup(network: (url: string, kind: number) => Observable<Message> = () => of('EOSE')) {
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} }, relays: [app] });
  runtime.setLookupRelays([lookup]);
  const account = PrivateKeyAccount.fromKey(alice);
  // Keep the real runtime, store, cast and relay objects; replace only incoming network streams.
  runtime.pool.add$.subscribe((relay) => vi.spyOn(relay, 'subscription').mockImplementation((filters) => {
    const filter = Array.isArray(filters) ? filters[0] : filters;
    if (typeof filter === 'function' || !('kinds' in filter)) throw new Error('Unexpected dynamic filter');
    return network(relay.url, filter.kinds![0]);
  }));
  // Cast-triggered background loaders are best effort and must not authorize a write.
  vi.spyOn(runtime.pool, 'request').mockImplementation((_urls, filters) => {
    const list = Array.isArray(filters) ? filters : [filters];
    return list.some((filter) => typeof filter === 'object' && 'kinds' in filter && filter.kinds?.includes(3)) ? EMPTY : NEVER;
  });
  const publish = vi.spyOn(runtime.pool, 'publish').mockResolvedValue([{ from: app, ok: true }]);
  const sign = vi.spyOn(account, 'signEvent');
  const snapshot = vi.fn();
  cleanup.push(() => runtime.dispose());
  return { runtime, account, sign, publish, snapshot,
    write: () => updateContacts(runtime, account, { add: [added] }, () => true, snapshot) };
}

function metadata() {
  return finalizeEvent({ kind: 10002, created_at: NOW, tags: [['r', personal, 'write']], content: '' }, alice);
}
function contacts() {
  return finalizeEvent({ kind: 3, created_at: NOW, tags: [['p', friend, 'wss://hint.example.com', 'Friend'], ['custom', 'keep']], content: 'legacy' }, alice);
}
function delayed(messages: Message[], delay: number) {
  return new Observable<Message>((subscriber) => {
    const timer = setTimeout(() => { messages.forEach((message) => subscriber.next(message)); subscriber.complete(); }, delay);
    return () => clearTimeout(timer);
  });
}

describe('strict contact discovery', () => {
  it('waits for metadata arriving at 2200ms and preserves follows found only on the personal outbox', async () => {
    vi.useFakeTimers();
    const previous = contacts();
    const reads: string[] = [];
    const ctx = setup((url, kind) => {
      if (kind === 10002 && url === lookup) return delayed([metadata(), 'EOSE'], 2200);
      if (kind === 3) {
        reads.push(url);
        return url === personal ? of(previous, 'EOSE') : of('EOSE');
      }
      return of('EOSE');
    });
    const observed: string[][] = [];
    const cast = castUser(ctx.account.pubkey, ctx.runtime.eventStore).outboxes$.subscribe((value) => { if (value) observed.push(value); });
    cleanup.push(() => cast.unsubscribe());
    const bestEffort = loadOutboxRelays(ctx.runtime, ctx.account.pubkey);
    const result = ctx.write();
    await vi.advanceTimersByTimeAsync(1501);
    expect(await bestEffort).toEqual([]);
    expect(ctx.sign).not.toHaveBeenCalled();
    expect(ctx.publish).not.toHaveBeenCalled();
    expect(reads).toEqual([]);
    await vi.advanceTimersByTimeAsync(699);
    const event = await result;
    expect(observed.some((urls) => urls.includes(personal))).toBe(true);
    expect(reads).toContain(personal);
    expect(event.tags).toContainEqual(previous.tags[0]);
    expect(event.tags).toContainEqual(['custom', 'keep']);
    expect(event.tags).toContainEqual(['p', added]);
    expect(event.content).toBe('legacy');
    expect(ctx.sign).toHaveBeenCalledTimes(1);
    expect(ctx.snapshot.mock.calls.map(([event]) => event.id)).toEqual([previous.id, event.id]);
  });

  it('supports a new user after successful empty metadata and contact EOSE reads', async () => {
    const ctx = setup();
    const event = await ctx.write();
    expect(event.tags).toContainEqual(['p', added]);
    expect(ctx.sign).toHaveBeenCalledTimes(1);
    expect(ctx.publish).toHaveBeenCalledTimes(1);
  });

  it('supports discovered metadata with no existing contact list', async () => {
    const ctx = setup((_url, kind) => kind === 10002 ? of(metadata(), 'EOSE') : of('EOSE'));
    expect((await ctx.write()).tags).toContainEqual(['p', added]);
    expect(ctx.publish.mock.calls[0][0]).toContain(personal);
  });

  it.each([10002, 3])('aborts on partial relay failure reading kind %s and preserves the cached previous list', async (failedKind) => {
    const previous = contacts();
    const ctx = setup((url, kind) => {
      if (kind === failedKind && url === app) return throwError(() => new Error('offline'));
      return kind === 10002 ? of(metadata(), 'EOSE') : of('EOSE');
    });
    ctx.runtime.eventStore.add(previous);
    await expect(ctx.write()).rejects.toThrow('offline');
    expect(ctx.sign).not.toHaveBeenCalled();
    expect(ctx.publish).not.toHaveBeenCalled();
    expect(ctx.snapshot).not.toHaveBeenCalled();
    expect(ctx.runtime.eventStore.getReplaceable(3, ctx.account.pubkey)?.id).toBe(previous.id);
  });

  it.each([10002, 3])('does not interpret a silent relay as absence for kind %s', async (silentKind) => {
    vi.useFakeTimers();
    const ctx = setup((url, kind) => {
      if (kind === silentKind && url === lookup && kind === 10002) return NEVER;
      if (kind === silentKind && url === personal && kind === 3) return concat(of(contacts()), NEVER);
      return kind === 10002 ? of(metadata(), 'EOSE') : of('EOSE');
    });
    const result = expect(ctx.write()).rejects.toThrow('Timeout');
    await vi.advanceTimersByTimeAsync(6001);
    await result;
    expect(ctx.sign).not.toHaveBeenCalled();
    expect(ctx.publish).not.toHaveBeenCalled();
  });

  it('requires EOSE, not just stream completion', async () => {
    const ctx = setup(() => EMPTY);
    await expect(ctx.write()).rejects.toThrow('before EOSE');
    expect(ctx.sign).not.toHaveBeenCalled();
    expect(ctx.publish).not.toHaveBeenCalled();
  });

  it('does not silently skip an unhealthy discovery relay', async () => {
    const ctx = setup();
    vi.spyOn(ctx.runtime.pool, 'filterRelays').mockImplementation((urls) => urls.filter((url) => url !== lookup));
    await expect(ctx.write()).rejects.toThrow('all relays');
    expect(ctx.sign).not.toHaveBeenCalled();
    expect(ctx.publish).not.toHaveBeenCalled();
  });
});
