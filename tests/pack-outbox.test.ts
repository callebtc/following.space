import { afterEach, describe, expect, it, vi } from 'vitest';
import { NEVER, Observable, firstValueFrom, of, filter, take } from 'rxjs';
import { addSeenRelay, finalizeEvent, type Filter } from 'applesauce-core/helpers';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { loadPack, observePack } from '../src/lib/features/packs/detail';
import { packHref, packNaddr, packRelayHints, resolvePackLink } from '../src/lib/nostr/protocol/pack-link';
import { parseFollowListEvent } from '../src/lib/nostr/protocol/follow-pack';
import { alice, signedPack } from './fixtures';

const OUTBOX = 'wss://personal-outbox.example/';
const stops: (() => void)[] = [];
afterEach(() => { stops.splice(0).forEach((stop) => stop()); vi.useRealTimers(); });
function mailboxes(timestamp = 1, relay = OUTBOX) {
  return finalizeEvent({ kind: 10002, created_at: timestamp, content: '',
    tags: [['r', relay, 'write'], ['r', 'wss://inbox-only.example', 'read']] }, alice);
}
function setup(cached: boolean, deleted = false) {
  const pack = signedPack({ timestamp: Math.floor(Date.now() / 1000) - 86400 });
  const metadata = mailboxes();
  const deletion = finalizeEvent({ kind: 5, created_at: pack.created_at + 1, content: '',
    tags: [['a', `39089:${pack.pubkey}:garden`], ['k', '39089']] }, alice);
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} }, relays: ['wss://app.example'] });
  stops.push(() => runtime.dispose());
  if (cached) runtime.eventStore.add(metadata);
  const liveTargets: string[][] = [];
  vi.spyOn(runtime.pool, 'subscription').mockImplementation((targets) => new Observable(() => {
    const sub = (targets as Observable<string[]>).subscribe((value) => liveTargets.push(value));
    return () => sub.unsubscribe();
  }));
  const request = vi.spyOn(runtime.pool, 'request').mockImplementation((relays, filters) => {
    if (!Array.isArray(relays)) throw new Error('Expected finite request targets');
    const queries = (Array.isArray(filters) ? filters : [filters]) as Filter[];
    if (queries.some((query) => query.kinds?.includes(10002))) {
      // Fresh discovery must reach metadata lookup relays, not pretend the app relay has the list.
      return of(...(relays.includes(runtime.lookupRelays$.value[0]) ? [metadata] : []));
    }
    if (!relays.includes(OUTBOX)) return of();
    const events = [pack, ...(deleted ? [deletion] : [])].filter((event) => queries.some((query) =>
      query.kinds?.includes(event.kind) && (!query.since || event.created_at >= query.since)));
    return of(...events);
  });
  return { runtime, pack, request, liveTargets };
}

describe('pack author outbox routing', () => {
  it('refreshes old history when metadata arrives after the snapshot deadline', async () => {
    vi.useFakeTimers();
    const { runtime, pack, request } = setup(false);
    request.mockImplementation((relays, filters) => {
      if (!Array.isArray(relays)) throw new Error('Expected finite request targets');
      const queries = (Array.isArray(filters) ? filters : [filters]) as Filter[];
      if (queries.some((query) => query.kinds?.includes(10002))) return NEVER;
      return relays.includes(OUTBOX) ? of(pack) : of();
    });
    const seen: (string | undefined)[] = [];
    const sub = observePack(runtime, 'garden', pack.pubkey).subscribe((state) => seen.push(state.pack?.eventId));
    await vi.advanceTimersByTimeAsync(2200);
    expect(seen).not.toContain(pack.id);
    runtime.eventStore.add(mailboxes());
    await vi.advanceTimersByTimeAsync(0);
    expect(seen).toContain(pack.id);
    sub.unsubscribe();
    const count = request.mock.calls.length;
    runtime.eventStore.add(mailboxes(2, 'wss://later.example/'));
    await vi.advanceTimersByTimeAsync(0);
    expect(request).toHaveBeenCalledTimes(count);
  });

  it.each([true, false])('loads an older pack only available at the author outbox (cached metadata: %s)', async (cached) => {
    const { runtime, pack, request } = setup(cached);
    expect((await loadPack(runtime, 'garden', pack.pubkey))?.eventId).toBe(pack.id);
    const history = request.mock.calls.find(([, filters]) => (filters as Filter[]).some((query) => query.kinds?.includes(39089)));
    expect(history?.[0]).toContain(OUTBOX);
    expect(history?.[0]).not.toContain('wss://inbox-only.example/');
    expect((history?.[1] as Filter[]).every((query) => query.since === undefined)).toBe(true);
    expect(history?.[1]).toContainEqual({ kinds: [5], '#k': ['39089'], authors: [pack.pubkey] });
    expect(runtime.eventStore.getReplaceable(10002, pack.pubkey)).toBeDefined();
  });

  it.each([true, false])('reads historical deletions from the same outboxes (cached metadata: %s)', async (cached) => {
    const { runtime, pack } = setup(cached, true);
    expect(await loadPack(runtime, packNaddr(parseFollowListEvent(pack)!))).toBeNull();
  });

  it.each([true, false])('routes live subscriptions through discovered and subsequently changed outboxes: %s', async (cached) => {
    const { runtime, pack, liveTargets } = setup(cached);
    const state = await firstValueFrom(observePack(runtime, 'garden', pack.pubkey).pipe(filter((state) => !state.loading), take(1)));
    expect(state.pack?.eventId).toBe(pack.id);
    // Keep a second observer alive to check metadata updates and teardown.
    const sub = observePack(runtime, 'garden', pack.pubkey).subscribe();
    expect(liveTargets.at(-1)).toContain(OUTBOX);
    runtime.eventStore.add(mailboxes(2, 'wss://new-outbox.example/'));
    expect(liveTargets.at(-1)).toContain('wss://new-outbox.example/');
    expect(liveTargets.at(-1)).not.toContain(OUTBOX);
    sub.unsubscribe();
    const count = liveTargets.length;
    runtime.eventStore.add(mailboxes(3, 'wss://after-unsubscribe.example/'));
    expect(liveTargets).toHaveLength(count);
  });

  it('displays cached packs synchronously while metadata discovery is pending, and cancels history on unsubscribe', async () => {
    vi.useFakeTimers();
    const { runtime, pack, request } = setup(false);
    request.mockReturnValue(NEVER);
    runtime.eventStore.add(pack);
    const states: (string | undefined)[] = [];
    const sub = observePack(runtime, 'garden', pack.pubkey).subscribe((state) => states.push(state.pack?.eventId));
    expect(states[0]).toBe(pack.id);
    await Promise.resolve();
    sub.unsubscribe();
    await vi.advanceTimersByTimeAsync(1600);
    expect(request.mock.calls.every(([, filters]) => !(filters as Filter[]).some((query) => query.kinds?.includes(39089)))).toBe(true);
    expect(states).toHaveLength(1);
  });

  it('uses seen-event relays before author outboxes in generated and copied links', () => {
    const { runtime, pack } = setup(true);
    addSeenRelay(pack, 'wss://accepted-publish.example');
    runtime.eventStore.add(pack);
    const parsed = parseFollowListEvent(pack)!;
    const hints = packRelayHints(runtime, parsed, ['wss://embedded.example']);
    expect(hints).toEqual(['wss://accepted-publish.example/', OUTBOX, 'wss://embedded.example/']);
    expect(resolvePackLink(packHref(parsed, hints).slice(3)).relays).toEqual(hints);
    const copied = `nostr:${packNaddr(parsed, hints)}`;
    expect(resolvePackLink(copied.slice('nostr:'.length)).relays).toEqual(hints);
  });

  it('cancels an editor read promptly while metadata is still being discovered', async () => {
    vi.useFakeTimers();
    const { runtime, pack, request } = setup(false);
    request.mockReturnValue(NEVER);
    const controller = new AbortController();
    const loading = loadPack(runtime, 'garden', pack.pubkey, controller.signal);
    await Promise.resolve();
    controller.abort();
    await expect(loading).rejects.toMatchObject({ name: 'AbortError' });
    await vi.advanceTimersByTimeAsync(1600);
    expect(request.mock.calls.every(([, filters]) => !(filters as Filter[]).some((query) => query.kinds?.includes(39089)))).toBe(true);
  });
});
