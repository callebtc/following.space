import { BehaviorSubject, Observable, Subscription, combineLatest, map, of, shareReplay } from 'rxjs';
import { filterOptimalRelays, includeFallbackRelays, includeMailboxes } from 'applesauce-core';
import { createOutboxMap, kinds, type NostrEvent } from 'applesauce-core/helpers';
import { ignoreUnhealthyRelays, ignoreUnhealthyRelaysOnPointers } from 'applesauce-relay';
import { createOutboxTimelineLoader } from 'applesauce-loaders/loaders';
import type { NostrRuntime } from '../../nostr/runtime';

export interface PostState { events: NostrEvent[]; loading: boolean; warning?: string }
export function createPostTimeline(runtime: NostrRuntime, pubkeys: string[]) {
  const authors = [...new Set(pubkeys)].filter((key) => /^[0-9a-f]{64}$/i.test(key));
  const now = Math.floor(Date.now() / 1000);
  const windows = new BehaviorSubject({ since: now - 30 * 86400, until: now });
  let limit = 50;
  const state$ = new Observable<PostState>((observer) => {
    if (!authors.length) { observer.next({ events: [], loading: false }); return; }
    const scope = new Subscription();
    let state: PostState = { events: [], loading: true };
    let failed = false;
    const update = (patch: Partial<PostState>) => {
      state = { ...state, ...patch };
      state.warning = failed && !state.loading && !state.events.length ? 'Unable to load posts. Please retry.' : undefined;
      observer.next(state);
    };
    const fallbacks$ = runtime.relayPolicy.readRelays$.pipe(ignoreUnhealthyRelays(runtime.liveness));
    const outboxes$ = of(authors.map((pubkey) => ({ pubkey }))).pipe(
      includeMailboxes(runtime.eventStore),
      // Re-select whenever relay health changes, before applying connection limits.
      ignoreUnhealthyRelaysOnPointers(runtime.liveness),
      includeFallbackRelays(fallbacks$),
      filterOptimalRelays(30, 4),
      map(createOutboxMap),
      shareReplay({ bufferSize: 1, refCount: true })
    );
    const loader = createOutboxTimelineLoader(runtime.pool, outboxes$, { kinds: [kinds.ShortTextNote] }, {
      eventStore: runtime.eventStore, cache: runtime.cacheRequest, liveness: runtime.liveness,
      prefetch: 0, responseTimeout: 8000
    });
    scope.add(combineLatest([runtime.eventStore.timeline({ kinds: [kinds.ShortTextNote], authors }), windows]).subscribe(([events, window]) => {
      update({ events: events.filter((event) => event.created_at >= window.since && !event.tags.some((tag) => tag[0] === 'e')).slice(0, limit) });
    }));
    scope.add(loader.status$.subscribe((statuses) => {
      const relays = statuses.filter((s) => /^wss?:/.test(s.source) && s.state !== 'removed');
      failed = relays.length > 0 && relays.every((s) => s.state === 'incomplete' && s.reason === 'request');
      update({ loading: statuses.some((s) => s.state === 'loading') });
    }));
    scope.add(loader(windows).subscribe({ error: () => { failed = true; update({ loading: false }); } }));
    scope.add(runtime.pool.outboxSubscription(outboxes$, { kinds: [kinds.ShortTextNote], since: now - 60 }).subscribe({
      next: (event) => runtime.eventStore.add(event), error: () => {}
    }));
    return () => scope.unsubscribe();
  }).pipe(shareReplay({ bufferSize: 1, refCount: true }));
  return { state$, loadMore() { limit += 50; windows.next({ ...windows.value, since: Math.max(0, windows.value.since - 90 * 86400) }); } };
}
