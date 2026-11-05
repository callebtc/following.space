import { resolvePackLink } from '../../nostr/protocol/pack-link';
import { eventRelays, normalizeRelays } from '../../nostr/relay-policy';
import { Observable, Subscription, shareReplay, map, combineLatest, of, from, fromEvent, firstValueFrom, takeUntil, defaultIfEmpty } from 'rxjs';
import { loadOutboxRelays } from '../../nostr/outboxes';
import { type FollowList, FOLLOW_LIST_KIND, parseFollowListEvent } from '../../nostr/protocol/follow-pack';
import type { NostrRuntime } from '../../nostr/runtime';
import { requestEvents } from '../../nostr/requests';
import { kinds, type Filter, type NostrEvent } from 'applesauce-core/helpers';

export interface PackDetailState { pack: FollowList | null; candidates: FollowList[]; loading: boolean; error?: string }
export class AmbiguousPackError extends Error {
  constructor(public candidates: FollowList[]) { super('Several authors use this pack identifier. Choose an author.'); }
}
function packQuery(value: string, author?: string) {
  const { identifier, pubkey, relays } = resolvePackLink(value, author);
  const filter: Filter = { kinds: [FOLLOW_LIST_KIND], '#d': [identifier], ...(pubkey ? { authors: [pubkey] } : {}) };
  const deletes: Filter = { kinds: [kinds.EventDeletion], '#k': [String(FOLLOW_LIST_KIND)], ...(pubkey ? { authors: [pubkey] } : {}) };
  return { pubkey, relays, filter, deletes };
}
function parsePacks(events: NostrEvent[]) {
  return events.flatMap((event) => {
    const pack = parseFollowListEvent(event); return pack ? [pack] : [];
  });
}
async function refreshPack(runtime: NostrRuntime, query: ReturnType<typeof packQuery>, signal?: AbortSignal) {
  const filters = [query.filter, query.deletes];
  await runtime.hydrate(filters).catch(() => {});
  signal?.throwIfAborted();
  const discovery$ = query.pubkey ? from(loadOutboxRelays(runtime, query.pubkey)) : of([] as string[]);
  const outboxes = await firstValueFrom(signal ? discovery$.pipe(takeUntil(fromEvent(signal, 'abort')), defaultIfEmpty([])) : discovery$);
  signal?.throwIfAborted();
  await requestEvents(runtime, filters, normalizeRelays([...runtime.relayPolicy.readRelays, ...query.relays, ...outboxes]), signal);
}

export function observePack(runtime: NostrRuntime, value: string, author?: string) {
  return new Observable<PackDetailState>((observer) => {
    let location: ReturnType<typeof packQuery>;
    try { location = packQuery(value, author); } catch {
      observer.next({ pack: null, candidates: [], loading: false, error: 'Invalid pack address' }); return;
    }
    const { pubkey, relays, filter, deletes } = location;
    const scope = new Subscription();
    const controller = new AbortController();
    let settled = false;
    let warning: string | undefined;
    let current: NostrEvent[] = [];
    const emit = () => {
      if (scope.closed) return;
      const candidates = parsePacks(current);
      observer.next({ pack: (pubkey || settled) && candidates.length === 1 ? candidates[0] : null,
        candidates: !pubkey && settled && candidates.length > 1 ? candidates : [],
        loading: !settled && (!pubkey || !candidates.length), error: settled && !candidates.length ? warning : undefined });
    };
    // Consume the model's atomic revision view. During insert notifications the
    // underlying database can briefly contain both revisions before old cleanup.
    scope.add(runtime.eventStore.timeline(filter).subscribe((events) => { current = events; emit(); }));
    const boundary = Math.floor(Date.now() / 1000) - 60;
    const outboxes$ = pubkey ? runtime.eventStore.replaceable(kinds.RelayList, pubkey).pipe(map((event) => eventRelays(event, 'write'))) : of([] as string[]);
    const targets$ = combineLatest([runtime.relayPolicy.readRelays$, outboxes$]).pipe(
      map(([current, outboxes]) => normalizeRelays([...current, ...relays, ...outboxes]))
    );
    scope.add(runtime.pool.subscription(targets$, [filter, deletes].map((f) => ({ ...f, since: boundary }))).subscribe({
      next: (event) => runtime.eventStore.add(event), error: () => {}
    }));
    void refreshPack(runtime, location, controller.signal).catch((error) => {
      warning = error instanceof Error ? error.message : 'Pack could not be refreshed';
    }).then(() => {
      if (controller.signal.aborted) return;
      settled = true; emit();
    });
    return () => { scope.unsubscribe(); controller.abort(); };
  }).pipe(shareReplay({ bufferSize: 1, refCount: true }));
}

export async function loadPack(runtime: NostrRuntime, value: string, author?: string, signal?: AbortSignal) {
  const query = packQuery(value, author);
  await refreshPack(runtime, query, signal);
  const packs = parsePacks(runtime.eventStore.getTimeline(query.filter));
  const { pubkey } = query;
  if (!pubkey && packs.length > 1) throw new AmbiguousPackError(packs);
  return packs[0] ?? null;
}
