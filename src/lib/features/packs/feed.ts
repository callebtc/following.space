import type { Filter, NostrEvent } from 'applesauce-core/helpers';
import type { TimelineWindow } from 'applesauce-loaders/loaders';
import { BehaviorSubject, combineLatest, shareReplay, map, of, throttle, timer, EMPTY } from 'rxjs';
import { createContactsPackDirectory } from './contacts-directory';
import { getPackDirectory, type PackDirectory } from './directory';
import { FOLLOW_LIST_KIND, packAddress, parseFollowListEvent, type FollowList } from '../../nostr/protocol/follow-pack';
import type { NostrRuntime } from '../../nostr/runtime';

export const PACK_PAGE_SIZE = 20;
export type PackFilter = { authors?: string[]; included?: string[]; contactOutboxes?: boolean };
export interface PackFeedState {
  packs: FollowList[];
  loading: boolean;
  since: number;
  canLoadOlder: boolean;
  warning?: string;
}

// Preserve the existing moderation rule without importing auth or browser services.
const HIDDEN_AUTHORS = new Set(['414f438fe851a53ee2dc94883300d04f04165337141fc97563a5ee6542637660']);

/** Latest revision per full address, including when supplied old cache revisions. */
export function selectPacks(events: NostrEvent[], window: TimelineWindow, limit: number): FollowList[] {
  const addresses = new Set<string>();
  return [...events]
    .sort((a, b) => b.created_at - a.created_at || a.id.localeCompare(b.id))
    .flatMap((event) => {
      const pack = parseFollowListEvent(event);
      if (!pack || HIDDEN_AUTHORS.has(pack.pubkey)) return [];
      const address = packAddress(pack);
      if (addresses.has(address)) return [];
      addresses.add(address);
      // Keep live arrivals newer than the history window's captured upper bound.
      return pack.createdAt >= window.since ? [pack] : [];
    }).slice(0, limit);
}

/** Store projections over shared discovery, with contact outbox sync when requested. */
export function createPackFeed(runtime: NostrRuntime, filter: PackFilter = {}, options: { now?: number; directory?: PackDirectory } = {}) {
  const directory = options.directory ?? (filter.contactOutboxes && filter.authors?.length
    ? createContactsPackDirectory(runtime, filter.authors, options.now) : getPackDirectory(runtime, options.now));
  const visibleLimit$ = new BehaviorSubject(PACK_PAGE_SIZE);
  const initial: PackFeedState = { packs: [], loading: true, since: directory.window$.value.since, canLoadOlder: true };
  const packFilter: Filter = {
    kinds: [FOLLOW_LIST_KIND], ...(filter.authors ? { authors: filter.authors } : {}),
    ...(filter.included ? { '#p': filter.included } : {})
  };
  const empty = filter.authors?.length === 0 || filter.included?.length === 0;
  let available = 0;
  const state$ = empty ? of({ ...initial, loading: false, canLoadOlder: false }) : combineLatest([
    runtime.eventStore.timeline(packFilter).pipe(
      // Emit the first populated result immediately; coalesce bulk sync updates.
      throttle((events) => events.length ? timer(500) : EMPTY, { leading: true, trailing: true })
    ), directory.state$, visibleLimit$
  ]).pipe(map(([events, status, limit]): PackFeedState => {
    const packs = selectPacks(events, { since: status.since, until: directory.window$.value.until }, Infinity);
    available = packs.length;
    return { packs: packs.slice(0, limit), since: status.since, loading: status.loading,
      canLoadOlder: status.since > 0 || available > limit, warning: !status.loading && !packs.length ? status.warning : undefined };
  }), shareReplay({ bufferSize: 1, refCount: true }));
  return { state$, initial,
    loadMore() {
      visibleLimit$.next(visibleLimit$.value + PACK_PAGE_SIZE);
      if (available < visibleLimit$.value && directory.window$.value.since > 0) directory.loadOlder();
    },
    retry: directory.retry
  };
}
