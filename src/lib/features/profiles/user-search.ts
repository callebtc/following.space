import { decodeProfilePointer, kinds } from 'applesauce-core/helpers';
import { combineLatest, defer, finalize, firstValueFrom, fromEvent, map, of, race, startWith, switchMap, filter, timeout, mergeMap, throwError } from 'rxjs';
import { SEARCH_RELAYS } from '../../nostr/relay-defaults';
import { getNostrRuntime } from '../../nostr/runtime.client';
import { requestEvents$ } from '../../nostr/requests';
import { accounts } from '../../nostr/accounts';
import { searchRankedPubkeys } from './open-ranking';
import { parseProfile } from '../../nostr/protocol/profile';

export interface UserSearchResult { pubkey: string; relays: string[]; rank: number }
export interface UserSearchState { results: UserSearchResult[]; loading: boolean }

export function observeUserSearch(query: string, limit = 5, source: 'ranking' | 'relay' = 'ranking') {
  query = query.trim();
  return defer(() => {
    if (!query) return of<UserSearchState>({ results: [], loading: false });
    const controller = new AbortController();
    const pointer = /^[0-9a-f]{64}$/i.test(query) ? { pubkey: query } : decodeProfilePointer(query.replace(/^nostr:/, ''));
    if (pointer) return of<UserSearchState>({ results: [{ pubkey: pointer.pubkey, relays: pointer.relays ?? [], rank: 0 }], loading: false });
    if (source === 'ranking') return defer(() => searchRankedPubkeys(query, limit, controller.signal)).pipe(
      map((results): UserSearchState => ({ results: results.map((result) => ({ ...result, relays: [] })), loading: false })),
      finalize(() => controller.abort())
    );
    return defer(getNostrRuntime).pipe(switchMap((runtime) => {
      const queryFilter = { kinds: [kinds.Metadata], search: query, limit: 100 };
      const contacts$ = accounts.active$.pipe(switchMap((account) => account
        ? runtime.eventStore.replaceable(kinds.Contacts, account.pubkey) : of(undefined)));
      const loading$ = defer(() => runtime.hydrate([queryFilter])).pipe(
        switchMap(() => requestEvents$(runtime, queryFilter, SEARCH_RELAYS)),
        map(() => false), startWith(true)
      );
      return combineLatest([runtime.eventStore.timeline(queryFilter), contacts$, loading$]).pipe(
        map(([events, contacts, loading]): UserSearchState => {
          const following = new Set(contacts?.tags.filter((tag) => tag[0] === 'p').map((tag) => tag[1]));
          const results = events.filter((event) => parseProfile(event).name?.toLowerCase().includes(query.toLowerCase()))
            .map((event) => ({ pubkey: event.pubkey, relays: [], rank: following.has(event.pubkey) ? 1 : 0 }))
            .sort((a, b) => b.rank - a.rank).slice(0, limit);
          return { results, loading };
        })
      );
    }));
  });
}

/** Snapshot boundary for non-reactive callers; UI consumers subscribe directly. */
export function searchUsersByName(query: string, limit = 5, signal?: AbortSignal, source: 'ranking' | 'relay' = 'ranking') {
  if (signal?.aborted) return Promise.reject(new DOMException('Cancelled', 'AbortError'));
  const results$ = observeUserSearch(query, limit, source).pipe(filter((state) => !state.loading), map((state) => state.results), timeout({ first: 10000 }));
  return firstValueFrom(signal ? race(results$, fromEvent(signal, 'abort').pipe(
    mergeMap(() => throwError(() => new DOMException('Cancelled', 'AbortError')))
  )) : results$);
}
