import type { Filter, NostrEvent } from 'applesauce-core/helpers';
import type { NostrRuntime } from './runtime';
import { filter, firstValueFrom, forkJoin, take, tap, timeout as bound, defer, toArray, race, fromEvent, mergeMap, throwError, map, of, defaultIfEmpty, catchError } from 'rxjs';
import { normalizeRelays } from './relay-policy';

/** Best-effort finite read: group completion can include failed or unfinished relays. */
export function requestEvents(runtime: NostrRuntime, filters: Filter | Filter[], relays = runtime.relays, signal?: AbortSignal, timeout = 6000): Promise<NostrEvent[]> {
  if (signal?.aborted) return Promise.reject(new DOMException('Cancelled', 'AbortError'));
  const result$ = requestEvents$(runtime, filters, relays, timeout);
  return firstValueFrom(signal ? race(result$, fromEvent(signal, 'abort').pipe(
    mergeMap(() => throwError(() => new DOMException('Cancelled', 'AbortError')))
  )) : result$);
}

/** Finite best-effort read; unsubscribing cancels the underlying request. */
export function requestEvents$(runtime: NostrRuntime, filters: Filter | Filter[], relays = runtime.relays, timeout = 6000) {
  return defer(() => {
    const targets = runtime.pool.filterRelays(relays);
    if (!targets.length) throw new Error('No healthy relays are available. Please retry.');
    return runtime.pool.request(targets, filters, { timeout, firstResponseTimeout: timeout, waitForAuth: false }).pipe(
      tap((event) => runtime.eventStore.add(event)), toArray(), bound({ first: timeout })
    );
  });
}

export interface SettledRead { events: NostrEvent[]; answered: string[]; failed: string[] }

/** For read-modify-write: query every relay individually and report which ones reached EOSE.
 * Offline, erroring or silent relays are normal on Nostr, so they are reported, never thrown;
 * callers decide whether the relays that answered are enough.
 * Pool.request hides partial failures, so use individual subscriptions with an absolute
 * EOSE deadline (events do not reset it).
 */
export async function requestEventsSettled(runtime: NostrRuntime, filters: Filter | Filter[], relays = runtime.relays, timeout = 6000): Promise<SettledRead> {
  const targets = normalizeRelays(relays);
  const healthy = new Set(runtime.pool.filterRelays(targets));
  const events: NostrEvent[] = [];
  const results = targets.length ? await firstValueFrom(forkJoin(targets.map((url) => !healthy.has(url) ? of(false) : runtime.pool.relay(url).subscription(filters, { waitForAuth: false }).pipe(
    tap((message) => {
      if (message !== 'EOSE') { runtime.eventStore.add(message); events.push(message); }
    }),
    filter((message) => message === 'EOSE'),
    take(1),
    bound({ first: timeout }),
    map(() => true),
    defaultIfEmpty(false),
    catchError(() => of(false))
  )))) : [];
  return { events, answered: targets.filter((_, i) => results[i]), failed: targets.filter((_, i) => !results[i]) };
}
