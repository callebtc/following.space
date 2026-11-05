import type { Filter, NostrEvent } from 'applesauce-core/helpers';
import type { NostrRuntime } from './runtime';
import { filter, firstValueFrom, forkJoin, take, tap, throwIfEmpty, timeout as bound, defer, toArray, race, fromEvent, mergeMap, throwError } from 'rxjs';
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

/** For read-modify-write: every intended relay must explicitly reach EOSE.
 * Pool.request hides partial failures and can finish on idle before all relays answer.
 * Use individual subscriptions instead, with an absolute EOSE deadline (events do not reset it).
 */
export async function requestEventsStrict(runtime: NostrRuntime, filters: Filter | Filter[], relays = runtime.relays, timeout = 6000): Promise<NostrEvent[]> {
  const targets = normalizeRelays(relays);
  const healthy = new Set(runtime.pool.filterRelays(targets));
  if (!targets.length || targets.some((url) => !healthy.has(url))) {
    throw new Error('Contact refresh requires all relays to be available. Please retry.');
  }
  const events: NostrEvent[] = [];
  await firstValueFrom(forkJoin(targets.map((url) => runtime.pool.relay(url).subscription(filters, { waitForAuth: false }).pipe(
    tap((message) => {
      if (message !== 'EOSE') { runtime.eventStore.add(message); events.push(message); }
    }),
    filter((message) => message === 'EOSE'),
    take(1),
    bound({ first: timeout }),
    throwIfEmpty(() => new Error(`Relay ${url} closed before EOSE; please retry.`))
  ))));
  return events;
}
