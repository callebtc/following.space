import type { Filter, NostrEvent } from 'applesauce-core/helpers';
import type { NostrRuntime } from './runtime';
import { filter, firstValueFrom, forkJoin, take, tap, throwIfEmpty, timeout as bound } from 'rxjs';
import { normalizeRelays } from './relay-policy';

/** Best-effort finite read: group completion can include failed or unfinished relays. */
export function requestEvents(runtime: NostrRuntime, filters: Filter | Filter[], relays = runtime.relays, signal?: AbortSignal, timeout = 6000): Promise<NostrEvent[]> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new DOMException('Cancelled', 'AbortError'));
    const targets = runtime.pool.filterRelays(relays);
    if (!targets.length) return reject(new Error('No healthy relays are available. Please retry.'));
    const events: NostrEvent[] = [];
    const sub = runtime.pool.request(targets, filters, { timeout, firstResponseTimeout: timeout, waitForAuth: false }).subscribe({
      next: (event) => { runtime.eventStore.add(event); events.push(event); },
      error: (error) => { signal?.removeEventListener('abort', cancel); reject(error); },
      complete: () => { signal?.removeEventListener('abort', cancel); resolve(events); }
    });
    function cancel() { sub.unsubscribe(); reject(new DOMException('Cancelled', 'AbortError')); }
    if (!sub.closed) signal?.addEventListener('abort', cancel, { once: true });
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
