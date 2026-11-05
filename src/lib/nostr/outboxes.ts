import { castUser } from 'applesauce-common/casts';
import { kinds } from 'applesauce-core/helpers';
import type { NostrRuntime } from './runtime';
import { eventRelays } from './relay-policy';
import { firstValueFrom, map, filter, distinctUntilChanged, timeout } from 'rxjs';
import { requestEventsSettled } from './requests';

/** Cast-driven discovery stays subscribed for late metadata and subsequent changes. */
export function observeOutboxRelays(runtime: NostrRuntime, pubkey: string) {
  return castUser(pubkey, runtime.eventStore).outboxes$.pipe(
    // Preserve valid long TLDs rejected by the SDK hint parser.
    map((hints) => {
      const event = runtime.eventStore.getReplaceable(kinds.RelayList, pubkey);
      return event ? eventRelays(event, 'write') : hints;
    }),
    filter((value): value is string[] => value !== undefined),
    distinctUntilChanged((a, b) => a.join('\n') === b.join('\n'))
  );
}

/** Best-effort outbox discovery for contact writes: tolerates dead relays, but reports
 * whether every discovery relay answered so callers can tell absence from an unfinished lookup. */
export async function discoverOutboxRelaysSettled(runtime: NostrRuntime, pubkey: string) {
  const lookup = await firstValueFrom(runtime.relayPolicy.lookupRelays$.pipe(timeout({ first: 6000 })));
  const cached = runtime.eventStore.getReplaceable(kinds.RelayList, pubkey);
  const read = await requestEventsSettled(runtime, { kinds: [kinds.RelayList], authors: [pubkey] }, [
    ...lookup, ...runtime.relayPolicy.readRelays, ...eventRelays(cached, 'write')
  ]);
  return { outboxes: eventRelays(runtime.eventStore.getReplaceable(kinds.RelayList, pubkey), 'write'), complete: !read.failed.length };
}
