import { castUser } from 'applesauce-common/casts';
import { kinds } from 'applesauce-core/helpers';
import type { NostrRuntime } from './runtime';
import { eventRelays } from './relay-policy';
import { firstValueFrom, map, filter, distinctUntilChanged, timeout } from 'rxjs';
import { requestEventsStrict } from './requests';

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

/** Contact writes must distinguish absent metadata from a failed or unfinished lookup. */
export async function discoverOutboxRelaysStrict(runtime: NostrRuntime, pubkey: string) {
  const lookup = await firstValueFrom(runtime.relayPolicy.lookupRelays$.pipe(timeout({ first: 6000 })));
  const cached = runtime.eventStore.getReplaceable(kinds.RelayList, pubkey);
  await requestEventsStrict(runtime, { kinds: [kinds.RelayList], authors: [pubkey] }, [
    ...lookup, ...runtime.relayPolicy.readRelays, ...eventRelays(cached, 'write')
  ]);
  return eventRelays(runtime.eventStore.getReplaceable(kinds.RelayList, pubkey), 'write');
}
