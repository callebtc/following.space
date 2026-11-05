import { castUser } from 'applesauce-common/casts';
import { kinds } from 'applesauce-core/helpers';
import type { NostrRuntime } from './runtime';
import { eventRelays } from './relay-policy';
import { firstValueFrom } from 'rxjs';
import { requestEventsStrict } from './requests';

/** Bound metadata discovery; cached lists resolve immediately. */
export async function loadOutboxRelays(runtime: NostrRuntime, pubkey: string) {
  const cached = runtime.eventStore.getReplaceable(kinds.RelayList, pubkey);
  if (cached) return eventRelays(cached, 'write');
  const hints = await castUser(pubkey, runtime.eventStore).outboxes$.$first(1500, [] as string[]);
  // Use the signed list once discovered. Its URL parser also handles valid long TLDs rejected by SDK hint parsing.
  const discovered = runtime.eventStore.getReplaceable(kinds.RelayList, pubkey);
  return discovered ? eventRelays(discovered, 'write') : hints;
}

/** Contact writes must distinguish absent metadata from a failed or unfinished lookup. */
export async function discoverOutboxRelaysStrict(runtime: NostrRuntime, pubkey: string) {
  const lookup = await firstValueFrom(runtime.relayPolicy.lookupRelays$);
  const cached = runtime.eventStore.getReplaceable(kinds.RelayList, pubkey);
  await requestEventsStrict(runtime, { kinds: [kinds.RelayList], authors: [pubkey] }, [
    ...lookup, ...runtime.relayPolicy.readRelays, ...eventRelays(cached, 'write')
  ]);
  return eventRelays(runtime.eventStore.getReplaceable(kinds.RelayList, pubkey), 'write');
}
