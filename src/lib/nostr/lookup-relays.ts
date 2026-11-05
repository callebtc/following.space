import { ensureWebSocketURL, type EventTemplate, type NostrEvent } from 'applesauce-core/helpers';
import type { NostrRuntime } from './runtime';
import { eventRelays, normalizeRelays } from './relay-policy';
import { publishSigned } from './publish';
import { LOOKUP_RELAY_LIST_KIND } from './protocol/kinds';

export function normalizeLookupRelays(values: string[]): string[] {
  const relays = values.map((value) => {
    try {
      const [relay] = normalizeRelays([ensureWebSocketURL(value.trim())]);
      if (relay && value.trim()) return relay;
    } catch { /* Report invalid input below. */ }
    throw new Error(`Invalid relay URL: ${value}`);
  });
  if (!relays.length) throw new Error('Keep at least one lookup relay.');
  return [...new Set(relays)];
}

/** Signed-in edits always publish kind 10086, including a user's first list. */
export async function publishLookupRelays(
  runtime: NostrRuntime, pubkey: string, values: string[],
  sign: (event: EventTemplate) => Promise<NostrEvent>, isCurrent: () => boolean
) {
  const relays = normalizeLookupRelays(values);
  const state = runtime.relayPolicy.account$.value;
  if (!isCurrent() || state.pubkey !== pubkey) throw new Error('Account changed. Please retry.');
  if (state.loading) throw new Error('Your relay list is still loading.');
  const previous = runtime.eventStore.getReplaceable(LOOKUP_RELAY_LIST_KIND, pubkey);
  const signed = await sign({
    kind: LOOKUP_RELAY_LIST_KIND,
    created_at: Math.max(Math.floor(Date.now() / 1000), (previous?.created_at ?? 0) + 1),
    content: previous?.content ?? '',
    tags: [...(previous?.tags ?? []).filter((tag) => tag[0] !== 'relay'), ...relays.map((relay) => ['relay', relay])]
  });
  if (!isCurrent() || signed.pubkey !== pubkey || runtime.eventStore.getReplaceable(LOOKUP_RELAY_LIST_KIND, pubkey)?.id !== previous?.id)
    throw new Error('Account or relay list changed. Please retry.');
  await publishSigned(runtime, signed, [...eventRelays(previous), ...relays]);
  return relays;
}
