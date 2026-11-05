import { decodeProfilePointer, kinds } from 'applesauce-core/helpers';
import { SEARCH_RELAYS } from '../../nostr/relay-defaults';
import { getNostrRuntime } from '../../nostr/runtime.client';
import { requestEvents } from '../../nostr/requests';
import { accounts } from '../../nostr/accounts';
import { searchRankedPubkeys } from './open-ranking';
import { parseProfile } from '../../nostr/protocol/profile';
export interface UserSearchResult { pubkey: string; relays: string[]; rank: number }
export async function searchUsersByName(query: string, limit = 5, signal?: AbortSignal, source: 'ranking' | 'relay' = 'ranking'): Promise<UserSearchResult[]> {
  query = query.trim();
  if (!query) return [];
  const runtime = await getNostrRuntime();
  const pointer = /^[0-9a-f]{64}$/i.test(query) ? { pubkey: query } : decodeProfilePointer(query.replace(/^nostr:/, ''));
  signal?.throwIfAborted();
  if (!pointer && source === 'ranking') {
    const ranked = await searchRankedPubkeys(query, limit, signal);
    signal?.throwIfAborted();
    if (!ranked.length) return [];
    return ranked.map((result) => ({ ...result, relays: [] }));
  }
  // Identity lookup needs no metadata round trip; the UI observes the profile.
  if (pointer) return [{ pubkey: pointer.pubkey, relays: pointer.relays ?? [], rank: 0 }];
  const filter = { kinds: [kinds.Metadata], search: query, limit: 100 };
  await runtime.hydrate([filter]);
  await requestEvents(runtime, filter, SEARCH_RELAYS, signal);
  signal?.throwIfAborted();
  const following = new Set(runtime.eventStore.getReplaceable(kinds.Contacts, accounts.active?.pubkey ?? '')?.tags.filter((tag) => tag[0] === 'p').map((tag) => tag[1]));
  const results = runtime.eventStore.getTimeline(filter).map((event) => {
    const profile = parseProfile(event);
    return { pubkey: event.pubkey, relays: [], rank: following.has(event.pubkey) ? 1 : 0,
      name: profile.name };
  }).filter((profile) => profile.name?.toLowerCase().includes(query.toLowerCase()));
  return results.sort((a, b) => b.rank - a.rank).slice(0, limit).map(({ name, ...identity }) => identity);
}
