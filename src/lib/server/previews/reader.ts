import { kinds } from 'applesauce-core/helpers';
import { FOLLOW_LIST_KIND } from '../../nostr/protocol/kinds';
import { resolvePackLink } from '../../nostr/protocol/pack-link';
import { createNostrRuntime } from '../../nostr/runtime';
import { requestEvents } from '../../nostr/requests';
import { parseFollowListEvent } from '../../nostr/protocol/follow-pack';
import { parseProfile } from '../../nostr/protocol/profile';

/** A separate read-only server runtime; every request closes its sockets and store. */
export async function readPreview(value: string, pubkey: string | undefined, signal: AbortSignal) {
  let location: ReturnType<typeof resolvePackLink>;
  try { location = resolvePackLink(value, pubkey); } catch { return null; }
  const { identifier, pubkey: author } = location;
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} } });
  try {
    const filter = { kinds: [FOLLOW_LIST_KIND], '#d': [identifier], ...(author ? { authors: [author] } : {}) };
    // URL relay hints are untrusted server destinations (including private networks).
    // Preview reads use only configured app relays, without author relay discovery.
    await requestEvents(runtime, [filter, { kinds: [kinds.EventDeletion], '#k': [String(FOLLOW_LIST_KIND)], ...(author ? { authors: [author] } : {}) }], runtime.relays, signal, 4500);
    const events = runtime.eventStore.getTimeline(filter);
    if (events.length !== 1) return null;
    const pack = parseFollowListEvent(events[0]);
    if (!pack) return null;
    const members = pack.entries.slice(0, 6).map((entry) => entry.pubkey);
    if (members.length) {
      try { await requestEvents(runtime, { kinds: [kinds.Metadata], authors: members }, runtime.relays, signal, 2500); } catch { /* Render without unavailable profiles. */ }
    }
    return { pack, pictures: members.flatMap((pubkey) => {
      const event = runtime.eventStore.getReplaceable(kinds.Metadata, pubkey);
      const picture = parseProfile(event).picture;
      return picture ? [picture] : [];
    }) };
  } finally { runtime.dispose(); }
}
