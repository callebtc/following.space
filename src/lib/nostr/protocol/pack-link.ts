import { decodePointer, getSeenRelays, kinds, naddrEncode } from 'applesauce-core/helpers';
import { FOLLOW_LIST_KIND, type FollowList } from './follow-pack';
import { eventRelays, normalizeRelays } from '../relay-policy';
import type { NostrRuntime } from '../runtime';

// NIP-19 hints are a small bootstrap, not an unbounded relay directory.
function boundedHints(relays: string[]) {
  return normalizeRelays(relays).filter((relay) => new TextEncoder().encode(relay).length <= 255).slice(0, 3);
}

/** Prefer relays that actually carried the event, then its author's known outboxes. */
export function packRelayHints(runtime: NostrRuntime | undefined, pack: Pick<FollowList, 'pubkey'> & { eventId?: string }, hints: string[] = []) {
  const event = pack.eventId ? runtime?.eventStore.getEvent(pack.eventId) : undefined;
  return boundedHints([
    ...(event ? getSeenRelays(event) ?? [] : []),
    ...eventRelays(runtime?.eventStore.getReplaceable(kinds.RelayList, pack.pubkey), 'write'),
    ...hints
  ]);
}

export interface PackLocation { identifier: string; pubkey?: string; relays: string[] }

/** Decode once at the URL boundary; legacy identifiers remain literal. */
export function resolvePackLink(value: string, author?: string): PackLocation {
  let decoded: ReturnType<typeof decodePointer> | undefined;
  try { decoded = decodePointer(value); } catch { /* Not NIP-19: a legacy d tag. */ }
  if (decoded) {
    if (decoded.type !== 'naddr' || decoded.data.kind !== FOLLOW_LIST_KIND) throw new Error('Invalid pack address');
    return { identifier: decoded.data.identifier, pubkey: decoded.data.pubkey, relays: normalizeRelays(decoded.data.relays ?? []) };
  }
  if (!value || (author && !/^[0-9a-f]{64}$/i.test(author))) throw new Error('Invalid pack address');
  return { identifier: value, pubkey: author?.toLowerCase(), relays: [] };
}

export function packNaddr(pack: Pick<FollowList, 'pubkey' | 'id'>, relays: string[] = []) {
  return naddrEncode({ kind: FOLLOW_LIST_KIND, pubkey: pack.pubkey, identifier: pack.id, relays: boundedHints(relays) });
}
export function packHref(pack: Pick<FollowList, 'pubkey' | 'id'>, relays: string[] = []) {
  return `/d/${packNaddr(pack, relays)}`;
}
