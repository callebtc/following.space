import { kinds, type NostrEvent } from 'applesauce-core/helpers';

export interface FollowSnapshot {
  timestamp: number; eventId: string; count: number; pubkeys: string[]; event: NostrEvent;
}
export interface StorageLike { getItem(key: string): string | null; setItem(key: string, value: string): void; removeItem(key: string): void }
const LEGACY_KEY = 'nostr-follow-list:snapshots';
const keyFor = (pubkey: string) => `following:v2:snapshots:${pubkey}`;
function storedArray(storage: StorageLike, key: string): unknown[] {
  try { const value = JSON.parse(storage.getItem(key) || '[]'); return Array.isArray(value) ? value : []; }
  catch { return []; }
}

export function readSnapshots(storage: StorageLike, pubkey: string): FollowSnapshot[] {
  try {
    const all = [...storedArray(storage, keyFor(pubkey)), ...storedArray(storage, LEGACY_KEY)] as FollowSnapshot[];
    const ids = new Set<string>();
    const snapshots = all.filter((snapshot) => {
      if (snapshot?.event?.pubkey !== pubkey || snapshot.event.kind !== kinds.Contacts || !Array.isArray(snapshot.pubkeys) ||
          !snapshot.pubkeys.every((p: unknown) => typeof p === 'string' && /^[0-9a-f]{64}$/i.test(p)) || ids.has(snapshot.eventId)) return false;
      ids.add(snapshot.eventId); return true;
    }).sort((a, b) => b.timestamp - a.timestamp).slice(0, 20);
    try { storage.setItem(keyFor(pubkey), JSON.stringify(snapshots)); } catch { /* Reading history must still work at storage quota. */ }
    return snapshots;
  } catch { return []; }
}

export function saveSnapshot(storage: StorageLike, event: NostrEvent) {
  const pubkeys = [...new Set(event.tags.filter((tag) => tag[0] === 'p').map((tag) => tag[1]))];
  const snapshots = readSnapshots(storage, event.pubkey);
  if (snapshots.some((snapshot) => snapshot.pubkeys.length === pubkeys.length && snapshot.pubkeys.every((key) => pubkeys.includes(key)))) return;
  const snapshot: FollowSnapshot = { timestamp: Date.now(), eventId: event.id, count: pubkeys.length, pubkeys, event };
  try { storage.setItem(keyFor(event.pubkey), JSON.stringify([snapshot, ...snapshots].slice(0, 20))); } catch { /* Optional local history. */ }
}
