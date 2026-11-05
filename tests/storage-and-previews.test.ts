import { packHref } from '../src/lib/nostr/protocol/pack-link';
import { describe, expect, it } from 'vitest';
import { finalizeEvent } from 'applesauce-core/helpers';
import { readSnapshots, saveSnapshot } from '../src/lib/features/contacts/snapshots';
import { previewKey, previewMeta } from '../src/lib/server/previews/metadata';
import { parseFollowListEvent } from '../src/lib/nostr/protocol/follow-pack';
import { alice, bob, NOW, signedPack } from './fixtures';
function memoryStorage() {
  const data = new Map<string, string>();
  return { getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => { data.set(key, value); }, removeItem: (key: string) => { data.delete(key); } };
}
describe('snapshot migration and isolation', () => {
  it('migrates only the active author and keeps other authors history available', () => {
    const storage = memoryStorage();
    const event = finalizeEvent({ kind: 3, created_at: NOW, content: '', tags: [['p', 'a'.repeat(64)]] }, alice);
    const other = finalizeEvent({ kind: 3, created_at: NOW, content: '', tags: [] }, bob);
    storage.setItem('nostr-follow-list:snapshots', JSON.stringify([event, other].map((event) => ({ event, eventId: event.id, timestamp: NOW, pubkeys: event.tags.map((t) => t[1]), count: event.tags.length }))));
    expect(readSnapshots(storage, event.pubkey).map((s) => s.eventId)).toEqual([event.id]);
    expect(readSnapshots(storage, other.pubkey).map((s) => s.eventId)).toEqual([other.id]);
    storage.setItem('unrelated', 'preserved');
    saveSnapshot(storage, event);
    expect(readSnapshots(storage, event.pubkey)).toHaveLength(1);
    expect(storage.getItem('unrelated')).toBe('preserved');
  });
});
describe('preview identity and escaping', () => {
  it('uses author and revision to separate colliding identifiers', () => {
    const a = parseFollowListEvent(signedPack())!;
    const b = parseFollowListEvent(signedPack({ key: bob }))!;
    const revision = parseFollowListEvent(signedPack({ title: 'Changed' }))!;
    expect(new Set([previewKey(a), previewKey(b), previewKey(revision)]).size).toBe(3);
  });
  it('escapes content before inserting metadata into HTML', () => {
    const pack = parseFollowListEvent(signedPack({ title: '\"><script>alert(1)</script>' }))!;
    const meta = previewMeta(pack, 'https://example.com', '/farm.png');
    expect(meta).not.toContain('<script>');
    expect(meta).toContain('&quot;&gt;&lt;script&gt;');
    expect(meta).toContain(packHref(pack));
  });
});
