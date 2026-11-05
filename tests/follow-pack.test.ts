import { describe, expect, it } from 'vitest';
import { AppEventStore } from '../src/lib/nostr/event-store';
import { finalizeEvent } from 'applesauce-core/helpers';
import { packAddress, parseFollowListEvent } from '../src/lib/nostr/protocol/follow-pack';
import { selectPacks } from '../src/lib/features/packs/feed';
import { alice, bob, NOW, signedPack } from './fixtures';

describe('legacy pack protocol and identity', () => {
  it('preserves legacy name/description, ordered members and relay hints', () => {
    const member = signedPack({ key: bob }).pubkey;
    const event = signedPack({ content: JSON.stringify({ description: 'Old description' }) });
    event.tags = [['d', 'garden'], ['n', 'Legacy'], ['p', member, 'wss://example.com'], ['p', 'invalid']];
    const pack = parseFollowListEvent(event)!;
    expect(pack.name).toBe('Legacy');
    expect(pack.description).toBe('Old description');
    expect(pack.entries).toEqual([{ pubkey: member, relay: 'wss://example.com' }]);
  });

  it('rejects other kinds and tolerates malformed legacy content', () => {
    const event = signedPack({ content: '{bad' });
    expect(parseFollowListEvent(event)?.description).toBe('');
    expect(parseFollowListEvent({ ...event, kind: 1 })).toBeNull();
    expect(parseFollowListEvent({ ...event, content: '{"description":123}' })?.description).toBe('');
  });

  it('keeps colliding identifiers from different authors and picks latest revisions', () => {
    const old = signedPack({ timestamp: NOW - 1 });
    const latest = signedPack({ title: 'New title' });
    const other = signedPack({ key: bob });
    const result = selectPacks([old, latest, other], { since: 0, until: NOW }, 20);
    expect(result).toHaveLength(2);
    expect(result.find((pack) => pack.pubkey === latest.pubkey)?.name).toBe('New title');
    expect(new Set(result.map(packAddress)).size).toBe(2);
  });

  it('retains distinct events on the same timestamp boundary with deterministic ties', () => {
    const a = signedPack({ identifier: 'a' });
    const b = signedPack({ identifier: 'b' });
    const revision = signedPack({ identifier: 'a', title: 'Alternative' });
    const result = selectPacks([a, b, revision], { since: NOW, until: NOW }, 20);
    expect(result).toHaveLength(2);
    expect(result.find((pack) => pack.id === 'a')?.eventId).toBe([a.id, revision.id].sort()[0]);
  });
});

describe('real EventStore verification and deletion', () => {
  it('rejects invalid signatures and unauthorized deletes; honors address deletion and newer recreation', () => {
    const store = new AppEventStore();
    const event = signedPack();
    expect(store.add(JSON.parse(JSON.stringify({ ...event, sig: '0'.repeat(128) })))).toBeNull();
    store.add(event);
    const tags = [['a', `39089:${event.pubkey}:garden`], ['e', event.id], ['k', '39089']];
    const deletion = finalizeEvent({ kind: 5, created_at: NOW + 1, tags, content: '' }, alice);
    const tombstones: string[] = [];
    store.deletion$.subscribe((event) => tombstones.push(event.id));
    // JSON roundtrip strips verification memo symbols supplied by the fixture signer.
    expect(store.add(JSON.parse(JSON.stringify({ ...deletion, sig: '0'.repeat(128) })))).toBeNull();
    expect(tombstones).toEqual([]);
    expect(store.getEvent(event.id)).toBeDefined();
    store.add(finalizeEvent({ kind: 5, created_at: NOW + 1, tags, content: '' }, bob));
    expect(store.getEvent(event.id)).toBeDefined();
    store.add(finalizeEvent({ kind: 5, created_at: NOW + 1, tags, content: '' }, alice));
    expect(tombstones).toContain(deletion.id);
    expect(store.getTimeline({ kinds: [39089] })).toEqual([]);
    store.add(event);
    expect(store.getTimeline({ kinds: [39089] })).toEqual([]);
    const recreated = signedPack({ timestamp: NOW + 2 });
    store.add(recreated);
    expect(store.getTimeline({ kinds: [39089] }).map((e) => e.id)).toEqual([recreated.id]);
    store.dispose();
  });

  it('does not resurrect cached packs when a fresh runtime hydrates persisted tombstones', () => {
    const event = signedPack();
    const deletion = finalizeEvent({
      kind: 5, created_at: NOW + 1,
      tags: [['a', `39089:${event.pubkey}:garden`], ['k', '39089']], content: ''
    }, alice);
    for (const events of [[event, deletion], [deletion, event]]) {
      const store = new AppEventStore();
      events.forEach((event) => store.add(JSON.parse(JSON.stringify(event))));
      expect(store.getTimeline({ kinds: [39089] })).toEqual([]);
      store.dispose();
    }
  });
});
