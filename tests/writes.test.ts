import { afterEach, describe, expect, it, vi } from 'vitest';
import { PrivateKeyAccount } from 'applesauce-accounts/accounts';
import { finalizeEvent, type NostrEvent } from 'applesauce-core/helpers';
import { of, throwError } from 'rxjs';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { FollowPackFactory, packDeletion } from '../src/lib/features/packs/factory';
import { updateContacts } from '../src/lib/features/contacts/commands';
import { publishSigned } from '../src/lib/nostr/publish';
import { alice, bob, NOW, signedPack } from './fixtures';
const cleanup: (() => void)[] = [];
afterEach(() => cleanup.splice(0).forEach((fn) => fn()));
function setup() {
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} }, relays: ['wss://relay.example.com'] });
  const account = PrivateKeyAccount.fromKey(alice);
  runtime.eventStore.add(finalizeEvent({ kind: 10002, created_at: NOW, tags: [], content: '' }, alice));
  vi.spyOn(runtime.pool, 'request').mockReturnValue(of());
  const network = vi.fn(() => of<NostrEvent | 'EOSE'>('EOSE'));
  runtime.pool.add$.subscribe((relay) => vi.spyOn(relay, 'subscription').mockImplementation(network));
  const publish = vi.spyOn(runtime.pool, 'publish').mockResolvedValue([{ from: runtime.relays[0], ok: true }]);
  cleanup.push(() => runtime.dispose());
  return { runtime, account, publish, network };
}

describe('pack writes', () => {
  it('preserves kind, identifier, member order and unknown tags on edits', async () => {
    const previous = signedPack({ tags: [['client', 'legacy'], ['p', signedPack({ key: bob }).pubkey]] });
    const event = await FollowPackFactory.create({ id: 'garden', name: 'New', coverImageUrl: '', description: 'Desc', entries: [{ pubkey: previous.pubkey, relay: 'wss://hint.example' }] }, previous).sign(PrivateKeyAccount.fromKey(alice));
    expect(event.kind).toBe(39089);
    expect(event.tags).toContainEqual(['d', 'garden']);
    expect(event.tags).toContainEqual(['client', 'legacy']);
    expect(event.tags.filter((tag) => tag[0] === 'p')).toEqual([['p', previous.pubkey, 'wss://hint.example']]);
  });
  it('deletes the address using d, never the revision id', async () => {
    const pack = signedPack();
    const event = await packDeletion(pack).sign(PrivateKeyAccount.fromKey(alice));
    expect(event.kind).toBe(5);
    expect(event.tags).toContainEqual(['a', `39089:${pack.pubkey}:garden`]);
    expect(event.tags).toContainEqual(['e', pack.id]);
  });
  it('does not insert failed publications; accepts partial publication', async () => {
    const { runtime, publish } = setup();
    const event = signedPack();
    publish.mockResolvedValueOnce([{ from: 'wss://relay.example.com', ok: false, message: 'blocked' }]);
    await expect(publishSigned(runtime, event)).rejects.toThrow('No relay accepted');
    expect(runtime.eventStore.getEvent(event.id)).toBeUndefined();
    publish.mockResolvedValueOnce([{ from: 'wss://relay.example.com', ok: true }, { from: 'wss://other.example.com', ok: false }]);
    await publishSigned(runtime, event);
    expect(runtime.eventStore.getEvent(event.id)).toBeDefined();
  });
});

describe('contact transactions', () => {
  it('signs a bulk update once and preserves legacy content, petnames and unknown tags', async () => {
    const { runtime, account, publish } = setup();
    const friend = signedPack({ key: bob }).pubkey;
    const previous = finalizeEvent({ kind: 3, created_at: NOW, content: '{"legacy":"relay map"}', tags: [['p', friend, 'wss://hint', 'Friend'], ['custom', 'keep']] }, alice);
    runtime.eventStore.add(previous);
    const sign = vi.spyOn(account, 'signEvent');
    const snapshots: NostrEvent[] = [];
    const event = await updateContacts(runtime, account, { add: [friend, 'c'.repeat(64), 'd'.repeat(64)] }, () => true, (event) => snapshots.push(event));
    expect(sign).toHaveBeenCalledTimes(1);
    expect(publish).toHaveBeenCalledTimes(1);
    expect(event.content).toBe(previous.content);
    expect(event.tags).toContainEqual(['p', friend, 'wss://hint', 'Friend']);
    expect(event.tags).toContainEqual(['custom', 'keep']);
    expect(event.tags.filter((t) => t[0] === 'p')).toHaveLength(3);
    expect(event.created_at).toBeGreaterThan(previous.created_at);
    expect(snapshots.map((e) => e.id)).toEqual([previous.id, event.id]);
  });
  it('does not replace unknown contacts after a failed refresh', async () => {
    const { runtime, account, publish, network } = setup();
    network.mockReturnValue(throwError(() => new Error('offline')));
    await expect(updateContacts(runtime, account, { add: ['a'.repeat(64)] }, () => true, () => {})).rejects.toThrow('could not be found');
    expect(publish).not.toHaveBeenCalled();
  });
  it('serializes concurrent updates so the second builds on the first', async () => {
    const { runtime, account } = setup();
    await Promise.all([
      updateContacts(runtime, account, { add: ['a'.repeat(64)] }, () => true, () => {}),
      updateContacts(runtime, account, { add: ['b'.repeat(64)] }, () => true, () => {})
    ]);
    const current = runtime.eventStore.getReplaceable(3, account.pubkey)!;
    expect(current.tags.filter((t) => t[0] === 'p').map((t) => t[1]).sort()).toEqual(['a'.repeat(64), 'b'.repeat(64)]);
  });
  it('rejects account changes before signing or publishing', async () => {
    const { runtime, account, publish } = setup();
    await expect(updateContacts(runtime, account, { replace: [] }, () => false, () => {})).rejects.toThrow('Account changed');
    expect(publish).not.toHaveBeenCalled();
  });
});
