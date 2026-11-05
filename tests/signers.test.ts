import { afterEach, describe, expect, it } from 'vitest';
import { NostrConnectProvider, NostrConnectSigner, PrivateKeySigner, type NostrPool } from 'applesauce-signers';
import { NostrConnectAccount, ExtensionAccount } from 'applesauce-accounts/accounts';
import { AccountManager } from 'applesauce-accounts';
import { matchFilters, verifyEvent, type NostrEvent } from 'applesauce-core/helpers';
import { filter, ReplaySubject } from 'rxjs';
import { FollowPackFactory } from '../src/lib/features/packs/factory';

const cleanup: (() => Promise<unknown>)[] = [];
afterEach(async () => { for (const stop of cleanup.splice(0)) await stop(); });
function transport(): NostrPool {
  const events = new ReplaySubject<NostrEvent>(100);
  return {
    subscription: (_relays, filters) => events.pipe(filter((event) => matchFilters(filters, event))),
    publish: async (_relays, event) => { queueMicrotask(() => events.next(event)); }
  };
}
function provider(pool: NostrPool) {
  const upstream = new PrivateKeySigner();
  const remote = new NostrConnectProvider({ pool, upstream, relays: ['wss://signer.example'], bunkerSecret: 'pairing-secret', onConnect: () => true, onSignEvent: () => true });
  cleanup.push(() => remote.stop());
  return { upstream, remote };
}
const draft = { id: 'garden', name: 'Garden', coverImageUrl: '', entries: [] };

describe('NIP-46 Applesauce integration', () => {
  it('pairs a bunker, signs packs, and resumes a serialized account without reconnecting', async () => {
    const pool = transport();
    const { upstream, remote } = provider(pool);
    await remote.start();
    const signer = await NostrConnectSigner.fromBunkerURI(await remote.getBunkerURI(), { pool, timeout: 1000, permissions: NostrConnectSigner.buildSigningPermissions([3, 5, 39089]) });
    cleanup.push(() => signer.close());
    const pubkey = await signer.getPublicKey();
    expect(pubkey).toBe(await upstream.getPublicKey());
    const account = new NostrConnectAccount(pubkey, signer);
    const event = await FollowPackFactory.create(draft).sign(account);
    expect(verifyEvent(event)).toBe(true);
    await signer.close();
    // Restoration uses the same pool and client key as production AccountManager restoration.
    NostrConnectSigner.pool = pool;
    const restored = NostrConnectAccount.fromJSON(account.toJSON());
    cleanup.push(() => restored.signer.close());
    const second = await FollowPackFactory.create({ ...draft, name: 'Restored' }).sign(restored);
    expect(second.pubkey).toBe(pubkey);
    expect(verifyEvent(second)).toBe(true);
  });

  it('pairs a nostrconnect QR session and cancels an unpaired session', async () => {
    const pool = transport();
    const { upstream, remote } = provider(pool);
    const signer = new NostrConnectSigner({ pool, relays: ['wss://signer.example'], timeout: 1000 });
    remote.bunkerSecret = undefined; // QR pairing uses the client's connect secret.
    cleanup.push(() => signer.close());
    const uri = signer.getNostrConnectURI({ name: 'following.space', permissions: NostrConnectSigner.buildSigningPermissions([3, 5, 39089]) });
    const waiting = signer.waitForSigner();
    await remote.start(uri);
    await waiting;
    expect(await signer.getPublicKey()).toBe(await upstream.getPublicKey());
    const unpaired = new NostrConnectSigner({ pool: transport(), relays: ['wss://signer.example'], timeout: 1000 });
    cleanup.push(() => unpaired.close());
    const controller = new AbortController();
    const rejected = expect(unpaired.waitForSigner(controller.signal)).rejects.toThrow();
    controller.abort();
    await rejected;
  });

  it('roundtrips extension identity in AccountManager without persisting a signing key', async () => {
    const account = new ExtensionAccount('a'.repeat(64), { getPublicKey: async () => 'a'.repeat(64) } as never);
    const manager = new AccountManager(); manager.registerType(ExtensionAccount);
    manager.addAccount(account); manager.setActive(account);
    const serialized = manager.toJSON();
    const restored = new AccountManager(); restored.registerType(ExtensionAccount); restored.fromJSON(serialized);
    restored.setActive(account.id);
    expect(restored.active?.pubkey).toBe(account.pubkey);
    expect(JSON.stringify(serialized)).not.toContain('clientKey');
  });
});
