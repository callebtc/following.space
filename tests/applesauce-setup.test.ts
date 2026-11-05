import { afterEach, describe, expect, it, vi } from 'vitest';
import { finalizeEvent, type NostrEvent } from 'applesauce-core/helpers';
import { of } from 'rxjs';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { createAppVerifier } from '../src/lib/nostr/verifier';
import { observeAccountRelays } from '../src/lib/nostr/account-relays';
import { publishSigned } from '../src/lib/nostr/publish';
import { LOOKUP_RELAYS, normalizeRelays } from '../src/lib/nostr/relay-policy';
import { alice, NOW, signedPack } from './fixtures';
const stops: (() => void)[] = [];
afterEach(() => { stops.splice(0).forEach((stop) => stop()); });
const plain = <T>(value: T): T => JSON.parse(JSON.stringify(value));
const mailboxes = () => finalizeEvent({ kind: 10002, created_at: NOW, content: '', tags: [
  ['r', 'wss://inbox.example', 'read'], ['r', 'wss://outbox.example', 'write'], ['r', 'wss://both.example']
] }, alice);
function setup() {
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} }, relays: ['wss://app.example'] });
  stops.push(() => runtime.dispose()); return runtime;
}

describe('relay-policy roles', () => {
  it('separates read/lookup/write roles and resets published relay preferences on logout', () => {
    const runtime = setup(); const reads: string[][] = []; const lookups: string[][] = [];
    const a = runtime.relayPolicy.readRelays$.subscribe((value) => reads.push(value));
    const b = runtime.relayPolicy.lookupRelays$.subscribe((value) => lookups.push(value));
    stops.push(() => { a.unsubscribe(); b.unsubscribe(); });
    runtime.relayPolicy.account$.next({ loading: false, pubkey: signedPack().pubkey, mailboxes: mailboxes(),
      lookup: finalizeEvent({ kind: 10086, created_at: NOW, content: '', tags: [['relay', 'wss://lookup.example'], ['relay', 'https://invalid.example']] }, alice) });
    expect(reads.at(-1)).toEqual(normalizeRelays(['wss://app.example', 'wss://inbox.example', 'wss://both.example']));
    expect(lookups.at(-1)).toEqual(['wss://lookup.example/']);
    runtime.setLookupRelays(['local.example']);
    runtime.relayPolicy.account$.next({ loading: false });
    expect(reads.at(-1)).toEqual(['wss://app.example/']);
    expect(lookups.at(-1)).toEqual(['wss://local.example/']);
  });
  it('hydrates relay lists and bootstraps discovery through both mailboxes and local lookup settings', async () => {
    const boxes = mailboxes();
    const runtime = createNostrRuntime({ cache: { read: async () => [boxes], write: async () => {} }, relays: ['wss://app.example'] });
    stops.push(() => runtime.dispose());
    runtime.setLookupRelays(['local.example']);
    const request = vi.spyOn(runtime.pool, 'request').mockReturnValue(of());
    const sub = observeAccountRelays(runtime, boxes.pubkey).subscribe(); stops.push(() => sub.unsubscribe());
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(runtime.relayPolicy.account$.value.mailboxes?.id).toBe(boxes.id);
    expect(request.mock.calls.some(([relays]) => Array.isArray(relays) && ['wss://local.example/', 'wss://inbox.example/', 'wss://outbox.example/'].every((relay) => relays.includes(relay)))).toBe(true);
    sub.unsubscribe(); expect(runtime.relayPolicy.account$.value.pubkey).toBeUndefined();
  });
  it('discovers missing outboxes before publication and never publishes to read-only inboxes', async () => {
    const runtime = setup(); const boxes = mailboxes();
    vi.spyOn(runtime.pool, 'request').mockReturnValue(of(boxes));
    const publish = vi.spyOn(runtime.pool, 'publish').mockResolvedValue([{ from: 'wss://app.example/', ok: true }]);
    await publishSigned(runtime, signedPack());
    expect(publish.mock.calls[0][0]).toEqual(normalizeRelays(['wss://app.example', 'wss://outbox.example', 'wss://both.example']));
  });
});

describe('WASM verification setup', () => {
  it('keeps JS verification active before initialization and after an initialization failure', async () => {
    let reject!: (error: Error) => void;
    const verifier = createAppVerifier(undefined, () => new Promise((_resolve, fail) => { reject = fail; }));
    const event = plain(signedPack());
    expect(verifier.verifyEvent(event)).toBe(true);
    expect(verifier.verifyEvent(plain({ ...event, sig: '0'.repeat(128) }))).toBe(false);
    reject(new Error('WASM unavailable')); expect(await verifier.ready).toBe(false);
    expect(verifier.verifyEvent(plain({ ...event, sig: '0'.repeat(128) }))).toBe(false);
  });
  it('uses actual WASM for every critical kind and rejects invalid signatures/id hashes', async () => {
    const verifier = createAppVerifier(); expect(await verifier.ready).toBe(true);
    for (const kind of [0, 3, 5, 10002, 10063, 10086, 24242, 39089]) {
      const event = plain(finalizeEvent({ kind, tags: [], content: '', created_at: NOW }, alice));
      expect(verifier.verifyEvent(event)).toBe(true);
      expect(verifier.verifyEvent(plain({ ...event, sig: '0'.repeat(128) }))).toBe(false);
      expect(verifier.verifyEvent(plain({ ...event, content: 'tampered' }))).toBe(false);
    }
  });
  it('applies the configured verifier to the EventStore deletion fast path', () => {
    const check = vi.fn((_event: NostrEvent) => false);
    const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} }, verifyEvent: check });
    stops.push(() => runtime.dispose());
    const deletion = finalizeEvent({ kind: 5, tags: [], content: '', created_at: NOW }, alice);
    expect(runtime.eventStore.add(deletion)).toBeNull(); expect(check).toHaveBeenCalledWith(deletion);
  });
});
