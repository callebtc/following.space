import { afterEach, expect, it, vi } from 'vitest';
import { PrivateKeyAccount } from 'applesauce-accounts/accounts';
import { finalizeEvent } from 'applesauce-core/helpers';
import { of } from 'rxjs';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { publishLookupRelays } from '../src/lib/nostr/lookup-relays';
import { alice, NOW } from './fixtures';

const cleanup: (() => void)[] = [];
afterEach(() => cleanup.splice(0).forEach((dispose) => dispose()));
function setup() {
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} }, relays: ['wss://app.example'] });
  const account = PrivateKeyAccount.fromKey(alice);
  runtime.relayPolicy.account$.next({ pubkey: account.pubkey, loading: false });
  runtime.eventStore.add(finalizeEvent({ kind: 10002, created_at: NOW, tags: [], content: '' }, alice));
  vi.spyOn(runtime.pool, 'request').mockReturnValue(of());
  const publish = vi.spyOn(runtime.pool, 'publish').mockResolvedValue([{ from: runtime.relays[0], ok: true }]);
  cleanup.push(() => runtime.dispose());
  return { runtime, account, publish, sign: (draft: Parameters<typeof account.signEvent>[0]) => account.signEvent(draft) };
}

it('creates a signed-in user’s first public lookup list without changing local settings', async () => {
  const { runtime, account, sign, publish } = setup();
  const local = runtime.lookupRelays$.value;
  await publishLookupRelays(runtime, account.pubkey, ['lookup.example'], sign, () => true);
  const event = runtime.eventStore.getReplaceable(10086, account.pubkey)!;
  expect(event.tags).toEqual([['relay', 'wss://lookup.example/']]);
  expect(publish).toHaveBeenCalled();
  expect(runtime.lookupRelays$.value).toEqual(local);
});

it('preserves unrelated data and publishes only the edited relay rows', async () => {
  const { runtime, account, sign, publish } = setup();
  const previous = finalizeEvent({ kind: 10086, created_at: NOW, content: 'preserve', tags: [['client', 'other'], ['relay', 'wss://old.example']] }, alice);
  runtime.eventStore.add(previous);
  await publishLookupRelays(runtime, account.pubkey, ['new.example'], sign, () => true);
  const event = runtime.eventStore.getReplaceable(10086, account.pubkey)!;
  expect(event.tags).toEqual([['client', 'other'], ['relay', 'wss://new.example/']]);
  expect(event.content).toBe('preserve');
  expect(event.created_at).toBeGreaterThan(previous.created_at);
  expect(publish.mock.calls[0][0]).toEqual(expect.arrayContaining(['wss://old.example/', 'wss://new.example/']));
});

it('does not replace the list after failed publishing or an account switch', async () => {
  const { runtime, account, sign, publish } = setup();
  publish.mockResolvedValue([{ from: runtime.relays[0], ok: false }]);
  await expect(publishLookupRelays(runtime, account.pubkey, ['new.example'], sign, () => true)).rejects.toThrow('No relay accepted');
  expect(runtime.eventStore.getReplaceable(10086, account.pubkey)).toBeUndefined();
  publish.mockClear();
  await expect(publishLookupRelays(runtime, account.pubkey, ['new.example'], sign, () => false)).rejects.toThrow('Account changed');
  expect(publish).not.toHaveBeenCalled();
});
