import { expect, it, vi } from 'vitest';
import { from, lastValueFrom, of } from 'rxjs';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { LOOKUP_RELAYS, normalizeRelays } from '../src/lib/nostr/relay-policy';

it('persists validated lookup relays and routes loader requests to changed relays', async () => {
  const values = new Map<string, string>();
  const storage = { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => { values.set(key, value); } };
  const cache = { read: async () => [], write: async () => {} };
  const runtime = createNostrRuntime({ cache, storage, relays: [] });
  expect(runtime.lookupRelays$.value).toEqual(normalizeRelays(LOOKUP_RELAYS));
  const request = vi.spyOn(runtime.pool, 'request').mockReturnValue(of());
  runtime.setLookupRelays(['lookup.example', 'wss://lookup.example/']);
  await lastValueFrom(from(runtime.eventStore.eventLoader!({ kind: 0, pubkey: 'a'.repeat(64) })), { defaultValue: undefined });
  expect(request.mock.calls.some(([relays]) => Array.isArray(relays) && relays.includes('wss://lookup.example/'))).toBe(true);
  runtime.setLookupRelays(['https://lookup.example', 'lookup.example']);
  expect(runtime.lookupRelays$.value).toEqual(['wss://lookup.example/']);
  expect(() => runtime.setLookupRelays(['javascript:alert(1)'])).toThrow('Invalid relay');
  expect(() => runtime.setLookupRelays([])).toThrow('at least one');
  expect(runtime.lookupRelays$.value).toEqual(['wss://lookup.example/']);
  const restored = createNostrRuntime({ cache, storage, relays: [] });
  expect(restored.lookupRelays$.value).toEqual(['wss://lookup.example/']);
  restored.dispose();
  runtime.dispose();
});

it('uses the signed-in account lookup list in loader requests and restores fallback on logout', async () => {
  const { finalizeEvent } = await import('applesauce-core/helpers');
  const { alice } = await import('./fixtures');
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} }, relays: [] });
  expect(runtime.lookupRelays$.value).toEqual(['wss://purplepag.es/', 'wss://relay.vertexlab.io/']);
  const lookup = finalizeEvent({ kind: 10086, created_at: Math.floor(Date.now() / 1000), content: '', tags: [['relay', 'wss://account-lookup.example']] }, alice);
  const request = vi.spyOn(runtime.pool, 'request').mockReturnValue(of());
  runtime.relayPolicy.account$.next({ pubkey: lookup.pubkey, lookup, loading: false });
  runtime.setLookupRelays(['device-lookup.example']);
  await lastValueFrom(from(runtime.eventStore.eventLoader!({ kind: 0, pubkey: 'b'.repeat(64) })), { defaultValue: undefined });
  expect(request.mock.calls.some(([relays]) => Array.isArray(relays) && relays.includes('wss://account-lookup.example/'))).toBe(true);
  expect(request.mock.calls.some(([relays]) => Array.isArray(relays) && relays.includes('wss://device-lookup.example/'))).toBe(false);
  runtime.relayPolicy.account$.next({ loading: false });
  request.mockClear();
  await lastValueFrom(from(runtime.eventStore.eventLoader!({ kind: 0, pubkey: 'c'.repeat(64) })), { defaultValue: undefined });
  expect(request.mock.calls.some(([relays]) => Array.isArray(relays) && relays.includes('wss://device-lookup.example/'))).toBe(true);
  runtime.dispose();
});
