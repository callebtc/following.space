import { expect, it } from 'vitest';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { APP_RELAYS, normalizeRelays } from '../src/lib/nostr/relay-policy';

const cache = { read: async () => [], write: async () => {} };

it('persists app relay edits across login, logout and runtime restarts', () => {
  const values = new Map<string, string>();
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); }
  };
  const runtime = createNostrRuntime({ cache, storage });
  const reads: string[][] = [];
  const subscription = runtime.relayPolicy.readRelays$.subscribe((relays) => reads.push(relays));
  expect(runtime.relays).toEqual(normalizeRelays(APP_RELAYS));
  runtime.setAppRelays(['packs.example', 'wss://packs.example/']);
  expect(reads.at(-1)).toEqual(['wss://packs.example/']);
  runtime.relayPolicy.account$.next({ pubkey: 'a'.repeat(64), loading: false });
  runtime.setAppRelays(['other.example']);
  expect(reads.at(-1)).toEqual(['wss://other.example/']);
  runtime.relayPolicy.account$.next({ loading: false });
  expect(runtime.relays).toEqual(['wss://other.example/']);
  expect(() => runtime.setAppRelays([])).toThrow('at least one app relay');
  expect(() => runtime.setAppRelays(['javascript:alert(1)'])).toThrow('Invalid relay');
  expect(runtime.relays).toEqual(['wss://other.example/']);
  const restored = createNostrRuntime({ cache, storage });
  expect(restored.relays).toEqual(['wss://other.example/']);
  restored.setAppRelays(APP_RELAYS);
  expect(restored.relays).toEqual(normalizeRelays(APP_RELAYS));
  subscription.unsubscribe();
  restored.dispose();
  runtime.dispose();
});

it('falls back to defaults for invalid saved app relays', () => {
  const storage = { getItem: () => '["javascript:alert(1)"]', setItem: () => {} };
  const runtime = createNostrRuntime({ cache, storage });
  expect(runtime.relays).toEqual(normalizeRelays(APP_RELAYS));
  runtime.dispose();
});
