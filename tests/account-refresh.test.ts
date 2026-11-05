import { expect, it } from 'vitest';
import { accountRefreshFailed } from '../src/lib/nostr/account-refresh';

const relay = (state: string, count = 0) => ({ state, count });
it('stays silent when any relay responds, including an empty response', () => {
  expect(accountRefreshFailed({ done: true, loaded: 0, relays: { a: relay('error'), b: relay('complete') } })).toBe(false);
  expect(accountRefreshFailed({ done: true, loaded: 1, relays: { a: relay('error', 1), b: relay('error') } })).toBe(false);
});
it('warns only after every relay fails or is unavailable', () => {
  const relays = { a: relay('error'), b: relay('skipped') };
  expect(accountRefreshFailed({ done: false, loaded: 0, relays })).toBe(false);
  expect(accountRefreshFailed({ done: true, loaded: 0, relays })).toBe(true);
  expect(accountRefreshFailed({ done: true, loaded: 0, relays: {} })).toBe(true);
});
