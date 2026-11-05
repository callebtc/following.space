import { afterEach, expect, it, vi } from 'vitest';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { npubEncode, finalizeEvent } from 'applesauce-core/helpers';
import { Subject } from 'rxjs';
import { alice } from './fixtures';

const mocks = vi.hoisted(() => ({ runtime: vi.fn(), request: vi.fn(), ranked: vi.fn() }));
vi.mock('../src/lib/nostr/runtime.client', () => ({ getNostrRuntime: mocks.runtime }));
vi.mock('../src/lib/nostr/requests', async (original) => ({ ...await original<typeof import('../src/lib/nostr/requests')>(), requestEvents: mocks.request }));
vi.mock('../src/lib/features/profiles/open-ranking', () => ({ searchRankedPubkeys: mocks.ranked }));
import { searchUsersByName, observeUserSearch, type UserSearchState } from '../src/lib/features/profiles/user-search';
const pubkey = 'a'.repeat(64);
afterEach(() => vi.resetAllMocks());

it('streams relay matches before EOSE and tears down an unfinished search', async () => {
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} } });
  mocks.runtime.mockResolvedValue(runtime);
  const responses = new Subject<ReturnType<typeof finalizeEvent>>();
  vi.spyOn(runtime.pool, 'request').mockReturnValue(responses);
  const states: UserSearchState[] = [];
  const sub = observeUserSearch('alice', 5, 'relay').subscribe((state) => states.push(state));
  try {
    await vi.waitFor(() => expect(responses.observed).toBe(true));
    const profile = finalizeEvent({ kind: 0, created_at: 1, tags: [], content: JSON.stringify({ name: 'alice' }) }, alice);
    responses.next(profile);
    expect(states.at(-1)).toMatchObject({ loading: true, results: [{ pubkey: profile.pubkey }] });
    sub.unsubscribe();
    expect(responses.observed).toBe(false);
    const count = states.length;
    runtime.eventStore.add(finalizeEvent({ kind: 0, created_at: 2, tags: [], content: JSON.stringify({ name: 'alice updated' }) }, alice));
    expect(states).toHaveLength(count);
  } finally { sub.unsubscribe(); runtime.dispose(); }
});

it('keeps ranked users selectable when profile relays fail', async () => {
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} } });
  mocks.runtime.mockResolvedValue(runtime);
  mocks.ranked.mockResolvedValue([{ pubkey, rank: 42 }]);
  mocks.request.mockRejectedValue(new Error('relay unavailable'));
  try {
    expect(await searchUsersByName('alice')).toEqual([{ pubkey, rank: 42, relays: [] }]);
    expect(mocks.request).not.toHaveBeenCalled();
  } finally { runtime.dispose(); }
});

it('looks up npubs directly without contacting the ranking provider', async () => {
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} } });
  mocks.runtime.mockResolvedValue(runtime);
  mocks.request.mockResolvedValue([]);
  try {
    expect((await searchUsersByName(npubEncode(pubkey)))[0].pubkey).toBe(pubkey);
    expect(mocks.ranked).not.toHaveBeenCalled();
  } finally { runtime.dispose(); }
});
