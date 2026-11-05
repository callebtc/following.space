import { expect, it, vi, afterEach } from 'vitest';
import { BehaviorSubject } from 'rxjs';
vi.mock('applesauce-common/casts', () => ({ castUser: vi.fn() }));
vi.mock('../src/lib/nostr/publish', () => ({ publishSigned: vi.fn() }));
import { castUser } from 'applesauce-common/casts';
import { publishSigned } from '../src/lib/nostr/publish';
import { loadBlossomServers, observeResolvedBlossomServers, publishBlossomServers } from '../src/lib/features/media/servers';
import { DEFAULT_BLOSSOM_SERVERS } from '../src/lib/features/media/blossom';
import type { NostrRuntime } from '../src/lib/nostr/runtime';
const pubkey = 'a'.repeat(64);
function setup(value: URL[] | undefined, previous?: any) {
  const servers = new BehaviorSubject(value);
  vi.mocked(castUser).mockReturnValue({ blossomServers$: servers } as any);
  const runtime = { hydrate: vi.fn().mockResolvedValue(0), eventStore: { getReplaceable: vi.fn().mockReturnValue(previous) } } as unknown as NostrRuntime;
  return { runtime, servers };
}
afterEach(() => { vi.useRealTimers(); vi.clearAllMocks(); });
it('keeps observing after default fallback and preserves a late explicit empty list', async () => {
  vi.useFakeTimers();
  const { runtime, servers } = setup(undefined);
  const values: string[][] = [];
  const sub = observeResolvedBlossomServers(runtime, pubkey).subscribe((value) => values.push(value));
  await vi.advanceTimersByTimeAsync(4001);
  expect(values).toEqual([DEFAULT_BLOSSOM_SERVERS]);
  servers.next([]);
  expect(values.at(-1)).toEqual([]);
  sub.unsubscribe();
  expect(servers.observed).toBe(false);
});
it('prefers the account cast list, preserving order and explicit empty lists', async () => {
  const { runtime, servers } = setup([new URL('https://personal.example'), new URL('https://backup.example')]);
  expect(await loadBlossomServers(runtime, pubkey)).toEqual(['https://personal.example/', 'https://backup.example/']);
  expect(castUser).toHaveBeenCalledWith(pubkey, runtime.eventStore);
  expect(runtime.hydrate).toHaveBeenCalledWith([{ kinds: [10063], authors: [pubkey] }]);
  servers.next([]);
  expect(await loadBlossomServers(runtime, pubkey)).toEqual([]);
});
it('waits for discovery before falling back to defaults', async () => {
  vi.useFakeTimers();
  const { runtime } = setup(undefined);
  const pending = loadBlossomServers(runtime, pubkey);
  await vi.advanceTimersByTimeAsync(4001);
  expect(await pending).toEqual(DEFAULT_BLOSSOM_SERVERS);
});
it('falls back to a cached list, not defaults, when the cast stalls', async () => {
  vi.useFakeTimers();
  const { runtime } = setup(undefined, { kind: 10063, pubkey, created_at: 1, content: '', tags: [['server', 'https://cached.example/']] });
  const pending = loadBlossomServers(runtime, pubkey);
  await vi.advanceTimersByTimeAsync(4001);
  expect(await pending).toEqual(['https://cached.example/']);
});
it('publishes a normalized BUD-03 replacement while preserving other tags', async () => {
  const { runtime } = setup([new URL('https://old.example')], { created_at: 9999999999, content: '', tags: [['server', 'https://old.example/'], ['custom', 'keep']] });
  const signer = vi.fn(async (draft) => ({ ...draft, pubkey, id: 'id', sig: 'sig' }));
  expect(await publishBlossomServers(runtime, pubkey, ['media.example'], signer, () => true)).toEqual(['http://media.example/']);
  expect(signer).toHaveBeenCalledWith({ kind: 10063, content: '', created_at: 10000000000, tags: [['custom', 'keep'], ['server', 'http://media.example/']] });
  expect(publishSigned).toHaveBeenCalledWith(runtime, expect.objectContaining({ pubkey, kind: 10063 }));
});
it('does not sign or publish after an account change', async () => {
  const { runtime } = setup([]);
  const signer = vi.fn();
  await expect(publishBlossomServers(runtime, pubkey, ['media.example'], signer, () => false)).rejects.toThrow('Account changed');
  expect(signer).not.toHaveBeenCalled();
  expect(publishSigned).not.toHaveBeenCalled();
});
