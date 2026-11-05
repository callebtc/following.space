import { afterEach, describe, expect, it, vi } from 'vitest';
import { searchRankedPubkeys } from '../src/lib/features/profiles/open-ranking';

const a = 'a'.repeat(64), b = 'b'.repeat(64);
const discovery = () => Response.json({ '/search/pubkeys': [{ id: 'personal', pov: true }, { id: 'global' }] });
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe('Open Ranking search', () => {
  it('discovers a global algorithm and preserves scores without duplicate pubkeys', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(discovery()).mockResolvedValueOnce(Response.json({
      results: [{ pubkey: a, rank: 1 }, { pubkey: b, rank: 3 }, { pubkey: b, rank: 2 }]
    }));
    vi.stubGlobal('fetch', fetcher);
    expect(await searchRankedPubkeys(' jack ', 10, undefined, 'https://rank.example/one')).toEqual([
      { pubkey: b, rank: 3 }, { pubkey: a, rank: 1 }
    ]);
    expect(JSON.parse(fetcher.mock.calls[1][1].body)).toEqual({ query: 'jack', limit: 10, algorithm: 'global' });
    expect(fetcher.mock.calls[1][1].headers.Authorization).toBeUndefined();
  });
  it('retries an identical request after 202', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(discovery())
      .mockResolvedValueOnce(new Response(null, { status: 202, headers: { 'Retry-After': '0' } }))
      .mockResolvedValueOnce(Response.json({ results: [] }));
    vi.stubGlobal('fetch', fetcher);
    expect(await searchRankedPubkeys('jack', 10, undefined, 'https://rank.example/retry')).toEqual([]);
    expect(fetcher.mock.calls[1][1].body).toBe(fetcher.mock.calls[2][1].body);
  });
  it('cancels while waiting for delayed results', async () => {
    const controller = new AbortController();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(discovery()).mockImplementationOnce(() => {
      setTimeout(() => controller.abort(), 0);
      return Promise.resolve(new Response(null, { status: 202, headers: { 'Retry-After': '60' } }));
    }));
    await expect(searchRankedPubkeys('jack', 10, controller.signal, 'https://rank.example/cancel')).rejects.toMatchObject({ name: 'AbortError' });
  });
  it('reports authorization requirements instead of empty results', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(discovery()).mockResolvedValueOnce(new Response(null, { status: 401 })));
    await expect(searchRankedPubkeys('jack', 10, undefined, 'https://rank.example/auth')).rejects.toThrow('requires authorization');
  });
  it('rejects malformed pubkeys', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(discovery()).mockResolvedValueOnce(Response.json({ results: [{ pubkey: 'invalid', rank: 1 }] })));
    await expect(searchRankedPubkeys('jack', 10, undefined, 'https://rank.example/invalid')).rejects.toThrow('invalid search results');
  });
});
