/** ORE-01 discovery + ORE-05 search, following applesauce's search/open-ranking example.
 * Keep HTTP here so cancellation and 202 Retry-After work throughout the request.
 */
export const OPEN_RANKING_PROVIDER = 'https://ranking.vertexlab.io';
export interface RankedPubkey { pubkey: string; rank: number }
const capabilities = new Map<string, { expires: number; algorithm: string }>();

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function wait(ms: number, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const cancel = () => { clearTimeout(timer); reject(signal.reason); };
    const timer = setTimeout(() => { signal.removeEventListener('abort', cancel); resolve(); }, ms);
    signal.addEventListener('abort', cancel, { once: true });
  });
}

async function checked(response: Response): Promise<Response> {
  if (!response.ok) {
    if (response.status === 401 || response.status === 403)
      throw new Error('Ranking provider requires authorization. Try relay search.');
    throw new Error(response.headers.get('X-Reason') || `Ranking provider failed (${response.status}). Try relay search.`);
  }
  return response;
}

export async function searchRankedPubkeys(query: string, limit: number, signal?: AbortSignal,
  provider = OPEN_RANKING_PROVIDER): Promise<RankedPubkey[]> {
  query = query.trim();
  if (!query) return [];
  if (query.length > 512) throw new Error('Search must be 512 characters or fewer.');
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw new Error('Invalid search limit.');
  provider = provider.replace(/\/+$/, '');
  const controller = new AbortController();
  const cancel = () => controller.abort(signal?.reason);
  signal?.throwIfAborted();
  signal?.addEventListener('abort', cancel, { once: true });
  const timer = setTimeout(() => controller.abort(new Error('Ranking provider timed out. Try relay search.')), 15000);
  const requestSignal = controller.signal;
  try {
    let cached = capabilities.get(provider);
    if (!cached || cached.expires <= Date.now()) {
      const response = await checked(await fetch(`${provider}/.well-known/open-ranking.json`, { signal: requestSignal }));
      const document: unknown = await response.json();
      const algorithms = record(document) ? document['/search/pubkeys'] : undefined;
      const algorithm = Array.isArray(algorithms) && algorithms.find((item: unknown) =>
        record(item) && typeof item.id === 'string' && item.id.length > 0 && (item.pov === undefined || item.pov === false));
      if (!algorithm) throw new Error('Ranking provider has no global user search. Try relay search.');
      cached = { algorithm: algorithm.id, expires: Date.now() + 300000 };
      capabilities.set(provider, cached);
    }
    const body = JSON.stringify({ query, limit, algorithm: cached.algorithm });
    for (let attempt = 0; ; attempt++) {
      const response = await checked(await fetch(`${provider}/search/pubkeys`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body, signal: requestSignal
      }));
      if (response.status === 202) {
        if (attempt >= 2) throw new Error('Ranking results are still being prepared. Please retry.');
        const retry = response.headers.get('Retry-After');
        const delay = retry && /^\d+$/.test(retry) ? Number(retry) * 1000 : retry ? Date.parse(retry) - Date.now() : NaN;
        if (!Number.isFinite(delay)) throw new Error('Ranking provider returned an invalid retry delay.');
        await wait(Math.max(0, delay), requestSignal);
        continue;
      }
      const payload: unknown = await response.json();
      if (!record(payload) || !Array.isArray(payload.results) || payload.results.length > limit ||
        !payload.results.every((item: unknown) => record(item) && typeof item.pubkey === 'string' &&
          /^[0-9a-f]{64}$/i.test(item.pubkey) && typeof item.rank === 'number' && Number.isFinite(item.rank)))
        throw new Error('Ranking provider returned invalid search results.');
      requestSignal.throwIfAborted();
      const seen = new Set<string>();
      return (payload.results as RankedPubkey[]).map((item) => ({ ...item, pubkey: item.pubkey.toLowerCase() }))
        .sort((a, b) => b.rank - a.rank).filter((item) => !seen.has(item.pubkey) && !!seen.add(item.pubkey));
    }
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', cancel);
  }
}
