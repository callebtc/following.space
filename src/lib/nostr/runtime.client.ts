import { browser } from '$app/environment';
import { markFromCache, persistEventsToCache } from 'applesauce-core/helpers';
import { merge } from 'rxjs';
import { createNostrRuntime, type NostrRuntime } from './runtime';
import { createAppVerifier } from './verifier';

let runtime: NostrRuntime | undefined;
let initializing: Promise<NostrRuntime> | undefined;
let stopPersistence: (() => void) | undefined;

/** Read the existing browser runtime synchronously without starting cache initialization. */
export function peekNostrRuntime(): NostrRuntime | undefined {
  return browser ? runtime : undefined;
}

/** Import the browser-only cache only after mounting, never during SSR. */
export function getNostrRuntime(): Promise<NostrRuntime> {
  if (!browser) return Promise.reject(new Error('Browser Nostr runtime requested during SSR'));
  if (runtime) return Promise.resolve(runtime);
  return initializing ??= (async () => {
    // Storage can be unavailable (private mode, disabled IndexedDB); relays still work.
    try {
      await import('window.nostrdb.js');
    } catch {
      console.warn('Event cache unavailable; continuing with relay reads');
    }
    const cache = {
      read: async (filters: Parameters<NostrRuntime['cacheRequest']>[0]) => {
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          const events = await Promise.race([
            window.nostrdb.query(filters),
            new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('Cache timed out')), 1000); })
          ]);
          events.forEach(markFromCache);
          return events;
        } catch { return []; }
        finally { clearTimeout(timer); }
      },
      write: async (events: Parameters<NostrRuntime['eventStore']['add']>[0][]) => {
        await Promise.allSettled(events.map((event) => window.nostrdb?.add(event)));
      }
    };
    let storage: Storage | undefined;
    try { storage = window.localStorage; } catch { /* Storage is optional. */ }
    const verifier = createAppVerifier({
      getItem: (key) => { try { return storage?.getItem('following:verification:' + key) ?? null; } catch { return null; } },
      setItem: (key, value) => { try { storage?.setItem('following:verification:' + key, value); } catch { /* Optional evidence storage. */ } }
    });
    runtime = createNostrRuntime({ cache, storage, verifyEvent: verifier.verifyEvent });
    stopPersistence = persistEventsToCache({
      insert$: merge(runtime.eventStore.insert$, runtime.eventStore.deletion$),
      update$: runtime.eventStore.update$,
      remove$: runtime.eventStore.remove$
    }, cache.write);
    return runtime;
  })();
}

if (import.meta.hot) import.meta.hot.dispose(() => {
  stopPersistence?.();
  runtime?.dispose();
  runtime = undefined;
  initializing = undefined;
});
