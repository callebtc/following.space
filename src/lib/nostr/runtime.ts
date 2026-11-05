import { BehaviorSubject, ReplaySubject } from 'rxjs';
import type { Filter, NostrEvent } from 'applesauce-core/helpers';
import { createEventLoaderForStore, createSyncLoader } from 'applesauce-loaders/loaders';
import { RelayLiveness, RelayPool } from 'applesauce-relay';
import { APP_RELAYS, LOOKUP_RELAYS, normalizeRelays, createRelayPolicy } from './relay-policy';
import { normalizeLookupRelays } from './lookup-relays';
import { AppEventStore } from './event-store';

const APP_RELAYS_STORAGE_KEY = 'following.space.app-relays';
const LOOKUP_RELAYS_STORAGE_KEY = 'following.space.lookup-relays';

export interface EventCache {
  read(filters: Filter[]): Promise<NostrEvent[]>;
  write(events: NostrEvent[]): Promise<void>;
}

export function createNostrRuntime(options: { cache: EventCache; relays?: string[]; storage?: Pick<Storage, 'getItem' | 'setItem'>; verifyEvent?: (event: NostrEvent) => boolean }) {
  const eventStore = new AppEventStore(options.verifyEvent ? { verifyEvent: options.verifyEvent } : undefined);
  const liveness = new RelayLiveness();
  const pool = new RelayPool({ liveness });
  let relays = normalizeRelays(options.relays ?? APP_RELAYS);
  try {
    const stored: unknown = JSON.parse(options.storage?.getItem(APP_RELAYS_STORAGE_KEY) ?? 'null');
    if (options.relays === undefined && Array.isArray(stored) && stored.length && stored.every((value) => typeof value === 'string')) {
      relays = normalizeLookupRelays(stored);
    }
  } catch { /* Use defaults when saved app relays are unavailable or invalid. */ }
  let initialLookup = normalizeRelays(LOOKUP_RELAYS);
  try {
    const stored: unknown = JSON.parse(options.storage?.getItem(LOOKUP_RELAYS_STORAGE_KEY) ?? 'null');
    if (Array.isArray(stored) && stored.length && stored.every((value) => typeof value === 'string')) {
      const valid = normalizeRelays(stored);
      if (valid.length === stored.length) initialLookup = valid;
    }
  } catch { /* Defaults remain available when storage is unavailable. */ }
  const lookupRelays$ = new BehaviorSubject(initialLookup);
  const relayPolicy = createRelayPolicy(relays, lookupRelays$);
  const destroyed$ = new ReplaySubject<void>(1);
  let disposed = false;
  createEventLoaderForStore(eventStore, pool, {
    cacheRequest: options.cache.read,
    lookupRelays: relayPolicy.lookupRelays$,
    extraRelays: relayPolicy.readRelays$
  });
  const syncLoader = createSyncLoader({ eventStore, pool, liveness });

  return {
    eventStore, pool, liveness, syncLoader, lookupRelays$, relayPolicy, destroyed$,
    get relays() { return relayPolicy.appRelays$.value; },
    setAppRelays(values: string[]) {
      if (!values.length) throw new Error('Keep at least one app relay.');
      const next = normalizeLookupRelays(values);
      options.storage?.setItem(APP_RELAYS_STORAGE_KEY, JSON.stringify(next));
      relayPolicy.appRelays$.next(next);
    },
    setLookupRelays(values: string[]) {
      const next = normalizeLookupRelays(values);
      options.storage?.setItem(LOOKUP_RELAYS_STORAGE_KEY, JSON.stringify(next));
      lookupRelays$.next(next);
    },
    cacheRequest: options.cache.read,
    async hydrate(filters: Filter[]) {
      const events = await options.cache.read(filters);
      for (const event of events) eventStore.add(event);
      return events.length;
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      destroyed$.next(); destroyed$.complete();
      relayPolicy.dispose();
      lookupRelays$.complete();
      eventStore.dispose();
      pool.close();
    }
  };
}

export type NostrRuntime = ReturnType<typeof createNostrRuntime>;
