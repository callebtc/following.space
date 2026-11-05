import { filterOptimalRelays, includeFallbackRelays, includeMailboxes } from 'applesauce-core';
import { createOutboxMap } from 'applesauce-core/helpers';
import { ignoreUnhealthyRelaysOnPointers } from 'applesauce-relay';
import { debounceTime, distinctUntilChanged, map, of, shareReplay } from 'rxjs';
import type { NostrRuntime } from '../../nostr/runtime';
import { createPackDirectory } from './directory';

/** NIP-65 routing from Applesauce's outbox/contacts-sync example, scoped to packs. */
export function createContactsPackDirectory(runtime: NostrRuntime, authors: string[], now?: number) {
  const targets$ = of(authors.map((pubkey) => ({ pubkey }))).pipe(
    includeMailboxes(runtime.eventStore),
    // Contacts without a relay list still have a discovery path.
    includeFallbackRelays(runtime.relayPolicy.readRelays$),
    ignoreUnhealthyRelaysOnPointers(runtime.liveness),
    debounceTime(500),
    filterOptimalRelays(30, 3),
    map(createOutboxMap),
    map((outboxes) => Object.entries(outboxes).sort(([a], [b]) => a.localeCompare(b)).map(([relay, users]) => ({
      relays: [relay], authors: users.map((user) => user.pubkey).sort()
    }))),
    distinctUntilChanged((a, b) => JSON.stringify(a) === JSON.stringify(b)),
    shareReplay({ bufferSize: 1, refCount: true })
  );
  return createPackDirectory(runtime, now, targets$);
}
