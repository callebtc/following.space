import { describe, expect, it, vi } from 'vitest';
import { Observable, of, lastValueFrom, throwError } from 'rxjs';
import { createSyncLoader } from 'applesauce-loaders/loaders';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { requestEvents } from '../src/lib/nostr/requests';
import { AppEventStore } from '../src/lib/nostr/event-store';
import type { Filter } from 'applesauce-core/helpers';
import { signedPack } from './fixtures';

describe('finite requests', () => {
  it('cancels the underlying relay subscription and rejects instead of reporting an empty success', async () => {
    const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} }, relays: ['wss://relay.example'] });
    const closed = vi.fn();
    vi.spyOn(runtime.pool, 'request').mockReturnValue(new Observable(() => closed));
    const controller = new AbortController();
    const result = requestEvents(runtime, { kinds: [39089] }, runtime.relays, controller.signal);
    controller.abort();
    await expect(result).rejects.toThrow('Cancelled');
    expect(closed).toHaveBeenCalledTimes(1);
    runtime.dispose();
  });
});

describe('sync-loader transport paths', () => {
  it('uses paginated REQ fallback on relays without NIP-77 and stores events', async () => {
    const eventStore = new AppEventStore();
    const event = signedPack({ timestamp: Math.floor(Date.now() / 1000) - 60 });
    const request = vi.fn((_relay: string, filters: Filter[]) => of(...((filters[0].until ?? Infinity) < event.created_at ? [] : [event])));
    const sync = vi.fn(() => of());
    const loader = createSyncLoader({ eventStore, request, sync, getSupported: async () => [], getMaxLimit: async () => 500 });
    const status = await lastValueFrom(loader({ relays: ['wss://relay.example'], filter: { kinds: [39089] } }).status$);
    expect(status.done).toBe(true);
    expect(Object.values(status.relays)[0].method).toBe('request');
    expect(eventStore.getEvent(event.id)).toBeDefined();
    expect(sync).not.toHaveBeenCalled();
    eventStore.dispose();
  });
  it('downloads through NIP-77 and falls back if negotiation fails', async () => {
    for (const fails of [false, true]) {
      const eventStore = new AppEventStore(); const event = signedPack({ timestamp: Math.floor(Date.now() / 1000) - 60 });
      const request = vi.fn((_relay: string, filters: Filter[]) => of(...((filters[0].until ?? Infinity) < event.created_at ? [] : [event])));
      const loader = createSyncLoader({ eventStore, request,
        sync: () => fails ? throwError(() => new Error('negentropy unavailable')) : of({ type: 'received' as const, from: 'wss://relay.example', event }),
        getSupported: async () => [77], getMaxLimit: async () => 500 });
      const status = await lastValueFrom(loader({ relays: ['wss://relay.example'], filter: { kinds: [39089] } }).status$);
      expect(status.done).toBe(true);
      expect(Object.values(status.relays)[0].method).toBe(fails ? 'request' : 'negentropy');
      expect(eventStore.getEvent(event.id)).toBeDefined();
      if (!fails) expect(request).not.toHaveBeenCalled();
      eventStore.dispose();
    }
  });
});
