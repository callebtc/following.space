import { expect, it, vi } from 'vitest';
import { EMPTY } from 'rxjs';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { createPackFeed, type PackFeedState } from '../src/lib/features/packs/feed';
import { observableReadable } from '../src/lib/reactivity/readable';
import { NOW, signedPack } from './fixtures';

it('renders in-memory packs synchronously through the Svelte store on a revisit', () => {
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} }, relays: ['wss://relay.example.com'] });
  vi.spyOn(runtime.pool, 'subscription').mockReturnValue(EMPTY);
  vi.spyOn(runtime, 'syncLoader').mockImplementation(() => ({ status$: EMPTY, events$: EMPTY }));
  runtime.eventStore.add(signedPack());
  const feed = createPackFeed(runtime, {}, { now: NOW });
  const values: PackFeedState[] = [];
  const stop = observableReadable(feed.state$, feed.initial).subscribe((state) => values.push(state));
  try {
    expect(values).toHaveLength(1);
    expect(values[0].packs.map((pack) => pack.name)).toEqual(['Garden']);
  } finally {
    stop();
    runtime.dispose();
  }
});
