import { afterEach, describe, expect, it, vi } from 'vitest';
import { NEVER, of, throwError } from 'rxjs';
import { createNostrRuntime } from '../src/lib/nostr/runtime';
import { loadPack, AmbiguousPackError, observePack } from '../src/lib/features/packs/detail';
import { renderPreview } from '../src/lib/server/previews/render';
import { parseFollowListEvent } from '../src/lib/nostr/protocol/follow-pack';
import { finalizeEvent } from 'applesauce-core/helpers';
import { alice, bob, signedPack } from './fixtures';
const stops: (() => void)[] = [];
afterEach(() => stops.splice(0).forEach((stop) => stop()));
function setup() {
  const runtime = createNostrRuntime({ cache: { read: async () => [], write: async () => {} }, relays: ['wss://relay.example'] });
  // These identity tests do not exercise metadata discovery (covered in pack-outbox).
  for (const key of [alice, bob]) runtime.eventStore.add(finalizeEvent({ kind: 10002, created_at: 1, content: '', tags: [] }, key));
  vi.spyOn(runtime.pool, 'request').mockReturnValue(of(signedPack(), signedPack({ key: bob })));
  vi.spyOn(runtime.pool, 'subscription').mockReturnValue(NEVER);
  stops.push(() => runtime.dispose()); return runtime;
}
describe('pack detail identity', () => {
  it('rejects ambiguous authorless links rather than choosing an arbitrary author', async () => {
    const runtime = setup();
    await expect(loadPack(runtime, 'garden')).rejects.toBeInstanceOf(AmbiguousPackError);
    expect((await loadPack(runtime, 'garden', signedPack().pubkey))?.pubkey).toBe(signedPack().pubkey);
  });
  it('reacts to newer revisions of the addressed pack', async () => {
    const runtime = setup(); const pack = signedPack();
    runtime.eventStore.add(pack);
    const names: (string | undefined)[] = [];
    const subscription = observePack(runtime, 'garden', pack.pubkey).subscribe((state) => names.push(state.pack?.name));
    stops.push(() => subscription.unsubscribe());
    runtime.eventStore.add(signedPack({ timestamp: pack.created_at + 1, title: 'New revision' }));
    expect(names).toContain('Garden'); expect(names.at(-1)).toBe('New revision');
  });
});
it('renders an actual server PNG without requiring remote images', async () => {
  const pack = parseFollowListEvent(signedPack({ title: 'Preview Garden' }))!;
  const buffer = await renderPreview(pack, [], new AbortController().signal);
  expect(buffer.subarray(1, 4).toString()).toBe('PNG');
  expect(buffer.readUInt32BE(16)).toBe(1200);
  expect(buffer.readUInt32BE(20)).toBe(630);
});

it.each([false, true])('only reports detail failure without cached data: %s', async (cached) => {
  const runtime = setup(); const pack = signedPack();
  if (cached) runtime.eventStore.add(pack);
  vi.mocked(runtime.pool.request).mockReturnValue(throwError(() => new Error('offline')));
  vi.mocked(runtime.pool.subscription).mockReturnValue(throwError(() => new Error('live offline')));
  const states: { error?: string; loading: boolean }[] = [];
  const sub = observePack(runtime, 'garden', pack.pubkey).subscribe((state) => states.push(state));
  stops.push(() => sub.unsubscribe());
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(states.at(-1)?.loading).toBe(false);
  expect(!!states.at(-1)?.error).toBe(!cached);
});

it('loads the same address through naddr and legacy links, including relay hints', async () => {
  const { packNaddr } = await import('../src/lib/nostr/protocol/pack-link');
  const runtime = setup(); const pack = parseFollowListEvent(signedPack())!;
  const address = packNaddr(pack, ['wss://hint.example']);
  expect((await loadPack(runtime, address))?.eventId).toBe((await loadPack(runtime, pack.id, pack.pubkey))?.eventId);
  const states: (string | undefined)[] = [];
  const sub = observePack(runtime, address).subscribe((state) => states.push(state.pack?.name));
  stops.push(() => sub.unsubscribe());
  runtime.eventStore.add(signedPack({ timestamp: pack.createdAt + 1, title: 'Updated naddr pack' }));
  expect(states.at(-1)).toBe('Updated naddr pack');
  const targets = vi.mocked(runtime.pool.request).mock.calls[0][0];
  expect(targets).toContain('wss://hint.example/');
});

it('loads empty identifiers by naddr and rejects unsupported kinds before relay reads', async () => {
  const { naddrEncode } = await import('applesauce-core/helpers');
  const runtime = setup(); const event = signedPack({ identifier: '' });
  vi.mocked(runtime.pool.request).mockReturnValue(of(event));
  const address = naddrEncode({ kind: 39089, pubkey: event.pubkey, identifier: '' });
  expect((await loadPack(runtime, address))?.id).toBe('');
  vi.mocked(runtime.pool.request).mockClear();
  const states: { error?: string }[] = [];
  const sub = observePack(runtime, naddrEncode({ kind: 30023, pubkey: event.pubkey, identifier: 'garden' }))
    .subscribe((state) => states.push(state));
  stops.push(() => sub.unsubscribe());
  expect(states.at(-1)?.error).toBe('Invalid pack address');
  expect(runtime.pool.request).not.toHaveBeenCalled();
});

it('applies cached deletion events when taking an editor snapshot', async () => {
  const pack = signedPack();
  const deletion = finalizeEvent({ kind: 5, created_at: pack.created_at + 1, content: '',
    tags: [['e', pack.id], ['a', `39089:${pack.pubkey}:garden`], ['k', '39089']] }, alice);
  const runtime = setup();
  vi.spyOn(runtime, 'hydrate').mockImplementation(async (filters) => {
    runtime.eventStore.add(pack);
    if (filters.some((filter) => filter.kinds?.includes(5))) runtime.eventStore.add(deletion);
    return 2;
  });
  vi.mocked(runtime.pool.request).mockReturnValue(of());
  expect(await loadPack(runtime, 'garden', pack.pubkey)).toBeNull();
});
