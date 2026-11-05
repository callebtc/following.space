import { describe, expect, it } from 'vitest';
import { naddrEncode, npubEncode } from 'applesauce-core/helpers';
import { packHref, packNaddr, resolvePackLink } from '../src/lib/nostr/protocol/pack-link';
import { parseFollowListEvent } from '../src/lib/nostr/protocol/follow-pack';
import { previewMeta } from '../src/lib/server/previews/metadata';
import { signedPack } from './fixtures';

const pack = parseFollowListEvent(signedPack())!;
describe('pack links', () => {
  it.each(['garden', '', '日本語 / garden:%?'])('preserves the exact identifier %s across both formats', (id) => {
    expect(resolvePackLink(packNaddr({ ...pack, id }))).toEqual({ identifier: id, pubkey: pack.pubkey, relays: [] });
    if (id) expect(resolvePackLink(id, pack.pubkey)).toEqual({ identifier: id, pubkey: pack.pubkey, relays: [] });
  });
  it('uses the encoded author rather than a conflicting query parameter', () => {
    expect(resolvePackLink(packNaddr(pack), 'f'.repeat(64)).pubkey).toBe(pack.pubkey);
  });
  it('normalizes and filters relay hints', () => {
    const link = naddrEncode({ kind: 39089, pubkey: pack.pubkey, identifier: pack.id,
      relays: ['wss://example.com', 'wss://example.com/', 'https://example.com', 'ws://user:pass@example.com'] });
    expect(resolvePackLink(link).relays).toEqual(['wss://example.com/']);
  });
  it('embeds bounded, normalized useful hints in generated URLs and shared addresses', () => {
    const hints = ['https://invalid.example', 'wss://outbox.example', 'wss://outbox.example/',
      'wss://seen.example', 'wss://third.example', 'wss://fourth.example'];
    const expected = ['wss://outbox.example/', 'wss://seen.example/', 'wss://third.example/'];
    expect(resolvePackLink(packHref(pack, hints).slice(3)).relays).toEqual(expected);
    const copied = `nostr:${packNaddr(pack, hints)}`;
    expect(resolvePackLink(copied.slice('nostr:'.length)).relays).toEqual(expected);
  });
  it('does not generate malformed NIP-19 TLVs from oversized relay URLs', () => {
    expect(resolvePackLink(packNaddr(pack, ['wss://relay.example/' + 'x'.repeat(256), 'wss://useful.example'])).relays)
      .toEqual(['wss://useful.example/']);
  });
  it('retains authorless and naddr-prefixed legacy identifiers', () => {
    expect(resolvePackLink('garden').pubkey).toBeUndefined();
    expect(resolvePackLink('naddr1legacy').identifier).toBe('naddr1legacy');
  });
  it('rejects unsupported kinds, other NIP-19 entities and invalid legacy authors', () => {
    expect(() => resolvePackLink(naddrEncode({ kind: 30023, pubkey: pack.pubkey, identifier: 'garden' }))).toThrow();
    expect(() => resolvePackLink(npubEncode(pack.pubkey))).toThrow();
    expect(() => resolvePackLink('garden', 'bad')).toThrow();
    expect(() => resolvePackLink('')).toThrow();
  });
  it('uses a canonical naddr URL in preview metadata', () => {
    expect(previewMeta(pack, 'https://following.space', '/farm.png')).toContain(`content="https://following.space${packHref(pack)}"`);
  });
  it('never substitutes a revision ID for an empty or missing d tag', () => {
    const event = signedPack();
    expect(parseFollowListEvent({ ...event, tags: [['d', '']] })?.id).toBe('');
    expect(parseFollowListEvent({ ...event, tags: [] })?.id).toBe('');
  });
});
