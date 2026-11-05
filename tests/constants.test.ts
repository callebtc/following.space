import { describe, expect, it } from 'vitest';
import { kinds } from 'applesauce-core/helpers';
import { FOLLOW_LIST_KIND, LOOKUP_RELAY_LIST_KIND } from '../src/lib/nostr/protocol/kinds';
import { FOLLOW_LIST_KIND as legacyFollowListKind } from '../src/lib/nostr/protocol/follow-pack';
import * as defaults from '../src/lib/nostr/relay-defaults';
import { APP_RELAYS, LOOKUP_RELAYS, SIGNER_RELAYS, normalizeRelays } from '../src/lib/nostr/relay-policy';

describe('shared protocol and relay constants', () => {
  it('preserves the public follow-list kind and distinguishes lookup lists from mailboxes', () => {
    expect(FOLLOW_LIST_KIND).toBe(kinds.StarterPacks);
    expect(legacyFollowListKind).toBe(FOLLOW_LIST_KIND);
    expect(LOOKUP_RELAY_LIST_KIND).toBe(10086);
    expect(LOOKUP_RELAY_LIST_KIND).not.toBe(kinds.RelayList);
  });

  it('keeps relay-policy compatibility exports and valid defaults for every role', () => {
    expect(APP_RELAYS).toBe(defaults.APP_RELAYS);
    expect(LOOKUP_RELAYS).toBe(defaults.LOOKUP_RELAYS);
    expect(SIGNER_RELAYS).toBe(defaults.SIGNER_RELAYS);
    for (const relays of Object.values(defaults)) {
      expect(relays.length).toBeGreaterThan(0);
      expect(normalizeRelays(relays)).toHaveLength(relays.length);
      expect(relays.every((relay) => new URL(relay).protocol === 'wss:')).toBe(true);
    }
  });
});
