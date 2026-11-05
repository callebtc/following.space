import { afterEach, describe, expect, it, vi } from 'vitest';
import { naddrEncode } from 'applesauce-core/helpers';
import { RelayPool } from 'applesauce-relay';
import { of } from 'rxjs';
import { APP_RELAYS, normalizeRelays } from '../src/lib/nostr/relay-policy';
import { readPreview } from '../src/lib/server/previews/reader';
import { signedPack } from './fixtures';

afterEach(() => vi.restoreAllMocks());

describe('server preview relay policy', () => {
  const hints = [
    'ws://127.0.0.1:8080',
    'ws://localhost:8080',
    'ws://[::1]:8080',
    'wss://10.0.0.1',
    'wss://172.16.0.1',
    'wss://192.168.1.1',
    'ws://169.254.169.254',
    'wss://untrusted.example'
  ];

  describe.each([false, true])('pack available: %s', (available) => {
    it.each(hints)('never sends relay hint %s to server transport', async (hint) => {
      const member = 'a'.repeat(64);
      const event = signedPack({ tags: [['p', member]] });
      // Mock the pool transport, not readPreview/requestEvents: real URL decoding,
      // runtime relay selection, event ingestion, and cleanup still run.
      const request = vi.spyOn(RelayPool.prototype, 'request').mockReturnValue(of());
      if (available) request.mockReturnValueOnce(of(event));
      // Fail closed if any unmocked path tries to create an actual relay/socket.
      const relay = vi.spyOn(RelayPool.prototype, 'relay').mockImplementation(() => {
        throw new Error('Real relay transport is forbidden in this test');
      });
      const close = vi.spyOn(RelayPool.prototype, 'close');
      const address = naddrEncode({
        kind: 39089, pubkey: event.pubkey, identifier: 'garden', relays: [hint]
      });

      const result = await readPreview(address, undefined, new AbortController().signal);

      if (available) expect(result?.pack.eventId).toBe(event.id);
      else expect(result).toBeNull();
      expect(request).toHaveBeenCalledTimes(available ? 2 : 1);
      for (const [targets] of request.mock.calls) {
        expect(targets).toEqual(normalizeRelays(APP_RELAYS));
        expect(targets).not.toContain(new URL(hint).href);
      }
      if (available) expect(request.mock.calls[1][1]).toEqual({ kinds: [0], authors: [member] });
      expect(relay).not.toHaveBeenCalled();
      expect(close).toHaveBeenCalledOnce();
    });
  });
});
