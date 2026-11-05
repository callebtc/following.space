import { expect, it } from 'vitest';
import { finalizeEvent } from 'applesauce-core/helpers';
import { parseProfile } from '../src/lib/nostr/protocol/profile';
import { alice, NOW } from './fixtures';
it('tolerates malformed profile fields without exposing objects to rendering helpers', () => {
  const event = finalizeEvent({ kind: 0, created_at: NOW, tags: [], content: JSON.stringify({ name: 'Name', picture: { object: true }, about: [], display_name: 123 }) }, alice);
  expect(parseProfile(event)).toEqual({ name: 'Name', picture: undefined, bio: undefined, nip05: undefined });
});
it('rejects non-web avatar URLs', () => {
  const event = finalizeEvent({ kind: 0, created_at: NOW, tags: [], content: JSON.stringify({ name: 'Name', picture: 'javascript:alert(1)' }) }, alice);
  expect(parseProfile(event).picture).toBeUndefined();
});
