import { catchError, map, of } from 'rxjs';
import { kinds } from 'applesauce-core/helpers';
import type { NostrRuntime } from '../../nostr/runtime';
import { parseProfile, type ProfileView } from '../../nostr/protocol/profile';
export type { ProfileView } from '../../nostr/protocol/profile';
export function observeProfile(runtime: NostrRuntime, pubkey: string, relays?: string[]) {
  return runtime.eventStore.replaceable({ kind: kinds.Metadata, pubkey, relays }).pipe(
    map((event) => parseProfile(event)), catchError(() => of<ProfileView>({}))
  );
}
