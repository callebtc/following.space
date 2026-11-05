import { kinds } from 'applesauce-core/helpers';

/** NIP-51 starter packs; keep the app's existing follow-list name. */
export const FOLLOW_LIST_KIND = kinds.StarterPacks;

/** User-selected lookup relays (not NIP-65 read/write mailboxes). */
export const LOOKUP_RELAY_LIST_KIND = 10086;
