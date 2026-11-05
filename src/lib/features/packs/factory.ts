import { EventFactory, blankEventTemplate } from 'applesauce-core/factories';
import { kinds, type NostrEvent } from 'applesauce-core/helpers';
import { FOLLOW_LIST_KIND, type FollowList } from '../../nostr/protocol/follow-pack';

export type PackDraft = Pick<FollowList, 'id' | 'name' | 'coverImageUrl' | 'entries' | 'description'>;
export class FollowPackFactory extends EventFactory<typeof FOLLOW_LIST_KIND> {
  static create(draft: PackDraft, previous?: NostrEvent) {
    if (!draft.id || !draft.name.trim()) throw new Error('A pack needs an identifier and title');
    if (draft.entries.some((entry) => !/^[0-9a-f]{64}$/i.test(entry.pubkey))) throw new Error('Invalid member public key');
    const managed = new Set(['d', 'title', 'n', 'image', 'description', 'p']);
    const tags = (previous?.tags ?? []).filter((tag) => !managed.has(tag[0])).map((tag) => [...tag]);
    tags.push(['d', draft.id], ['title', draft.name]);
    if (draft.coverImageUrl) tags.push(['image', draft.coverImageUrl]);
    if (draft.description) tags.push(['description', draft.description]);
    tags.push(...draft.entries.map((entry) => entry.relay ? ['p', entry.pubkey, entry.relay] : ['p', entry.pubkey]));
    return new FollowPackFactory((resolve) => resolve({ ...blankEventTemplate(FOLLOW_LIST_KIND), tags, content: '' }));
  }
}

export function packDeletion(event: NostrEvent) {
  if (event.kind !== FOLLOW_LIST_KIND) throw new Error('Not a follow pack');
  const d = event.tags.find((tag) => tag[0] === 'd')?.[1];
  if (d === undefined) throw new Error('Pack identifier is missing');
  return EventFactory.fromKind(kinds.EventDeletion).content('Follow pack deleted').modifyPublicTags(() => [
    ['e', event.id], ['a', `${FOLLOW_LIST_KIND}:${event.pubkey}:${d}`], ['k', String(FOLLOW_LIST_KIND)]
  ]);
}
