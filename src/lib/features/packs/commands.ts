import { getNostrRuntime } from '../../nostr/runtime.client';
import { accounts } from '../../nostr/accounts';
import { initializeSigner } from '../../stores/login';
import { loadPack } from './detail';
import { FollowPackFactory, packDeletion } from './factory';
import { publishSigned } from '../../nostr/publish';
import { requestEvents } from '../../nostr/requests';
import type { FollowListEntry } from '../../types/follow-list';
import { FOLLOW_LIST_KIND } from '../../nostr/protocol/kinds';

export async function publishFollowList(name: string, coverImageUrl: string, entries: FollowListEntry[], id?: string, description?: string, expectedAuthor?: string) {
  await initializeSigner();
  const account = accounts.active;
  if (!account) throw new Error('Sign in first');
  if (expectedAuthor && expectedAuthor !== account.pubkey) throw new Error('Only the author can edit this pack');
  const runtime = await getNostrRuntime();
  const previous = id ? await loadPack(runtime, id, account.pubkey) : null;
  if (id && !previous) throw new Error('The pack to edit could not be found');
  const priorEvent = previous ? runtime.eventStore.getEvent(previous.eventId) : undefined;
  const factory = FollowPackFactory.create({ id: id || crypto.randomUUID(), name, coverImageUrl, entries, description }, priorEvent)
    .created(Math.max(Math.floor(Date.now() / 1000), (priorEvent?.created_at ?? 0) + 1));
  const signed = await factory.sign(account);
  if (accounts.active !== account) throw new Error('Account changed; please retry');
  await publishSigned(runtime, signed);
  return signed;
}
export async function deleteFollowList(eventId: string) {
  await initializeSigner();
  const account = accounts.active;
  if (!account) throw new Error('Sign in first');
  const runtime = await getNostrRuntime();
  if (!runtime.eventStore.getEvent(eventId)) await requestEvents(runtime, { ids: [eventId], kinds: [FOLLOW_LIST_KIND] });
  const event = runtime.eventStore.getEvent(eventId);
  if (!event || event.pubkey !== account.pubkey) throw new Error('Only the author can delete this pack');
  const signed = await packDeletion(event).created(Math.max(Math.floor(Date.now() / 1000), event.created_at)).sign(account);
  if (accounts.active !== account) throw new Error('Account changed; please retry');
  await publishSigned(runtime, signed);
  return true;
}
