import { ContactsFactory } from 'applesauce-common/factories';
import { kinds, type NostrEvent } from 'applesauce-core/helpers';
import type { ISigner } from 'applesauce-signers';
import { requestEventsSettled } from '../../nostr/requests';
import { publishSigned } from '../../nostr/publish';
import type { NostrRuntime } from '../../nostr/runtime';
import { discoverOutboxRelaysSettled } from '../../nostr/outboxes';

type Identity = ISigner & { pubkey: string };
const queues = new Map<string, Promise<unknown>>();
export function updateContacts(runtime: NostrRuntime, account: Identity, change: { add?: string[]; remove?: string[]; replace?: string[] }, isActive: () => boolean, onSnapshot: (event: NostrEvent) => void) {
  const prior = queues.get(account.pubkey) ?? Promise.resolve();
  const task = prior.catch(() => {}).then(async () => {
    if (!isActive()) throw new Error('Account changed; please retry');
    // Best effort: most users list some dead relays, so read from whichever relays answer.
    const discovery = await discoverOutboxRelaysSettled(runtime, account.pubkey);
    const outboxes = discovery.outboxes;
    const relays = [...runtime.relays, ...outboxes];
    const read = await requestEventsSettled(runtime, { kinds: [kinds.Contacts], authors: [account.pubkey] }, relays);
    if (!isActive()) throw new Error('Account changed; please retry');
    const previous = runtime.eventStore.getReplaceable(kinds.Contacts, account.pubkey);
    // Building on the newest list found is fine. Starting a new list is only safe when
    // every relay confirmed there is none; otherwise it could replace follows held on a
    // relay that didn't answer.
    if (!previous && (!discovery.complete || read.failed.length)) {
      throw new Error('Your existing follow list could not be found because some relays did not respond. Please retry.');
    }
    let factory = previous ? ContactsFactory.modify(previous) : ContactsFactory.create();
    if (change.replace) {
      factory = factory.modifyPublicTags((tags) => tags.filter((tag) => tag[0] !== 'p'));
    }
    for (const pubkey of [...(change.add ?? []), ...(change.replace ?? [])]) {
      if (!/^[0-9a-f]{64}$/i.test(pubkey)) throw new Error('Invalid public key');
      // Preserve existing relay hints and petnames for contacts already present.
      if (!previous?.tags.some((tag) => tag[0] === 'p' && tag[1] === pubkey) || change.replace) factory = factory.addContact(pubkey);
    }
    for (const pubkey of change.remove ?? []) factory = factory.removeContact(pubkey);
    factory = factory.created(Math.max(Math.floor(Date.now() / 1000), (previous?.created_at ?? 0) + 1));
    const signed = await factory.sign(account);
    if (!isActive()) throw new Error('Account changed; update was not published');
    if (previous) onSnapshot(previous);
    // Reuse the just-resolved destinations; don't wait for missing metadata twice.
    await publishSigned(runtime, signed, relays, outboxes);
    onSnapshot(signed);
    return signed;
  });
  queues.set(account.pubkey, task);
  void task.finally(() => { if (queues.get(account.pubkey) === task) queues.delete(account.pubkey); }).catch(() => {});
  return task;
}
