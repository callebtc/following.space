import { verifyEvent, type NostrEvent } from 'applesauce-core/helpers';
import { writable } from 'svelte/store';
import type { NostrRuntime } from './runtime';
import { normalizeRelays } from './relay-policy';
import { observeOutboxRelays } from './outboxes';
import { firstValueFrom, timeout, of } from 'rxjs';

export const publishNotice = writable('');

export async function publishSigned(runtime: NostrRuntime, event: NostrEvent, explicit: string[] = [], knownOutboxes?: string[]) {
  publishNotice.set('');
  if (!verifyEvent(event)) throw new Error('The signer returned an invalid event');
  const outboxes = knownOutboxes ?? await firstValueFrom(observeOutboxRelays(runtime, event.pubkey).pipe(
    timeout({ first: 1500, with: () => of([] as string[]) })
  ));
  const relays = normalizeRelays([...runtime.relays, ...explicit, ...outboxes]);
  const responses = await runtime.pool.publish(relays, event, {
    timeout: 8000, retries: 1, reconnect: 1, waitForAuth: false
  });
  if (!responses.some((response) => response.ok)) throw new Error('No relay accepted the event. Please retry.');
  runtime.eventStore.add(event);
  return responses;
}
