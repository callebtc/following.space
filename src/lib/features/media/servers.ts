import { castUser } from 'applesauce-common/casts';
import { kinds } from 'applesauce-core/helpers';
import { firstValueFrom, filter, timeout } from 'rxjs';
import type { NostrRuntime } from '../../nostr/runtime';
import { publishSigned } from '../../nostr/publish';
import { DEFAULT_BLOSSOM_SERVERS, normalizeBlossomServers } from './blossom';
import type { Signer } from 'blossom-client-sdk';

export function observeBlossomServers(runtime: NostrRuntime, pubkey: string) {
  return castUser(pubkey, runtime.eventStore).blossomServers$;
}

/** Resolve the account's BUD-03 list before considering application defaults. */
export async function loadBlossomServers(runtime: NostrRuntime, pubkey: string): Promise<string[]> {
  await runtime.hydrate([{ kinds: [kinds.BlossomServerList], authors: [pubkey] }]).catch(() => {});
  try {
    const servers = await firstValueFrom(observeBlossomServers(runtime, pubkey).pipe(
      filter((value): value is URL[] => value !== undefined),
      timeout({ first: 4000 })
    ));
    // An explicitly empty list must not silently send media to other servers.
    return servers.map((server) => server.href);
  } catch {
    if (runtime.eventStore.getReplaceable(kinds.BlossomServerList, pubkey)) throw new Error('Could not read your Blossom server list. Please retry.');
    return [...DEFAULT_BLOSSOM_SERVERS];
  }
}

export async function publishBlossomServers(runtime: NostrRuntime, pubkey: string, values: string[], signer: Signer, isCurrent: () => boolean) {
  const servers = normalizeBlossomServers(values);
  await loadBlossomServers(runtime, pubkey);
  if (!isCurrent()) throw new Error('Account changed. Please retry.');
  const previous = runtime.eventStore.getReplaceable(kinds.BlossomServerList, pubkey);
  const signed = await signer({
    kind: kinds.BlossomServerList, content: previous?.content ?? '',
    created_at: Math.max(Math.floor(Date.now() / 1000), (previous?.created_at ?? 0) + 1),
    tags: [...(previous?.tags ?? []).filter((tag) => tag[0] !== 'server'), ...servers.map((server) => ['server', server])]
  });
  if (!isCurrent() || signed.pubkey !== pubkey) throw new Error('Account changed. Please retry.');
  await publishSigned(runtime, signed);
  return servers;
}
