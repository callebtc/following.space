import { castUser } from 'applesauce-common/casts';
import { kinds } from 'applesauce-core/helpers';
import { getBlossomServersFromList } from 'applesauce-common/helpers';
import { firstValueFrom, filter, timeout, map, concat, of } from 'rxjs';
import type { NostrRuntime } from '../../nostr/runtime';
import { publishSigned } from '../../nostr/publish';
import { DEFAULT_BLOSSOM_SERVERS, normalizeBlossomServers } from './blossom';
import type { Signer } from 'blossom-client-sdk';

export function observeBlossomServers(runtime: NostrRuntime, pubkey: string) {
  return castUser(pubkey, runtime.eventStore).blossomServers$;
}

/** Defaults are provisional: keep listening for a list discovered after the deadline. */
export function observeResolvedBlossomServers(runtime: NostrRuntime, pubkey: string) {
  const servers$ = observeBlossomServers(runtime, pubkey).pipe(
    filter((value): value is URL[] => value !== undefined),
    map((servers) => servers.map((server) => server.href))
  );
  return servers$.pipe(timeout({ first: 4000, with: () => {
    // The cast waits on outbox discovery; a cached list still beats defaults.
    const cached = runtime.eventStore.getReplaceable(kinds.BlossomServerList, pubkey);
    const fallback = cached ? getBlossomServersFromList(cached).map((server) => server.href) : [...DEFAULT_BLOSSOM_SERVERS];
    return concat(of(fallback), servers$);
  } }));
}

/** Resolve the account's BUD-03 list before considering application defaults. */
export async function loadBlossomServers(runtime: NostrRuntime, pubkey: string): Promise<string[]> {
  await runtime.hydrate([{ kinds: [kinds.BlossomServerList], authors: [pubkey] }]).catch(() => {});
  return firstValueFrom(observeResolvedBlossomServers(runtime, pubkey));
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
