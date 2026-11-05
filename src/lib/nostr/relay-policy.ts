import type { NostrEvent } from 'applesauce-core/helpers';
import { BehaviorSubject, combineLatest, distinctUntilChanged, map, shareReplay } from 'rxjs';

// Compatibility exports for existing settings, login, and runtime consumers.
export { APP_RELAYS, LOOKUP_RELAYS, SIGNER_RELAYS } from './relay-defaults';

export function normalizeRelays(relays: string[]): string[] {
  return [...new Set(relays.flatMap((value) => {
    try {
      const url = new URL(value);
      if (!['wss:', 'ws:'].includes(url.protocol) || url.username || url.password || url.hash) return [];
      return [url.href];
    } catch {
      return [];
    }
  }))];
}

export function eventRelays(event?: NostrEvent, marker?: 'read' | 'write'): string[] {
  return normalizeRelays((event?.tags ?? []).flatMap((tag) =>
    tag[0] === (marker ? 'r' : 'relay') && (!marker || !tag[2] || tag[2] === marker) && tag[1] ? [tag[1]] : []
  ));
}
export interface AccountRelayState { pubkey?: string; lookup?: NostrEvent; mailboxes?: NostrEvent; loading: boolean }
export function createRelayPolicy(relays: string[], localLookupRelays$: BehaviorSubject<string[]>) {
  const appRelays$ = new BehaviorSubject(normalizeRelays(relays));
  const account$ = new BehaviorSubject<AccountRelayState>({ loading: false });
  const same = (a: string[], b: string[]) => a.join('\n') === b.join('\n');
  const readRelays$ = combineLatest([appRelays$, account$]).pipe(
    map(([app, account]) => normalizeRelays([...app, ...eventRelays(account.mailboxes, 'read')])),
    distinctUntilChanged(same), shareReplay({ bufferSize: 1, refCount: true })
  );
  const lookupRelays$ = combineLatest([localLookupRelays$, account$]).pipe(
    map(([local, account]) => account.lookup ? eventRelays(account.lookup) : local),
    distinctUntilChanged(same), shareReplay({ bufferSize: 1, refCount: true })
  );
  return { appRelays$, account$, readRelays$, lookupRelays$,
    get readRelays() { return normalizeRelays([...appRelays$.value, ...eventRelays(account$.value.mailboxes, 'read')]); },
    dispose() { account$.complete(); appRelays$.complete(); }
  };
}
