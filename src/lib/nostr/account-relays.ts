import { combineLatest, defer, from, Observable, Subscription, switchMap, map, distinctUntilChanged, takeUntil, timer, catchError, of } from 'rxjs';
import type { NostrRuntime } from './runtime';
import { eventRelays, normalizeRelays } from './relay-policy';
import { kinds } from 'applesauce-core/helpers';
import { LOOKUP_RELAY_LIST_KIND } from './protocol/kinds';

/** Bootstrap relay discovery for the active account. */
export function observeAccountRelays(runtime: NostrRuntime, pubkey: string) {
  return new Observable<void>(() => {
    const scope = new Subscription();
    runtime.relayPolicy.account$.next({ pubkey, loading: true });
    const filter = { kinds: [kinds.RelayList, LOOKUP_RELAY_LIST_KIND], authors: [pubkey] };
    scope.add(combineLatest([
      runtime.eventStore.replaceable(LOOKUP_RELAY_LIST_KIND, pubkey), runtime.eventStore.replaceable(kinds.RelayList, pubkey)
    ]).subscribe(([lookup, mailboxes]) => {
      runtime.relayPolicy.account$.next({ ...runtime.relayPolicy.account$.value, pubkey, lookup, mailboxes });
    }));
    const bootstrap$ = combineLatest([
      runtime.relayPolicy.appRelays$, runtime.relayPolicy.lookupRelays$, runtime.eventStore.replaceable(kinds.RelayList, pubkey)
    ]).pipe(
      map(([app, lookup, mailboxes]) => normalizeRelays([...app, ...lookup, ...eventRelays(mailboxes, 'read'), ...eventRelays(mailboxes, 'write')])),
      distinctUntilChanged((a, b) => a.join('\n') === b.join('\n'))
    );
    scope.add(defer(() => from(runtime.hydrate([filter]))).pipe(
      catchError(() => of(0)),
      switchMap(() => bootstrap$.pipe(switchMap((relays) => runtime.pool.request(relays, filter, { timeout: 6000, waitForAuth: false })))),
      takeUntil(timer(8000))
    ).subscribe({
      next: (event) => runtime.eventStore.add(event),
      error: () => finish(), complete: () => finish()
    }));
    function finish() {
      if (runtime.relayPolicy.account$.value.pubkey === pubkey) runtime.relayPolicy.account$.next({ ...runtime.relayPolicy.account$.value, loading: false });
    }
    return () => {
      scope.unsubscribe();
      if (runtime.relayPolicy.account$.value.pubkey === pubkey) runtime.relayPolicy.account$.next({ loading: false });
    };
  }).pipe(takeUntil(runtime.destroyed$));
}
