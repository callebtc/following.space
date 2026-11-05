import { browser } from '$app/environment';
import { writable } from 'svelte/store';
import { combineLatest, Observable, of, Subscription, switchMap, merge, map, distinctUntilChanged, catchError, EMPTY, ReplaySubject, shareReplay, startWith } from 'rxjs';
import { normalizeRelays, eventRelays } from '../nostr/relay-policy';
import { accountRefreshFailed } from '../nostr/account-refresh';
import { observeAccountRelays } from '../nostr/account-relays';
import { kinds, npubEncode } from 'applesauce-core/helpers';
import { LOOKUP_RELAY_LIST_KIND } from '../nostr/protocol/kinds';
import { accounts } from '../nostr/accounts';
import { parseProfile } from '../nostr/protocol/profile';
import { initializeSigner } from './login';
import { getNostrRuntime } from '../nostr/runtime.client';
import { updateContacts } from '../features/contacts/commands';
import { readSnapshots, saveSnapshot, type FollowSnapshot } from '../features/contacts/snapshots';
export type { FollowSnapshot } from '../features/contacts/snapshots';

export interface UserProfile {
  pubkey: string; name?: string; picture?: string; about?: string; npub?: string;
  following: Set<string>; relays: Set<string>;
}
const runtime$ = new ReplaySubject<Awaited<ReturnType<typeof getNostrRuntime>>>(1);
export const user$ = runtime$.pipe(switchMap((runtime) => observeUser(runtime)), startWith(null),
  shareReplay({ bufferSize: 1, refCount: true }));
export const user = user$;
export const userWarning = writable('');
let userSubscription: Subscription | undefined;

export async function loadUser() {
  if (!browser) return;
  await initializeSigner();
  if (userSubscription) return;
  const runtime = await getNostrRuntime();
  if (userSubscription) return;
  runtime$.next(runtime);
  // Keep account discovery active for the application session.
  userSubscription = user$.subscribe();
}

function observeUser(runtime: Awaited<ReturnType<typeof getNostrRuntime>>) {
  return accounts.active$.pipe(switchMap((account) => {
    userWarning.set('');
    if (!account) { runtime.relayPolicy.account$.next({ loading: false }); return of(null); }
    return new Observable<UserProfile>((observer) => {
      const scope = new Subscription();
      const pubkey = account.pubkey;
      scope.add(observeAccountRelays(runtime, pubkey).subscribe());
      scope.add(combineLatest([
        runtime.eventStore.replaceable(kinds.Metadata, pubkey), runtime.eventStore.replaceable(kinds.Contacts, pubkey), runtime.eventStore.replaceable(kinds.RelayList, pubkey)
      ]).subscribe(([profile, contacts, mailboxes]) => {
        if (profile || contacts) userWarning.set('');
        const content = parseProfile(profile);
        observer.next({ pubkey, name: content.name, picture: content.picture,
          about: content.bio, npub: npubEncode(pubkey),
          following: new Set(contacts?.tags.filter((tag) => tag[0] === 'p' && /^[0-9a-f]{64}$/i.test(tag[1] || '')).map((tag) => tag[1]) ?? []),
          relays: new Set(mailboxes ? eventRelays(mailboxes, 'write') : []) });
      }));
      const filter = { kinds: [kinds.Metadata, kinds.Contacts], authors: [pubkey] };
      void runtime.hydrate([filter]).catch(() => {}).then(() => {
        if (scope.closed) return;
        scope.add(combineLatest([
          runtime.relayPolicy.lookupRelays$, runtime.eventStore.replaceable(kinds.RelayList, pubkey)
        ]).pipe(
          map(([lookup, mailboxes]) => normalizeRelays([...runtime.relays, ...lookup, ...(mailboxes ? eventRelays(mailboxes, 'write') : [])])),
          distinctUntilChanged((a, b) => a.join('\n') === b.join('\n')),
          switchMap((relays) => {
            userWarning.set('');
            let responded = runtime.eventStore.getTimeline(filter).length > 0;
            const failedMessage = 'Account refresh could not reach any relay. Check your connection or lookup relays in Settings.';
            return merge(
              runtime.syncLoader({ relays, filter, timeout: 6000, waitForAuth: false }).status$.pipe(map((status) => {
                responded ||= status.loaded > 0 || Object.values(status.relays).some((relay) => relay.state === 'complete' || relay.count > 0);
                if (!status.done) return;
                userWarning.set(!responded && !runtime.eventStore.getTimeline(filter).length && accountRefreshFailed(status) ? failedMessage : '');
              }), catchError(() => { if (!responded && !runtime.eventStore.getTimeline(filter).length) userWarning.set(failedMessage); return EMPTY; })),
              runtime.pool.subscription(relays, { ...filter, kinds: [kinds.Metadata, kinds.Contacts, kinds.RelayList, LOOKUP_RELAY_LIST_KIND], since: Math.floor(Date.now() / 1000) - 60 }).pipe(
                map((event) => { responded = true; runtime.eventStore.add(event); userWarning.set(''); }),
                // RelayGroup isolates individual failures; keep sync and relay-setting changes alive if the live group fails.
                catchError(() => EMPTY)
              )
            );
          })
        ).subscribe());
      });
      return () => scope.unsubscribe();
    });
  }));
}
export function getFollowSnapshots(): FollowSnapshot[] {
  try { return browser && accounts.active ? readSnapshots(localStorage, accounts.active.pubkey) : []; } catch { return []; }
}
async function changeContacts(change: Parameters<typeof updateContacts>[2]) {
  await loadUser();
  const account = accounts.active;
  if (!account) throw new Error('Sign in first');
  await updateContacts(await getNostrRuntime(), account, change, () => accounts.active === account,
    (event) => { try { saveSnapshot(localStorage, event); } catch { /* Optional local history. */ } });
  return true;
}
export function followUsers(pubkeys: string[]) { return changeContacts({ add: pubkeys }); }
export function unfollowUsers(pubkeys: string[]) { return changeContacts({ remove: pubkeys }); }
export function restoreFollowSnapshot(snapshot: FollowSnapshot) {
  if (snapshot.event.pubkey !== accounts.active?.pubkey) throw new Error('This snapshot belongs to another account');
  return changeContacts({ replace: snapshot.pubkeys });
}
if (import.meta.hot) import.meta.hot.dispose(() => { userSubscription?.unsubscribe(); userSubscription = undefined; });
