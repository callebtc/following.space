import { BehaviorSubject, combineLatest, Observable, Subscription, shareReplay, switchMap, takeUntil, startWith, catchError, of, distinctUntilChanged, map, merge, from, mergeMap, scan, retry } from 'rxjs';
import type { SyncLoaderStatus } from 'applesauce-loaders/loaders';
import { kinds } from 'applesauce-core/helpers';
import type { NostrRuntime } from '../../nostr/runtime';
import { accountRefreshFailed } from '../../nostr/account-refresh';
import { FOLLOW_LIST_KIND } from '../../nostr/protocol/follow-pack';

const DAY = 86400;
export interface PackDirectoryState { since: number; loading: boolean; hydrated: boolean; warning?: string }

export interface PackSyncTarget { relays: string[]; authors?: string[] }

/** Hydrate cached packs, sync history with NIP-77/REQ, and share one live stream. */
export function createPackDirectory(runtime: NostrRuntime, now = Math.floor(Date.now() / 1000), targets$?: Observable<PackSyncTarget[]>) {
  const window$ = new BehaviorSubject({ since: Math.max(0, now - 90 * DAY), until: now });
  const refresh$ = new BehaviorSubject(0);
  const filters = [{ kinds: [FOLLOW_LIST_KIND] }, { kinds: [kinds.EventDeletion], '#k': [String(FOLLOW_LIST_KIND)] }];
  const sources$: Observable<PackSyncTarget[]> = targets$ ?? runtime.relayPolicy.readRelays$.pipe(map((relays) => [{ relays }]));
  const state$ = new Observable<PackDirectoryState>((observer) => {
    const scope = new Subscription();
    let state: PackDirectoryState = { since: window$.value.since, loading: true, hydrated: false };
    const emit = (patch: Partial<PackDirectoryState>) => { state = { ...state, ...patch }; observer.next(state); };
    observer.next(state);
    scope.add(sources$.pipe(switchMap((targets) => merge(...targets.map(({ relays, authors }) =>
      runtime.pool.subscription(relays, filters.map((filter) => ({ ...filter, ...(authors ? { authors } : {}), since: Math.max(0, now - 60) }))).pipe(
        // A failed outbox must not terminate live coverage from healthy relays.
        retry({ delay: 5000 })
      )
    )))).subscribe({
      next: (event) => runtime.eventStore.add(event),
      // Historical sync owns user-facing failure reporting.
      error: () => {}
    }));
    scope.add(combineLatest([sources$, window$, refresh$]).pipe(
      switchMap(([targets, window]) => new Observable<PackDirectoryState>((run) => {
        const work = new Subscription();
        run.next({ since: window.since, loading: true, hydrated: false });
        const jobs = targets.flatMap(({ relays, authors }) => filters.map((filter) => ({ relays, filter: { ...filter, ...(authors ? { authors } : {}), ...window } })));
        const queries = jobs.map(({ filter }) => filter);
        void runtime.hydrate(queries).catch(() => {}).then(() => {
          if (work.closed) return;
          if (!jobs.length) { run.next({ since: window.since, loading: false, hydrated: true }); return; }
          work.add(from(jobs).pipe(
            mergeMap(({ relays, filter }, index) => runtime.syncLoader({ relays, filter, timeout: 8000, waitForAuth: false }).status$.pipe(
              startWith<SyncLoaderStatus | undefined>(undefined),
              catchError(() => of<SyncLoaderStatus>({ done: true, loaded: 0, relays: {} })),
              map((status) => ({ index, status }))
            ), 10),
            scan((statuses, { index, status }) => { statuses.set(index, status); return statuses; }, new Map<number, SyncLoaderStatus | undefined>())
          ).subscribe({ next: (statuses) => {
            const settled = statuses.size === jobs.length && [...statuses.values()].every((status) => status?.done);
            const failed = settled && [...statuses.values()].every((status) => accountRefreshFailed(status!));
            run.next({ since: window.since, loading: !settled, hydrated: true,
              warning: failed ? 'Unable to load packs. Please retry.' : undefined });
          }, error: (error) => run.error(error) }));
        });
        return () => work.unsubscribe();
      }))
    ).subscribe({ next: (next) => emit(next), error: () => emit({ loading: false, warning: 'Unable to refresh packs. Please retry.' }) }));
    return () => scope.unsubscribe();
  }).pipe(
    // Sync counters can update every 250ms; don't rebuild pack views for bookkeeping.
    distinctUntilChanged((a, b) => a.since === b.since && a.loading === b.loading && a.hydrated === b.hydrated && a.warning === b.warning),
    takeUntil(runtime.destroyed$), shareReplay({ bufferSize: 1, refCount: true })
  );
  return { state$, window$,
    loadOlder() { window$.next({ ...window$.value, since: Math.max(0, window$.value.since - 365 * DAY) }); },
    retry() { refresh$.next(refresh$.value + 1); }
  };
}
export type PackDirectory = ReturnType<typeof createPackDirectory>;
const directories = new WeakMap<NostrRuntime, PackDirectory>();
export function getPackDirectory(runtime: NostrRuntime, now?: number) {
  let directory = directories.get(runtime);
  if (!directory) { directory = createPackDirectory(runtime, now); directories.set(runtime, directory); }
  return directory;
}
