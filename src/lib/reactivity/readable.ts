import { readable, type Readable } from 'svelte/store';
import type { Observable } from 'rxjs';

/**
 * Svelte starts this subscription before delivering the store's first value, so
 * synchronous EventStore emissions replace `initial` before the first render.
 * Feature streams turn errors into state before crossing this boundary.
 */
export function observableReadable<T>(source: Observable<T>, initial: T): Readable<T> {
  return readable(initial, (set) => {
    const subscription = source.subscribe(set);
    return () => subscription.unsubscribe();
  });
}
