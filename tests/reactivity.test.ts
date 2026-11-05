import { expect, it, vi } from 'vitest';
import { Observable, of } from 'rxjs';
import { observableReadable } from '../src/lib/reactivity/readable';

it('delivers synchronous observable state as the first value without a fallback flash', () => {
  const values: number[] = [];
  const stop = observableReadable(of(42), 0).subscribe((value) => values.push(value));
  expect(values).toEqual([42]);
  stop();
});

it('Svelte subscribers share a source and release it after the final unsubscribe', () => {
  const stop = vi.fn();
  const start = vi.fn(() => stop);
  const store = observableReadable(new Observable<number>(start), 0);
  const a = store.subscribe(() => {});
  const b = store.subscribe(() => {});
  expect(start).toHaveBeenCalledTimes(1);
  a();
  expect(stop).not.toHaveBeenCalled();
  b();
  expect(stop).toHaveBeenCalledTimes(1);
});
