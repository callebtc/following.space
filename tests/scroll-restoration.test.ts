import { afterEach, expect, it, vi } from 'vitest';
import { restoreScroll } from '../src/lib/navigation/scroll-restoration';

function setup() {
  vi.useFakeTimers();
  let resize = () => {};
  let height = 100;
  const disconnect = vi.fn();
  const target = new EventTarget();
  const viewport = Object.assign(target, {
    scrollX: 0, scrollY: 0,
    scrollTo: vi.fn(({ left, top }: { left: number; top: number }) => {
      viewport.scrollX = left;
      viewport.scrollY = Math.min(top, height);
    })
  });
  vi.stubGlobal('window', viewport);
  vi.stubGlobal('document', { body: {} });
  vi.stubGlobal('ResizeObserver', class {
    constructor(callback: () => void) { resize = callback; }
    observe() {}
    disconnect = disconnect;
  });
  return { viewport, disconnect, grow: () => { height = 2000; resize(); }, resize: () => resize() };
}

afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

it('retries a clamped history position when async content grows, then stops', () => {
  const { viewport, grow, resize, disconnect } = setup();
  restoreScroll({ x: 0, y: 1200 });
  expect(viewport.scrollY).toBe(100);
  grow();
  expect(viewport.scrollY).toBe(1200);
  expect(disconnect).toHaveBeenCalled();
  resize();
  expect(viewport.scrollTo).toHaveBeenCalledTimes(2);
});

it.each(['wheel', 'touchstart', 'pointerdown', 'keydown'])('stops when the user interacts via %s', (event) => {
  const { viewport, grow } = setup();
  restoreScroll({ x: 0, y: 1200 });
  viewport.dispatchEvent(new Event(event));
  grow();
  expect(viewport.scrollTo).toHaveBeenCalledTimes(1);
});

it('stops on cleanup or timeout if the destination remains too short', () => {
  const { viewport, grow } = setup();
  const stop = restoreScroll({ x: 0, y: 1200 });
  stop();
  grow();
  expect(viewport.scrollTo).toHaveBeenCalledTimes(1);
  restoreScroll({ x: 0, y: 3000 });
  vi.advanceTimersByTime(10_000);
  grow();
  expect(viewport.scrollTo).toHaveBeenCalledTimes(2);
});
