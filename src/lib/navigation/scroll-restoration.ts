/** Retry router restoration while asynchronously rendered content grows. */
export function restoreScroll(position: { x: number; y: number }): () => void {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const observer = new ResizeObserver(restore);
  const events = ['wheel', 'touchstart', 'pointerdown', 'keydown'] as const;

  function stop() {
    stopped = true;
    observer.disconnect();
    clearTimeout(timer);
    for (const event of events) window.removeEventListener(event, stop);
  }

  function restore() {
    if (stopped) return;
    window.scrollTo({ left: position.x, top: position.y, behavior: 'instant' });
    if (Math.abs(window.scrollX - position.x) < 1 && Math.abs(window.scrollY - position.y) < 1) stop();
  }

  observer.observe(document.body);
  for (const event of events) window.addEventListener(event, stop, { passive: true });
  // A missing/deleted item must not leave restoration active indefinitely.
  timer = setTimeout(stop, 10_000);
  restore();
  return stop;
}
