/** A successful empty response is enough: only total relay failure warrants a warning. */
export function accountRefreshFailed(status: {
  done: boolean;
  loaded: number;
  relays: Record<string, { state: string; count: number }>;
}): boolean {
  const relays = Object.values(status.relays);
  return status.done && status.loaded === 0 && !relays.some((relay) => relay.state === 'complete' || relay.count > 0);
}
