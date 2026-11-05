import { EventStore } from 'applesauce-core';
import { kinds, verifyEvent, type NostrEvent } from 'applesauce-core/helpers';
import { Subject } from 'rxjs';

/**
 * Core handles kind 5 before its normal verification/insertion path. Verify those
 * events here, and expose accepted tombstones for cache persistence as well.
 */
export class AppEventStore extends EventStore {
  readonly deletion$ = new Subject<NostrEvent>();
  private readonly deletionIds = new Set<string>();

  override add(event: NostrEvent, fromRelay?: string): NostrEvent | null {
    if (event.kind !== kinds.EventDeletion) return super.add(event, fromRelay);
    if (this.deletionIds.has(event.id)) return event;
    if (!(this.verifyEvent ?? verifyEvent)(event)) return null;
    this.deletionIds.add(event.id);
    const result = super.add(event, fromRelay);
    this.deletion$.next(event);
    return result;
  }

  override dispose() {
    this.deletion$.complete();
    this.deletionIds.clear();
    super.dispose();
  }
}
