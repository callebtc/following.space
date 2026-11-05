import { OptimisticEventVerifier } from 'applesauce-core';
import { kinds, verifyEvent, type NostrEvent } from 'applesauce-core/helpers';
import { FOLLOW_LIST_KIND, LOOKUP_RELAY_LIST_KIND } from './protocol/kinds';

type EvidenceStorage = { getItem(key: string): string | null; setItem(key: string, value: string): unknown };
type WasmVerifier = { verifyEvent(event: NostrEvent): void };
// These events control identity, routing, pack membership or deletion. Never sample them.
const STRICT_KINDS = new Set<number>([
  kinds.Metadata, kinds.Contacts, kinds.EventDeletion, kinds.RelayList,
  kinds.BlossomServerList, LOOKUP_RELAY_LIST_KIND, kinds.BlobsAuth, FOLLOW_LIST_KIND
]);

export function createAppVerifier(storage?: EvidenceStorage, loadWasm: () => Promise<WasmVerifier> = async () => {
  const { initNostrWasm } = await import('nostr-wasm');
  return initNostrWasm();
}) {
  let checkSignature: (event: NostrEvent) => boolean = verifyEvent;
  const ready = loadWasm().then((wasm) => {
    checkSignature = (event: NostrEvent) => {
      try { wasm.verifyEvent(event); return true; } catch { return false; }
    };
    return true;
  }).catch(() => false); // JS verification remains active when WASM cannot initialize.
  const optimistic = new OptimisticEventVerifier({ storage, verifyEvent: (event) => checkSignature(event) });
  return { ready, optimistic,
    verifyEvent: (event: NostrEvent) => STRICT_KINDS.has(event.kind) ? checkSignature(event) : optimistic.verifyEvent(event)
  };
}
