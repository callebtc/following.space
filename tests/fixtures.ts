import { finalizeEvent } from 'applesauce-core/helpers';
import { PrivateKeySigner } from 'applesauce-signers';

export const alice = new PrivateKeySigner().key;
export const bob = new PrivateKeySigner().key;
export const NOW = 1_800_000_000;

export function signedPack(options: {
  key?: Uint8Array; identifier?: string; timestamp?: number; title?: string; tags?: string[][]; content?: string;
} = {}) {
  return finalizeEvent({
    kind: 39089, created_at: options.timestamp ?? NOW,
    content: options.content ?? '',
    tags: [['d', options.identifier ?? 'garden'], ['title', options.title ?? 'Garden'], ...(options.tags ?? [])]
  }, options.key ?? alice);
}
