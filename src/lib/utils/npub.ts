import { decodeProfilePointer, npubEncode } from 'applesauce-core/helpers';
export function isValidNpub(input: string) { return input.startsWith('npub1') && !!decodeProfilePointer(input); }
export async function npubToHex(input: string) { return decodeProfilePointer(input)?.pubkey ?? null; }
export async function hexToNpub(hex: string) { try { return npubEncode(hex); } catch { return null; } }
export function isValidNprofile(input: string) { return input.startsWith('nprofile1') && !!decodeProfilePointer(input); }
export async function nprofileToNpubAndRelays(input: string) {
  const pointer = decodeProfilePointer(input);
  if (!pointer) throw new Error('Invalid profile pointer');
  return { npub: npubEncode(pointer.pubkey), relays: pointer.relays ?? [] };
}
