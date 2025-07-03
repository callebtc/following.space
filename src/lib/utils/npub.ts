import { nip19 } from 'nostr-tools';
import { NostrTypeGuard, type ProfilePointer } from 'nostr-tools/nip19';

// Debug logging configuration
const DEBUG = true;
const logDebug = (...args: any[]) => {
    if (DEBUG) console.log('[Npub Utils]', ...args);
};

/**
 * Check if a string looks like a nostr npub 
 */
export function isValidNpub(input: string): boolean {
    return NostrTypeGuard.isNPub(input);
}

/**
 * Convert npub to hex pubkey
 */
export function npubToHex(npub: string): string | null {
    // logDebug('Converting npub to hex:', npub);
    try {
        if (!isValidNpub(npub)) {
            logDebug('Invalid npub format');
            return null;
        }

        // Use nostr-tools bech32 conversion
        const { data } = nip19.decode(npub);
        // logDebug('Converted to hex:', data);
        return data as string;
    } catch (error) {
        console.error('Error converting npub to hex:', error);
        logDebug('Conversion error:', error);
        return null;
    }
}

/**
 * Convert hex pubkey to npub
 */
export async function hexToNpub(hex: string): Promise<string | null> {
    // logDebug('Converting hex to npub:', hex);
    try {
        // Use nostr-tools bech32 conversion
        const npub = nip19.npubEncode(hex);
        // logDebug('Converted to npub:', npub);
        return npub;
    } catch (error) {
        console.error('Error converting hex to npub:', error);
        logDebug('Conversion error:', error);
        return null;
    }
}

export function isValidNprofile(input: string): boolean {
    return NostrTypeGuard.isNProfile(input);
}

/**
 * Convert npub to hex pubkey
 */
export async function nprofileToNpubAndRelays(nprofile: string): Promise<{ npub: string, relays: string[] }> {
    if (!isValidNprofile(nprofile)) {
        logDebug('Invalid nprofile format');
        throw new Error('Invalid nprofile format');
    }
    logDebug('Converting nprofile to npub and relays:', nprofile);
    // Use nostr-tools bech32 conversion
    const { type, data } = nip19.decode(nprofile);
    logDebug('Converted to npub and relays:', data);
    if (type !== 'nprofile') {
        logDebug('Invalid nprofile format');
        throw new Error('Invalid nprofile format');
    }
    const pointer = data as ProfilePointer
    return {
        npub: nip19.npubEncode(pointer.pubkey),
        relays: pointer.relays || [],
    };
}
