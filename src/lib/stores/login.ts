import { writable, get } from 'svelte/store';
import { browser } from '$app/environment';
import {
    NDKNip07Signer,
    NDKPrivateKeySigner,
    NDKNip46Signer,
    NDKEvent,
    NDKSubscription,
    NDKUser
} from '@nostr-dev-kit/ndk';
import type { NDKSigner, NDKEncryptionScheme } from '@nostr-dev-kit/ndk';
import { ndk } from '$lib/nostr/ndk';
import { nip04, nip44 } from 'nostr-tools';
import * as nostrTools from 'nostr-tools';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { FOLLOW_LIST_KIND } from '$lib/types/follow-list';
import { Nip46Broker, makeSecret } from '@welshman/signer';
import type { Nip46ResponseWithResult } from '@welshman/signer';

// Login method types
export enum LoginMethod {
    EXTENSION = 'extension',
    NSEC = 'nsec',
    BUNKER = 'bunker',
    NOSTRCONNECT = 'nostrconnect',
    NONE = 'none'
}

// NIP-46 Request kind (24133)
const NIP46_REQUEST_KIND = 24133;

export interface LoginState {
    method: LoginMethod;
    loggedIn: boolean;
    data?: {
        nsec?: string;
        bunkerUrl?: string;
        nostrconnect?: {
            signer?: string;
        };
    };
}

// Local storage key
const LOGIN_STATE_KEY = 'nostr-follow-list:login';

// Debug logging
const DEBUG = true;
const logDebug = (...args: any[]) => {
    if (DEBUG) console.log('[Login Store]', ...args);
};

// Initialize store with default state
const defaultState: LoginState = {
    method: LoginMethod.NONE,
    loggedIn: false
};

export const loginState = writable<LoginState>(defaultState);

// Connection status for nostrconnect
export const connectStatus = writable<{
    status: 'idle' | 'waiting' | 'connected' | 'error';
    message?: string;
    clientPubkey?: string;
    secret?: string;
    subscription?: NDKSubscription;
}>({
    status: 'idle'
});

// Load login state from localStorage when browser is available
if (browser) {
    const savedState = localStorage.getItem(LOGIN_STATE_KEY);
    if (savedState) {
        try {
            loginState.set(JSON.parse(savedState));
        } catch (error) {
            console.error('Error parsing login state:', error);
        }
    }
}

/**
 * Custom NDK signer adapter for Welshman broker
 */
class WelshmanNDKSigner implements NDKSigner {
    private broker: Nip46Broker;
    public pubkey: string;

    constructor(broker: Nip46Broker, pubkey: string) {
        this.broker = broker;
        this.pubkey = pubkey;
    }

    async user(): Promise<NDKUser> {
        return new NDKUser({ pubkey: this.pubkey });
    }

    get userSync(): NDKUser {
        return new NDKUser({ pubkey: this.pubkey });
    }

    async blockUntilReady(): Promise<NDKUser> {
        // Welshman broker is ready when constructed
        return new NDKUser({ pubkey: this.pubkey });
    }

    async sign(event: NDKEvent): Promise<string> {
        try {
            const signedEvent = await this.broker.signEvent(event.rawEvent());
            return signedEvent.sig;
        } catch (error) {
            console.error('Error signing event with Welshman broker:', error);
            throw error;
        }
    }

    async encrypt(recipient: NDKUser, value: string, scheme?: NDKEncryptionScheme): Promise<string> {
        try {
            return await this.broker.nip44Encrypt(recipient.pubkey, value);
        } catch (error) {
            console.error('Error encrypting with Welshman broker:', error);
            throw error;
        }
    }

    async decrypt(sender: NDKUser, value: string, scheme?: NDKEncryptionScheme): Promise<string> {
        try {
            return await this.broker.nip44Decrypt(sender.pubkey, value);
        } catch (error) {
            console.error('Error decrypting with Welshman broker:', error);
            throw error;
        }
    }

    toPayload(): any {
        return {
            type: 'welshman',
            pubkey: this.pubkey
        };
    }
}

/**
 * Check if a NIP-07 extension is available in the browser
 */
export async function checkNip07Extension(): Promise<boolean> {
    if (typeof window === 'undefined') return false;
    return !!(window as any).nostr;
}

/**
 * Save login state to localStorage
 */
function saveLoginState(state: LoginState) {
    if (!browser) return;

    try {
        localStorage.setItem(LOGIN_STATE_KEY, JSON.stringify(state));
    } catch (error) {
        console.error('Error saving login state:', error);
    }
}

/**
 * Login with NIP-07 browser extension
 */
export async function loginWithExtension(): Promise<boolean> {
    try {
        // Check if extension is available
        if (!(await checkNip07Extension())) {
            throw new Error('NIP-07 extension not found');
        }

        // Create and set NIP-07 signer
        const nip07Signer = new NDKNip07Signer();
        logDebug('Created NIP-07 signer');
        await nip07Signer.blockUntilReady();
        ndk.signer = nip07Signer;
        logDebug('Set NIP-07 signer', ndk.signer);

        // Update login state
        const newState: LoginState = {
            method: LoginMethod.EXTENSION,
            loggedIn: true
        };
        loginState.set(newState);
        saveLoginState(newState);

        return true;
    } catch (error) {
        console.error('Error logging in with extension:', error);
        return false;
    }
}

/**
 * Login with private key (nsec)
 */
export async function loginWithNsec(nsec: string): Promise<boolean> {
    try {
        // Validate nsec format
        if (!nsec.startsWith('nsec1')) {
            throw new Error('Invalid nsec format');
        }

        // Create and set private key signer
        const privateKeySigner = new NDKPrivateKeySigner(nsec);
        logDebug('Created Private Key signer');
        ndk.signer = privateKeySigner;
        logDebug('Set Private Key signer');

        // Update login state - store sanitized data (we don't want to log the actual nsec)
        const newState: LoginState = {
            method: LoginMethod.NSEC,
            loggedIn: true,
            data: { nsec }
        };
        loginState.set(newState);
        saveLoginState(newState);

        return true;
    } catch (error) {
        console.error('Error logging in with nsec:', error);
        return false;
    }
}

/**
 * Login with NIP-46 Bunker
 */
export async function loginWithBunker(bunkerUrl: string): Promise<boolean> {
    // Validate bunker URL format
    if (!bunkerUrl.startsWith('bunker://')) {
        throw new Error('Invalid bunker URL format');
    }

    // Create and set NIP-46 signer
    const nip46Signer = new NDKNip46Signer(ndk, bunkerUrl);
    logDebug('Created NIP-46 signer');
    await nip46Signer.blockUntilReady();
    ndk.signer = nip46Signer;
    logDebug('Set NIP-46 signer');

    // Update login state
    const newState: LoginState = {
        method: LoginMethod.BUNKER,
        loggedIn: true,
        data: { bunkerUrl }
    };
    loginState.set(newState);
    saveLoginState(newState);

    return true;
}

// Welshman-based signer instance for NostrConnect
let welshmanSigner: any = null;
let welshmanBroker: Nip46Broker | null = null;

// Default relays for NostrConnect
const SIGNER_RELAYS = [
    'wss://relay.nsec.app/',
    'wss://relay.primal.net',
    'wss://nos.lol'
];

// NIP-46 permissions
const NIP46_PERMS = `sign_event:${FOLLOW_LIST_KIND},get_public_key,nip44_encrypt,nip44_decrypt`;

export interface NostrConnectResult {
    broker: Nip46Broker;
    url: string;
    clientSecret: string;
}

export async function createNostrConnectConnection(): Promise<NostrConnectResult> {
    const clientSecret = makeSecret();
    const broker = new Nip46Broker({
        clientSecret,
        relays: SIGNER_RELAYS
    });

    const url = await broker.makeNostrconnectUrl({
        perms: NIP46_PERMS,
        name: 'following.space',
        url: window.location.origin,
        image: window.location.origin + '/favicon.png'
    });

    // Store broker for later use
    welshmanBroker = broker;

    return { broker, url, clientSecret };
}

/**
 * Wait for NostrConnect approval and login
 */
export async function waitForNostrConnect(broker: Nip46Broker, url: string, abortController: AbortController): Promise<boolean> {
    try {
        connectStatus.set({
            status: 'waiting',
            message: 'Waiting for connection approval...'
        });

        logDebug('Waiting for NostrConnect approval...');
        const response = await broker.waitForNostrconnect(url, abortController.signal);
        logDebug('NostrConnect response:', response);

        // Get the public key from the broker
        const pubkey = await broker.getPublicKey();
        logDebug('Got pubkey from broker:', pubkey);

        if (pubkey) {
            // Create custom NDK signer adapter
            const welshmanNDKSigner = new WelshmanNDKSigner(broker, pubkey);
            ndk.signer = welshmanNDKSigner;
            logDebug('Set Welshman NDK signer');

            // Store broker info for signing
            welshmanBroker = broker;
            welshmanSigner = { broker, pubkey };

            // Store connection details for persistence
            const newState: LoginState = {
                method: LoginMethod.NOSTRCONNECT,
                loggedIn: true,
                data: {
                    nostrconnect: {
                        signer: JSON.stringify({
                            pubkey,
                            clientSecret: broker.params.clientSecret,
                            signerPubkey: response.event.pubkey,
                            relays: SIGNER_RELAYS
                        })
                    }
                }
            };

            loginState.set(newState);
            saveLoginState(newState);

            connectStatus.set({
                status: 'connected',
                message: 'Successfully connected!'
            });

            return true;
        }

        throw new Error('Failed to get public key from broker');
    } catch (error) {
        logDebug('NostrConnect error:', error);
        connectStatus.set({
            status: 'error',
            message: error instanceof Error ? error.message : 'Connection failed'
        });
        throw error;
    }
}


/**
 * Cancel an active nostrconnect connection attempt
 */
export function cancelNostrConnectAttempt(): void {
    const status = get(connectStatus);

    if (status.subscription) {
        status.subscription.stop();
    }

    connectStatus.set({
        status: 'idle'
    });
}

/**
 * Generate a random string of specified length
 */
function generateRandomString(length: number): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

/**
 * Initialize signer based on saved login state
 */
export async function initializeSigner(): Promise<boolean> {
    if (!browser) {
        return false;
    }

    // Get the current login state
    const state = get(loginState);
    logDebug('Initializing signer with state:', state);

    // If not logged in according to store, check localStorage as a backup
    if (!state.loggedIn) {
        const savedState = localStorage.getItem(LOGIN_STATE_KEY);
        if (savedState) {
            try {
                const parsedState = JSON.parse(savedState);
                if (parsedState.loggedIn) {
                    loginState.set(parsedState);
                    logDebug('Restored login state from localStorage:', parsedState);
                    // Continue with the restored state
                    return await initializeSignerFromState(parsedState);
                }
            } catch (error) {
                console.error('Error parsing login state from localStorage:', error);
            }
        }
        return false;
    }

    // If we have a logged in state, initialize the appropriate signer
    return await initializeSignerFromState(state);
}

/**
 * Helper function to initialize signer from a specific state
 */
async function initializeSignerFromState(state: LoginState): Promise<boolean> {
    if (!state.loggedIn) {
        return false;
    }

    try {
        switch (state.method) {
            case LoginMethod.EXTENSION:
                return await loginWithExtension();

            case LoginMethod.NSEC:
                if (state.data?.nsec) {
                    return await loginWithNsec(state.data.nsec);
                }
                break;

            case LoginMethod.BUNKER:
                if (state.data?.bunkerUrl) {
                    return await loginWithBunker(state.data.bunkerUrl);
                }
                break;

                        case LoginMethod.NOSTRCONNECT:
                if (state.data?.nostrconnect) {
                    const { signer } = state.data.nostrconnect;
                    if (signer) {
                        // Restore welshman broker from saved state
                        try {
                            const signerData = JSON.parse(signer);
                            const broker = new Nip46Broker({
                                clientSecret: signerData.clientSecret,
                                relays: signerData.relays || SIGNER_RELAYS
                            });
                            welshmanBroker = broker;
                            welshmanSigner = { broker, pubkey: signerData.pubkey };

                            // Create and set the Welshman NDK signer
                            const welshmanNDKSigner = new WelshmanNDKSigner(broker, signerData.pubkey);
                            ndk.signer = welshmanNDKSigner;
                            logDebug('Restored Welshman NDK signer');

                            connectStatus.set({
                                status: 'connected',
                                message: 'Restored connection'
                            });

                            return true;
                        } catch (error) {
                            console.error('Error restoring NostrConnect state:', error);
                            return false;
                        }
                    }
                }
                break;

            default:
                logDebug('Unknown login method:', state.method);
                return false;
        }
    } catch (error) {
        console.error('Error initializing signer:', error);
        // Reset login state on error
        logout();
        return false;
    }

    return false;
}

/**
 * Log out the current user
 */
export function logout(): void {
    // Clear NDK signer
    ndk.signer = undefined;

    // Reset login state
    loginState.set(defaultState);

    // Clear login state from localStorage
    if (browser) {
        localStorage.removeItem(LOGIN_STATE_KEY);
    }

    logDebug('User logged out');
}

/**
 * Check if user is currently logged in
 */
export function isLoggedIn(): boolean {
    return get(loginState).loggedIn;
}