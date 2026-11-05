import { browser } from '$app/environment';
import { writable } from 'svelte/store';
import { goto } from '$app/navigation';
import { accounts } from '../nostr/accounts';
import { loadUser } from '../stores/user';
export const initializingAuth = writable(false);
let initialization: Promise<boolean> | undefined;
export async function initializeAuth(callback?: () => void): Promise<boolean> {
  if (!browser) return false;
  if (!initialization) {
    initializingAuth.set(true);
    initialization = loadUser().then(() => !!accounts.active).finally(() => { initialization = undefined; initializingAuth.set(false); });
  }
  const authenticated = await initialization;
  if (authenticated) callback?.();
  return authenticated;
}
export function isAuthenticated() { return !!accounts.active; }
export function getCurrentUserPubkey() { return accounts.active?.pubkey ?? null; }
export async function requireAuth(redirectPath = '/') {
  const authenticated = await initializeAuth();
  if (!authenticated && browser) await goto(redirectPath);
  return authenticated;
}
export async function initOptionalAuth() { await initializeAuth(); }
