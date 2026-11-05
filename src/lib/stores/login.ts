import { BaseAccount } from 'applesauce-accounts';
import { browser } from '$app/environment';
import { writable } from 'svelte/store';
import { ExtensionAccount, NostrConnectAccount, PrivateKeyAccount } from 'applesauce-accounts/accounts';
import { ExtensionSigner, NostrConnectSigner } from 'applesauce-signers';
import type { IAccount } from 'applesauce-accounts';
import { accounts } from '../nostr/accounts';
import { normalizeRelays, SIGNER_RELAYS } from '../nostr/relay-policy';
import { kinds } from 'applesauce-core/helpers';
import { FOLLOW_LIST_KIND, LOOKUP_RELAY_LIST_KIND } from '../nostr/protocol/kinds';
import { APP_NAME } from '../constants';

export const authNotice = writable('');
export const connectStatus = writable<{ status: 'idle' | 'waiting' | 'connected' | 'error'; message?: string }>({ status: 'idle' });
const LOCAL = 'following:v2:accounts';
const SESSION = 'following:v2:remote-accounts';
const ACTIVE = 'following:v2:active';
const LEGACY = 'nostr-follow-list:login';
// Contacts, deletions, account server/lookup lists, Blossom upload auth, and packs.
const permissions = NostrConnectSigner.buildSigningPermissions([
  kinds.Contacts, kinds.EventDeletion, kinds.BlossomServerList,
  LOOKUP_RELAY_LIST_KIND, kinds.BlobsAuth, FOLLOW_LIST_KIND
]);
let initialized: Promise<boolean> | undefined;
let generation = 0;
let pending: { signer: NostrConnectSigner; controller: AbortController } | undefined;

function save() {
  try {
    // Raw private keys stay in memory. Remote client credentials last only for this browser tab.
    localStorage.setItem(LOCAL, JSON.stringify(accounts.toJSON(true).filter((a) => a.type === 'extension')));
    sessionStorage.setItem(SESSION, JSON.stringify(accounts.toJSON(true).filter((a) => a.type === 'nostr-connect')));
    if (accounts.active) localStorage.setItem(ACTIVE, accounts.active.id);
    else localStorage.removeItem(ACTIVE);
  } catch { /* Login still works without browser storage. */ }
}
function activate(account: IAccount, token: number) {
  if (!/^[0-9a-f]{64}$/i.test(account.pubkey)) throw new Error('Signer returned an invalid public key');
  if (token !== generation) throw new Error('Login cancelled');
  for (const old of accounts.accounts) {
    accounts.removeAccount(old.id);
    if (old instanceof BaseAccount) old.abortQueue(new Error('Account changed'));
    if (old.signer instanceof NostrConnectSigner) void old.signer.close();
  }
  accounts.addAccount(account);
  accounts.setActive(account);
  try { localStorage.removeItem(LEGACY); } catch { /* Optional storage. */ }
  authNotice.set('');
  save();
}
export async function initializeSigner(): Promise<boolean> {
  if (!browser) return false;
  if (initialized) { await initialized; return !!accounts.active; }
  const restorationToken = generation;
  initialized = (async () => {
    const { getNostrRuntime } = await import('../nostr/runtime.client');
    const runtime = await getNostrRuntime();
    NostrConnectSigner.pool = runtime.pool;
    NostrConnectSigner.subscriptionMethod = runtime.pool.subscription.bind(runtime.pool);
    NostrConnectSigner.publishMethod = async (relays, event) => {
      const responses = await runtime.pool.publish(relays, event, { timeout: 8000, retries: 1, reconnect: 1, waitForAuth: false });
      if (!responses.some((response) => response.ok)) throw new Error('The signer relay did not accept the request');
    };
    if (restorationToken !== generation) return false;
    try {
      const saved = [...JSON.parse(localStorage.getItem(LOCAL) || '[]'), ...JSON.parse(sessionStorage.getItem(SESSION) || '[]')];
      accounts.fromJSON(saved.filter((account) => /^[0-9a-f]{64}$/i.test(account?.pubkey || '') && ['extension', 'nostr-connect'].includes(account?.type)), true);
      const active = localStorage.getItem(ACTIVE);
      if (active && accounts.getAccount(active)) accounts.setActive(active);
      if (!accounts.active) {
        const old = JSON.parse(localStorage.getItem(LEGACY) || 'null');
        if (old?.loggedIn) {
          let migrated: IAccount | undefined;
          if (old.method === 'extension') {
            const pubkey = JSON.parse(localStorage.getItem('nostr-follow-list:user') || 'null')?.pubkey;
            migrated = /^[0-9a-f]{64}$/i.test(pubkey || '') ? new ExtensionAccount(pubkey, new ExtensionSigner()) : await ExtensionAccount.fromExtension();
          } else if (old.method === 'nsec' && old.data?.nsec) migrated = PrivateKeyAccount.fromKey(old.data.nsec);
          else authNotice.set('Please pair your remote signer again to finish upgrading your login.');
          if (migrated) activate(migrated, restorationToken);
        }
      }
    } catch { authNotice.set('Saved login could not be restored. Please sign in again.'); }
    accounts.accounts$.subscribe(save);
    accounts.active$.subscribe((account) => {
      save();
    });
    return !!accounts.active;
  })();
  try { return await initialized; } catch { initialized = undefined; return false; }
}
export async function checkNip07Extension() { return browser && !!window.nostr; }
export function cancelNostrConnectAttempt() {
  generation++;
  pending?.controller.abort();
  if (pending) void pending.signer.close();
  pending = undefined;
  connectStatus.set({ status: 'idle' });
}
export async function loginWithExtension() {
  await initializeSigner();
  cancelNostrConnectAttempt();
  const token = generation;
  activate(await ExtensionAccount.fromExtension(), token);
  return true;
}
export async function loginWithNsec(nsec: string) {
  await initializeSigner();
  cancelNostrConnectAttempt();
  activate(PrivateKeyAccount.fromKey(nsec.trim()), generation);
  return true;
}
export async function loginWithBunker(uri: string) {
  await initializeSigner();
  cancelNostrConnectAttempt();
  const token = generation;
  const parsed = NostrConnectSigner.parseBunkerURI(uri.trim());
  const signer = new NostrConnectSigner({ ...parsed, timeout: 15000 });
  pending = { signer, controller: new AbortController() };
  try {
    await signer.connect(parsed.bunkerSecret, permissions);
    const account = new NostrConnectAccount(await signer.getPublicKey(), signer);
    if (token !== generation) throw new Error('Login cancelled');
    pending = undefined;
    activate(account, token);
    return true;
  } catch (error) { await signer.close(); if (token === generation) pending = undefined; throw error; }
}
export async function createNostrConnectSigner(relay?: string) {
  await initializeSigner();
  cancelNostrConnectAttempt();
  const relays = normalizeRelays(relay?.trim() ? [relay.trim()] : SIGNER_RELAYS);
  if (!relays.length) throw new Error('Enter a valid relay URL');
  const signer = new NostrConnectSigner({ relays, timeout: 15000 });
  pending = { signer, controller: new AbortController() };
  connectStatus.set({ status: 'waiting', message: 'Waiting for your signer…' });
  return Object.assign(signer, { nostrConnectUri: signer.getNostrConnectURI({ name: APP_NAME, url: location.origin, permissions }) });
}
export async function loginWithNostrConnect(signer: NostrConnectSigner) {
  if (pending?.signer !== signer) throw new Error('Login cancelled');
  const token = generation;
  const controller = pending.controller;
  const timer = setTimeout(() => controller.abort(), 120000);
  try {
    await signer.waitForSigner(controller.signal);
    controller.signal.throwIfAborted();
    const pubkey = await signer.getPublicKey();
    if (token !== generation) throw new Error('Login cancelled');
    pending = undefined;
    activate(new NostrConnectAccount(pubkey, signer), token);
    connectStatus.set({ status: 'connected' });
    return true;
  } catch (error) { await signer.close(); if (token === generation) pending = undefined; throw error; }
  finally { clearTimeout(timer); }
}
export function logout() {
  cancelNostrConnectAttempt();
  for (const account of accounts.accounts) {
    if (account instanceof BaseAccount) account.abortQueue(new Error('Signed out'));
    if (account.signer instanceof NostrConnectSigner) void account.signer.logout({ timeout: 1500 });
    accounts.removeAccount(account.id);
  }
  accounts.clearActive();
  if (browser) { try { localStorage.removeItem(LEGACY); save(); } catch { /* Optional storage. */ } }
}
