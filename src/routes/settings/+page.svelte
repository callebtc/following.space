<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { user, getFollowSnapshots, restoreFollowSnapshot, type FollowSnapshot } from '$lib/stores/user';
  import { initializeAuth } from '$lib/services/auth';

  import { getNostrRuntime } from '$lib/nostr/runtime.client';
  import { APP_RELAYS } from '$lib/nostr/relay-policy';
  import { normalizeLookupRelays, publishLookupRelays } from '$lib/nostr/lookup-relays';

  import ServerFavicon from '$lib/components/ServerFavicon.svelte';
  import { DEFAULT_BLOSSOM_SERVERS, normalizeBlossomServers } from '$lib/features/media/blossom';
  import { observeResolvedBlossomServers, publishBlossomServers } from '$lib/features/media/servers';
  import { accounts } from '$lib/nostr/accounts';
  import { Subscription } from 'rxjs';
  let blossomServers: string[] = [];
  let newBlossomServer = '';
  let blossomMessage = '';
  let blossomError = '';
  let blossomAccount = '';
  let blossomLoading = true;
  let blossomSaving = false;
  let blossomSubscription: Subscription | undefined;
  let destroyed = false;
  onDestroy(() => { destroyed = true; blossomSubscription?.unsubscribe(); });
  $: if (($user?.pubkey ?? '') !== blossomAccount) {
    blossomAccount = $user?.pubkey ?? '';
    void refreshMediaServers(blossomAccount);
  }
  async function refreshMediaServers(pubkey: string) {
    blossomSubscription?.unsubscribe();
    blossomServers = []; newBlossomServer = ''; blossomMessage = ''; blossomError = ''; blossomLoading = true;
    if (!pubkey) { blossomLoading = false; return; }
    try {
      const runtime = await getNostrRuntime();
      if (destroyed || blossomAccount !== pubkey) return;
      blossomSubscription = observeResolvedBlossomServers(runtime, pubkey).subscribe({
        next: (servers) => { blossomServers = servers; blossomLoading = false; },
        error: (error) => { blossomError = error instanceof Error ? error.message : 'Could not load media servers.'; blossomLoading = false; }
      });
    } catch (error) {
      if (blossomAccount === pubkey) { blossomError = error instanceof Error ? error.message : 'Could not load media servers.'; blossomLoading = false; }
    }
  }
  async function saveMediaServers(values: string[]) {
    if (blossomLoading || blossomSaving) return false;
    blossomMessage = ''; blossomError = ''; blossomSaving = true;
    const account = accounts.active;
    try {
      if (!account) throw new Error('Sign in first');
      const servers = await publishBlossomServers(await getNostrRuntime(), account.pubkey,
        values,
        (draft) => account.signEvent(draft), () => accounts.active === account);
      if (accounts.active === account) {
        blossomServers = servers;
        blossomMessage = 'Media servers saved.';
        return true;
      }
    } catch (error) { blossomError = error instanceof Error ? error.message : 'Could not save media servers.'; }
    finally { blossomSaving = false; }
    return false;
  }
  async function addMediaServer() {
    if (blossomLoading || blossomSaving) return;
    blossomError = ''; blossomMessage = '';
    try {
      const [server] = normalizeBlossomServers([newBlossomServer]);
      if (blossomServers.includes(server)) throw new Error('This server is already in your list.');
      if (await saveMediaServers([...blossomServers, server])) newBlossomServer = '';
    } catch (error) { blossomError = error instanceof Error ? error.message : 'Could not add server.'; }
  }

  let appRelays: string[] = [];
  let newAppRelay = '';
  let appRelayLoading = true;
  let appRelaySaving = false;
  let appRelayError = '';

  async function saveAppRelays(values: string[]) {
    if (appRelayLoading || appRelaySaving) return false;
    appRelaySaving = true; appRelayError = '';
    try {
      const runtime = await getNostrRuntime();
      runtime.setAppRelays(values);
      return true;
    } catch (error) {
      appRelayError = error instanceof Error ? error.message : 'Could not save app relays.';
      return false;
    } finally { appRelaySaving = false; }
  }

  async function addAppRelay() {
    appRelayError = '';
    try {
      const [relay] = normalizeLookupRelays([newAppRelay]);
      if (appRelays.includes(relay)) throw new Error('Relay already added.');
      if (await saveAppRelays([...appRelays, relay])) newAppRelay = '';
    } catch (error) { appRelayError = error instanceof Error ? error.message : 'Could not add relay.'; }
  }

  let lookupRelays: string[] = [];
  let newLookupRelay = '';
  let relayLoading = true;
  let relaySaving = false;
  let relayError = '';
  let stopRelaySettings: (() => void) | undefined;
  onDestroy(() => stopRelaySettings?.());

  async function saveLookupRelays(values: string[]) {
    if (relayLoading || relaySaving) return false;
    relayError = ''; relaySaving = true;
    const account = accounts.active;
    try {
      const runtime = await getNostrRuntime();
      const next = normalizeLookupRelays(values);
      if (account) {
        await publishLookupRelays(runtime, account.pubkey, next,
          (draft) => account.signEvent(draft), () => accounts.active === account);
      } else {
        if (accounts.active) throw new Error('Account changed. Please retry.');
        runtime.setLookupRelays(next);
      }
      if (accounts.active === account) { lookupRelays = next; return true; }
    } catch (error) {
      if (accounts.active === account) relayError = error instanceof Error ? error.message : 'Could not save lookup relays.';
    } finally { relaySaving = false; }
    return false;
  }

  async function addLookupRelay() {
    if (relayLoading || relaySaving) return;
    relayError = '';
    try {
      const [relay] = normalizeLookupRelays([newLookupRelay]);
      if (lookupRelays.includes(relay)) throw new Error('Relay already added.');
      if (await saveLookupRelays([...lookupRelays, relay])) newLookupRelay = '';
    } catch (error) { relayError = error instanceof Error ? error.message : 'Could not add relay.'; }
  }

  // Format date
  function formatDate(timestamp: number): string {
    return new Date(timestamp).toLocaleString();
  }

  let snapshots: FollowSnapshot[] = [];
  let loading = true;
  let restoring = false;
  let restoringId = '';
  let message = '';
  let messageType = '';

  onMount(() => {
    void (async () => {
      const runtime = await getNostrRuntime();
      if (destroyed) return;
      const app = runtime.relayPolicy.appRelays$.subscribe((relays) => { appRelays = relays; });
      appRelayLoading = false;
      const active = runtime.relayPolicy.lookupRelays$.subscribe((relays) => { lookupRelays = relays; });
      const account = runtime.relayPolicy.account$.subscribe((state) => {
        relayLoading = !!accounts.active && (state.pubkey !== accounts.active.pubkey || state.loading);
      });
      const identity = accounts.active$.subscribe(() => {
        newLookupRelay = ''; relayError = '';
        snapshots = getFollowSnapshots();
      });
      stopRelaySettings = () => { app.unsubscribe(); active.unsubscribe(); account.unsubscribe(); identity.unsubscribe(); };
      snapshots = getFollowSnapshots();
      loading = false;
      await initializeAuth();
    })().catch((error) => { relayError = error instanceof Error ? error.message : 'Could not load settings.'; });
  });

  // Handle restore snapshot
  async function handleRestore(snapshot: FollowSnapshot) {
    if (restoring) return;

    restoring = true;
    restoringId = snapshot.eventId;
    messageType = '';
    message = '';

    try {
      const success = await restoreFollowSnapshot(snapshot);

      if (success) {
        messageType = 'success';
        message = `Successfully restored ${snapshot.count} follows from ${formatDate(snapshot.timestamp)}`;

        // Refresh snapshots list
        snapshots = getFollowSnapshots();
      } else {
        messageType = 'error';
        message = 'Failed to restore follow list';
      }
    } catch (err) {
      console.error('Error restoring snapshot:', err);
      messageType = 'error';
      message = `Error: ${err instanceof Error ? err.message : 'Unknown error'}`;
    } finally {
      restoring = false;
      restoringId = '';

      // Auto-hide message after 5 seconds
      if (message) {
        setTimeout(() => {
          message = '';
        }, 5000);
      }
    }
  }

  // Export snapshot as JSON
  function exportSnapshot(snapshot: FollowSnapshot) {
    const dataStr = JSON.stringify(snapshot, null, 2);
    const dataUri = `data:application/json;charset=utf-8,${encodeURIComponent(dataStr)}`;

    const exportFileDefaultName = `follow-snapshot-${new Date(snapshot.timestamp).toISOString().split('T')[0]}.json`;

    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  }
</script>

<div class="container py-10">
  <div class="max-w-3xl mx-auto">
    <div class="flex justify-between items-center mb-8">
      <h1 class="text-3xl font-bold text-foreground">Settings</h1>
      <a href="/" class="btn btn-secondary">Back to Home</a>
    </div>

      {#if message}
        <div class="bg-{messageType === 'success' ? 'green' : 'red'}-50 border border-{messageType === 'success' ? 'green' : 'red'}-200 rounded-md p-4 mb-6 text-{messageType === 'success' ? 'green' : 'red'}-700">
          {message}
        </div>
      {/if}

      <section class="bg-surface shadow-sm rounded-lg p-6 mb-8 border border-line">
        <div class="flex items-center justify-between gap-3 mb-4">
          <h2 class="text-xl font-medium">App relays</h2>
          <span class="text-xs text-muted-foreground">This device</span>
        </div>
        <p class="mb-4 text-sm text-muted-foreground">Choose the relays used to discover follow packs. Saved on this device for signed-in and signed-out browsing. Your account’s read relays are also used when signed in.</p>
        {#if appRelayLoading}
          <p role="status" class="py-4 text-muted-foreground">Loading relays…</p>
        {:else}
          <ul aria-label="App relays" aria-busy={appRelaySaving}>
            {#each appRelays as relay (relay)}
              <li class="flex flex-wrap items-center gap-3 py-2">
                <ServerFavicon server={relay.replace(/^ws/, 'http')} />
                <div class="min-w-0 flex-1">
                  <a href={relay.replace(/^ws/, 'http')} target="_blank" rel="noopener noreferrer" class="font-medium break-all hover:underline">{new URL(relay).host}{new URL(relay).pathname.replace(/\/$/, '')}{new URL(relay).search}</a>
                </div>
                <button type="button" class="p-1 text-muted-foreground hover:text-danger focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-40" disabled={appRelaySaving || appRelays.length === 1} aria-label={'Remove ' + new URL(relay).host} title={appRelays.length === 1 ? 'Keep at least one relay' : 'Remove relay'} on:click={() => saveAppRelays(appRelays.filter((value) => value !== relay))}>
                  <svg aria-hidden="true" class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M6 6l12 12M6 18L18 6" /></svg>
                </button>
              </li>
            {/each}
          </ul>
        {/if}
        <form class="mt-3" on:submit|preventDefault={addAppRelay}>
          <label for="app-relay" class="block text-sm font-medium mb-2">Add a relay</label>
          <div class="flex flex-col sm:flex-row gap-2">
            <input id="app-relay" type="text" bind:value={newAppRelay} disabled={appRelayLoading || appRelaySaving} spellcheck="false" autocapitalize="none" autocomplete="off" placeholder="relay.example.com" class="min-w-0 flex-1 rounded-md border border-line bg-surface px-3 py-2" />
            <button type="submit" class="btn btn-primary" disabled={appRelayLoading || appRelaySaving || !newAppRelay.trim()}>Add relay</button>
          </div>
        </form>
        <button type="button" class="mt-3 text-sm text-muted-foreground underline hover:text-foreground disabled:opacity-40" disabled={appRelayLoading || appRelaySaving} on:click={() => saveAppRelays(APP_RELAYS)}>Restore default relays</button>
        {#if appRelaySaving}<p role="status" class="mt-3 text-sm text-muted-foreground">Saving…</p>{/if}
        {#if appRelayError}<p role="alert" class="mt-3 text-warning">{appRelayError}</p>{/if}
      </section>

      <section class="bg-surface shadow-sm rounded-lg p-6 mb-8 border border-line">
        <div class="flex items-center justify-between gap-3 mb-4">
          <h2 class="text-xl font-medium">Lookup relays</h2>
          <span class="text-xs text-muted-foreground">{$user ? 'Your account' : 'This device'}</span>
        </div>
        {#if relayLoading}
          <p role="status" class="py-4 text-muted-foreground">Loading relays…</p>
        {:else}
          <ul aria-label="Lookup relays" aria-busy={relaySaving}>
            {#each lookupRelays as relay (relay)}
              <li class="flex flex-wrap items-center gap-3 py-2">
                <ServerFavicon server={relay.replace(/^ws/, 'http')} />
                <div class="min-w-0 flex-1">
                  <a href={relay.replace(/^ws/, 'http')} target="_blank" rel="noopener noreferrer" class="font-medium break-all hover:underline">{new URL(relay).host}{new URL(relay).pathname.replace(/\/$/, '')}{new URL(relay).search}</a>
                </div>
                <button type="button" class="p-1 text-muted-foreground hover:text-danger focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-40" disabled={relaySaving || lookupRelays.length === 1} aria-label={'Remove ' + new URL(relay).host} title={lookupRelays.length === 1 ? 'Keep at least one relay' : 'Remove relay'} on:click={() => saveLookupRelays(lookupRelays.filter((value) => value !== relay))}>
                  <svg aria-hidden="true" class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M6 6l12 12M6 18L18 6" /></svg>
                </button>
              </li>
            {/each}
          </ul>
        {/if}
        <form class="mt-3" on:submit|preventDefault={addLookupRelay}>
          <label for="lookup-relay" class="block text-sm font-medium mb-2">Add a relay</label>
          <div class="flex flex-col sm:flex-row gap-2">
            <input id="lookup-relay" type="text" bind:value={newLookupRelay} disabled={relayLoading || relaySaving} spellcheck="false" autocapitalize="none" autocomplete="off" placeholder="relay.example.com" class="min-w-0 flex-1 rounded-md border border-line bg-surface px-3 py-2" />
            <button type="submit" class="btn btn-primary" disabled={relayLoading || relaySaving || !newLookupRelay.trim()}>Add relay</button>
          </div>
        </form>
        {#if relaySaving}<p role="status" class="mt-3 text-sm text-muted-foreground">Saving…</p>{/if}
        {#if relayError}<p role="alert" class="mt-3 text-warning">{relayError}</p>{/if}
      </section>

      {#if $user}
      <section class="bg-surface shadow-sm rounded-lg p-6 mb-8 border border-line">
        <h2 class="text-xl font-medium mb-2">Blossom media servers</h2>
        {#if blossomLoading}
          <div role="status" class="py-2 text-sm text-muted-foreground">Loading your media servers…</div>
        {:else if blossomServers.length === 0}
          <div class="py-2">
            <p class="font-medium">No media servers yet</p>
            <p class="mt-1 text-sm text-muted-foreground">Add a server below to upload pack images.</p>
          </div>
        {:else}
          <ul aria-label="Media servers" aria-busy={blossomSaving}>
            {#each blossomServers as server, index (server)}
              <li class="flex flex-wrap items-center gap-3 py-2">
                <ServerFavicon {server} />
                <div class="min-w-0 flex-1">
                  <div class="flex flex-wrap items-center gap-2">
                    <a href={server} target="_blank" rel="noopener noreferrer" class="font-medium break-all hover:underline">{new URL(server).host}</a>
                    {#if index === 0}<span class="text-xs text-muted-foreground">Default</span>{/if}
                  </div>
                </div>
                <div class="flex items-center gap-2 ml-auto">
                  {#if index > 0}
                    <button type="button" class="py-1 text-sm text-muted-foreground hover:text-foreground disabled:opacity-40" disabled={blossomSaving} aria-label={'Make ' + new URL(server).host + ' default'} on:click={() => saveMediaServers([server, ...blossomServers.filter((value) => value !== server)])}>Make default</button>
                  {/if}
                  <button type="button" class="p-1 text-muted-foreground hover:text-danger disabled:opacity-40" disabled={blossomSaving || blossomServers.length === 1} aria-label={'Remove ' + new URL(server).host} title={blossomServers.length === 1 ? 'Keep at least one media server' : 'Remove server'} on:click={() => saveMediaServers(blossomServers.filter((value) => value !== server))}>
                    <svg aria-hidden="true" class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M6 6l12 12M6 18L18 6" /></svg>
                  </button>
                </div>
              </li>
            {/each}
          </ul>
        {/if}
        <form class="mt-3" on:submit|preventDefault={addMediaServer}>
          <label for="blossom-server" class="block text-sm font-medium mb-2">Add a media server</label>
          <div class="flex flex-col sm:flex-row gap-2">
            <input id="blossom-server" type="text" bind:value={newBlossomServer} disabled={blossomLoading || blossomSaving} spellcheck="false" autocapitalize="none" autocomplete="off" placeholder="blossom.example.com" class="min-w-0 flex-1 rounded-md border border-line bg-surface px-3 py-2" />
            <button type="submit" class="btn btn-primary" disabled={blossomLoading || blossomSaving || !newBlossomServer.trim()}>Add server</button>
          </div>
        </form>
        <div class="mt-3 flex flex-wrap items-center justify-between gap-3">
          <button type="button" class="text-sm text-muted-foreground underline hover:text-foreground disabled:opacity-40" disabled={blossomLoading || blossomSaving} on:click={() => saveMediaServers(DEFAULT_BLOSSOM_SERVERS)}>Restore default servers</button>
          {#if blossomSaving}<p role="status" class="text-sm text-muted-foreground">Saving media servers…</p>{/if}
        </div>
        {#if blossomMessage}<p role="status" class="mt-3 text-muted-foreground">{blossomMessage}</p>{/if}
        {#if blossomError}<p role="alert" class="mt-3 text-warning">{blossomError}</p>{/if}
      </section>

      <!-- Following Snapshots Section -->
      <div class="bg-surface shadow-sm rounded-lg overflow-hidden mb-8">
        <div class="p-6 border-b">
          <h2 class="text-xl font-medium mb-2">Following Snapshots</h2>
          <p class="text-muted-foreground mb-4">
            These are snapshots of your following list that can be restored if needed.
            We automatically save snapshots whenever your follow list changes.
          </p>

          {#if loading}
            <div class="flex justify-center py-6">
              <div class="animate-spin rounded-full h-6 w-6 border-t-2 border-b-2 border-purple-500"></div>
            </div>
          {:else if snapshots.length === 0}
            <div class="bg-subtle border border-line rounded-md p-4 text-center text-muted-foreground">
              No snapshots available yet. Snapshots are saved automatically when you follow users.
            </div>
          {:else}
            <div class="grid gap-4">
              {#each snapshots as snapshot}
                <div class="bg-surface border border-line rounded-lg p-4 shadow-sm hover:shadow-md transition-shadow">
                  <div class="flex flex-col sm:flex-row sm:justify-between sm:items-center">
                    <div class="mb-3 sm:mb-0">
                      <div class="text-sm font-medium text-muted-foreground">Date</div>
                      <div class="text-foreground">{formatDate(snapshot.timestamp)}</div>
                    </div>
                    <div class="mb-3 sm:mb-0">
                      <div class="text-sm font-medium text-muted-foreground">Following</div>
                      <div class="text-foreground">{snapshot.count} users</div>
                    </div>
                    <div class="flex space-x-3 mt-3 sm:mt-0">
                      <button
                        on:click={() => exportSnapshot(snapshot)}
                        class="px-3 py-1.5 text-sm rounded-md bg-accent-soft text-accent hover:bg-accent-soft/80 transition-colors"
                      >
                        Export
                      </button>
                      <button
                        on:click={() => handleRestore(snapshot)}
                        disabled={restoring}
                        class="px-3 py-1.5 text-sm rounded-md bg-info-soft text-info hover:bg-info-soft/80 transition-colors
                          {restoring && restoringId === snapshot.eventId ? 'opacity-50' : ''}"
                      >
                        {restoring && restoringId === snapshot.eventId ? 'Restoring...' : 'Restore'}
                      </button>
                    </div>
                  </div>
                </div>
              {/each}
            </div>

            <p class="mt-4 text-sm text-muted-foreground">
              Restoring a snapshot will replace your current following list with the selected snapshot.
            </p>
          {/if}
        </div>
      </div>
    {/if}
  </div>
</div>
