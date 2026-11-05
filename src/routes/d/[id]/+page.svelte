<script lang="ts">
  import { packHref, packRelayHints, resolvePackLink } from '$lib/nostr/protocol/pack-link';
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import { user, followUsers } from '$lib/stores/user';
  import { observePack, type PackDetailState } from '$lib/features/packs/detail';
  import type { NostrRuntime } from '$lib/nostr/runtime';
  import type { Subscription } from 'rxjs';
  import { getRelativeTime } from '$lib/utils/date';
  import { npubEncode } from 'applesauce-core/helpers';
  import PostTimeline from '$lib/components/PostTimeline.svelte';
  import MemberRow from '$lib/components/MemberRow.svelte';
  import ReactiveProfile from '$lib/components/ReactiveProfile.svelte';
  import CopyEvent from '$lib/components/CopyEvent.svelte';
  let runtime: NostrRuntime | undefined;
  let state: PackDetailState = { pack: null, candidates: [], loading: true };
  let activeTab = 'people';
  let followingAll = false;
  let message = '';
  let linkHints: string[] = [];
  onMount(() => {
    let disposed = false;
    let detail: Subscription | undefined;
    let stopPage: (() => void) | undefined;
    void import('$lib/nostr/runtime.client').then(({ getNostrRuntime }) => getNostrRuntime()).then((value) => {
      if (disposed) return;
      runtime = value;
      stopPage = page.subscribe((route) => {
        detail?.unsubscribe();
        state = { pack: null, candidates: [], loading: true };
        try { linkHints = resolvePackLink(route.params.id || '').relays; } catch { linkHints = []; }
        detail = observePack(value, route.params.id || '', route.url.searchParams.get('p') || undefined).subscribe((next) => state = next);
      });
    }).catch(() => { if (!disposed) state = { pack: null, candidates: [], loading: false, error: 'Unable to load this pack' }; });
    return () => { disposed = true; detail?.unsubscribe(); stopPage?.(); };
  });
  async function followAll() {
    if (!state.pack || followingAll) return;
    followingAll = true; message = '';
    try { await followUsers(state.pack.entries.map((entry) => entry.pubkey)); message = 'Follow list updated.'; }
    catch (error) { message = error instanceof Error ? error.message : 'Could not update follows'; }
    finally { followingAll = false; }
  }
</script>
<svelte:head>
  <title>Following._ {state.pack?.name || 'Nostr Follow Pack'}</title>
  <meta name="description" content={state.pack?.description || 'A Nostr Follow Pack'} />
</svelte:head>
<div class="container py-10 max-w-[800px]">
  {#if state.loading}<p class="p-8 text-muted-foreground">Loading follow pack…</p>
  {:else if state.candidates.length}
    <h1 class="text-2xl font-bold mb-4">Choose the pack's author</h1>
    <ul>{#each state.candidates as pack}<li class="p-4"><a class="text-accent underline" href={packHref(pack, packRelayHints(runtime, pack, linkHints))}>{pack.name} · {pack.pubkey.slice(0, 16)}…</a></li>{/each}</ul>
  {:else if !state.pack}
    <h1 class="text-2xl font-bold">Follow Pack Not Found</h1><p class="my-4">{state.error || 'This pack does not exist or has been deleted.'}</p><a href="/" class="btn btn-primary">Back to Home</a>
  {:else}
    {@const pack = state.pack}
    {#if state.error}<p role="status" class="mb-4 text-warning">{state.error}</p>{/if}
    {#if pack.coverImageUrl}<img src={pack.coverImageUrl} alt={pack.name} class="w-full h-60 object-cover rounded-lg mb-6" />{/if}
    <h1 class="text-3xl font-bold mb-4">{pack.name}</h1>
    <a href={'https://njump.me/' + npubEncode(pack.pubkey)} target="_blank" rel="noopener noreferrer" class="flex gap-2 items-center mb-3">
      {#if runtime}<ReactiveProfile {runtime} pubkey={pack.pubkey} showName size="sm" />{/if}
    </a>
    <p class="text-sm text-muted-foreground mb-3">{getRelativeTime(pack.createdAt)} · {pack.entries.length} users</p>
    <div class="flex flex-wrap gap-2 mb-6"><CopyEvent identifier={pack.id} pubkey={pack.pubkey} relays={packRelayHints(runtime, pack, linkHints)} />
      {#if $user}<button class="btn btn-primary" disabled={followingAll} on:click={followAll}>{followingAll ? 'Following…' : 'Follow All'}</button>{/if}
      {#if $user?.pubkey === pack.pubkey}<a class="btn btn-secondary" href={'/create?edit=' + encodeURIComponent(pack.id) + '&p=' + pack.pubkey}>Edit List</a>{/if}
    </div>
    {#if message}<p role="status" class="p-4 bg-accent-soft mb-4">{message}</p>{/if}
    {#if pack.description}<p class="bg-surface p-6 rounded-lg mb-6 whitespace-pre-wrap">{pack.description}</p>{/if}
    <div class="flex bg-surface rounded-t-lg border-b mb-4">
      <button class="flex-1 p-4 {activeTab === 'people' ? 'font-bold text-accent' : ''}" on:click={() => activeTab = 'people'}>People</button>
      <button class="flex-1 p-4 {activeTab === 'posts' ? 'font-bold text-accent' : ''}" on:click={() => activeTab = 'posts'}>Posts</button>
    </div>
    {#if activeTab === 'people'}<ul class="bg-surface rounded-lg divide-y">{#each pack.entries as entry}{#if runtime}<MemberRow {runtime} {entry} />{/if}{/each}</ul>
    {:else}<PostTimeline pubkeys={pack.entries.map((entry) => entry.pubkey)} />{/if}
  {/if}
</div>
