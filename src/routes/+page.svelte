<script lang="ts">
  import { packHref, packRelayHints } from '$lib/nostr/protocol/pack-link';
  import { onMount } from 'svelte';
  import { user, user$ } from '$lib/stores/user';
  import { getNostrRuntime, peekNostrRuntime } from '$lib/nostr/runtime.client';
  import { goto } from '$app/navigation';
  import type { NostrRuntime } from '$lib/nostr/runtime';
  import { createPackFeed, type PackFeedState, type PackFilter } from '$lib/features/packs/feed';
  import type { FollowList } from '$lib/nostr/protocol/follow-pack';
  import { getRelativeTime } from '$lib/utils/date';
  import ReactiveProfile from '$lib/components/ReactiveProfile.svelte';
  import { BehaviorSubject, combineLatest, distinctUntilChanged, map, switchMap } from 'rxjs';
  import { observableReadable } from '$lib/reactivity/readable';

  type FilterType = 'none' | 'follows' | 'included' | 'ours';
  const filterOptions: { value: FilterType; label: string }[] = [
    { value: 'none', label: 'Show all packs' },
    { value: 'follows', label: 'From users I follow' },
    { value: 'included', label: "Packs I'm in" },
    { value: 'ours', label: 'My packs' }
  ];
  let runtime: NostrRuntime | undefined = peekNostrRuntime();
  let followLists: FollowList[] = [];
  let loading = true;
  let loadingMore = false;
  let hasMoreLists = true;
  let warning: string | undefined;
  let filterType: FilterType = 'none';
  let dropdownOpen = false;
  let feed: ReturnType<typeof createPackFeed> | undefined;
  const selectedFilter = new BehaviorSubject<FilterType>('none');
  const initial: PackFeedState = { packs: [], loading: true, since: 0, canLoadOlder: true };
  function restoreFilter() {
    try {
      const saved = localStorage.getItem('filterType');
      if (filterOptions.some((option) => option.value === saved)) filterType = saved as FilterType;
    } catch { /* Storage is optional. */ }
    selectedFilter.next(filterType);
  }

  function createFeedState(value: NostrRuntime) {
    const state$ = combineLatest([selectedFilter, user$]).pipe(
      map(([selected, current]): PackFilter => {
        if (selected === 'none' || !current) return {};
        if (selected === 'included') return { included: [current.pubkey] };
        if (selected === 'ours') return { authors: [current.pubkey] };
        return { authors: [...current.following].sort(), contactOutboxes: true };
      }),
      distinctUntilChanged((a, b) => JSON.stringify(a) === JSON.stringify(b)),
      switchMap((filter) => {
        feed = createPackFeed(value, filter);
        return feed.state$;
      })
    );
    return observableReadable(state$, initial);
  }

  // Client-side revisits can render the EventStore's synchronous result immediately.
  // On a cold load, keep the SSR-compatible initial state until the browser mounts.
  if (runtime) restoreFilter();
  let feedState = runtime ? createFeedState(runtime) : observableReadable(new BehaviorSubject(initial), initial);
  $: currentFilterLabel = filterOptions.find((option) => option.value === filterType)?.label || 'Show all packs';
  $: followLists = $feedState.packs;
  $: loading = $feedState.loading && followLists.length === 0;
  $: loadingMore = $feedState.loading && followLists.length > 0;
  $: hasMoreLists = $feedState.canLoadOlder;
  $: warning = $feedState.warning;

  onMount(() => {
    let disposed = false;
    const closeDropdown = (event: MouseEvent) => {
      if (!(event.target as HTMLElement).closest('#filter-dropdown')) dropdownOpen = false;
    };
    window.addEventListener('click', closeDropdown);
    if (!runtime) {
      restoreFilter();
      void getNostrRuntime().then((value) => {
        if (disposed) return;
        runtime = value;
        feedState = createFeedState(value);
      }).catch(() => {
        if (!disposed) feedState = observableReadable(new BehaviorSubject({
          ...initial, loading: false, warning: 'Unable to start pack loading. Please reload to retry.'
        }), initial);
      });
    }
    return () => {
      disposed = true;
      window.removeEventListener('click', closeDropdown);
    };
  });

  function handleCreateClick() { goto('/create'); }
  function loadMore() { feed?.loadMore(); }
  function handleFilterChange() {
    try { localStorage.setItem('filterType', filterType); } catch { /* Storage is optional. */ }
    selectedFilter.next(filterType);
  }
  function retry() { feed?.retry(); }
</script>

<svelte:head>
  <title>Following._ Nostr Follow Packs</title>
</svelte:head>

<div class="container py-10">
  <!-- Hero section -->
  <div class="text-center mb-12">
    <h1 class="text-4xl font-bold text-foreground mb-4">Nostr Follow Packs</h1>
    <p class="text-xl text-muted-foreground max-w-2xl mx-auto">
      Discover and share curated lists of Nostr users to follow. Find the users that are most interesting to you or create your own lists.
    </p>
    
    <div class="mt-8">
      <button 
        on:click={handleCreateClick}
        class="btn btn-primary text-lg px-6 py-3 {!$user ? 'btn-disabled' : ''}"
        disabled={!$user}
      >
        Create New Follow Pack
      </button>
      
      {#if !$user}
        <p class="text-sm text-muted-foreground mt-4">Please log in to create a follow pack or to filter packs.</p>
      {/if}
    </div>
  </div>

  <!-- Browse section -->
  <div class="mt-16">
    <!-- Filter section (moved to top right) -->
    {#if $user}
      <div class="flex justify-end mb-6">
        <div class="relative" id="filter-dropdown">
          <button 
            class="appearance-none bg-surface border border-line rounded-md pl-4 pr-10 py-3 text-muted-foreground hover:bg-subtle focus:outline-none focus:ring-2 focus:ring-purple-300 focus:border-transparent transition-all min-w-[180px] font-medium text-sm flex items-center justify-between"
            on:click|stopPropagation={() => dropdownOpen = !dropdownOpen}
          >
            <span>{currentFilterLabel}</span>
            <div class="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-muted-foreground">
              <svg class="h-4 w-4 fill-current" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
                <path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" />
              </svg>
            </div>
          </button>
          
          {#if dropdownOpen}
            <div class="absolute mt-1 w-full bg-surface border border-line rounded-md shadow-lg z-10">
              {#each filterOptions as option}
                <button 
                  class="w-full text-left px-4 py-3 text-muted-foreground hover:bg-subtle transition-colors {filterType === option.value ? 'bg-accent-soft text-accent' : ''}"
                  on:click|stopPropagation={() => {
                    filterType = option.value;
                    dropdownOpen = false;
                    handleFilterChange();
                  }}
                >
                  {option.label}
                </button>
              {/each}
            </div>
          {/if}
        </div>
      </div>
    {/if}
    
    {#if warning}
      <div role="status" class="mb-6 rounded-lg bg-warning-soft p-4 text-warning">
        {warning} <button class="underline" on:click={retry}>Retry</button>
      </div>
    {/if}
    {#if loading}
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {#each Array(6) as _, i}
          <div class="bg-surface rounded-lg shadow-sm overflow-hidden animate-pulse">
            <!-- Skeleton cover image -->
            <div class="h-36 bg-placeholder"></div>
            
            <!-- Skeleton content -->
            <div class="p-4">
              <div class="h-5 bg-placeholder rounded w-3/4 mb-2"></div>
              
              <!-- Skeleton author info -->
              <div class="flex items-center mb-3">
                <div class="w-5 h-5 rounded-full bg-placeholder mr-2"></div>
                <div class="h-4 bg-placeholder rounded w-1/3"></div>
              </div>
              
              <!-- Skeleton user avatars -->
              <div class="flex -space-x-2 overflow-hidden mt-4">
                {#each Array(5) as _, j}
                  <div class="w-8 h-8 rounded-full bg-placeholder border-2 border-surface"></div>
                {/each}
              </div>
              
              <div class="h-4 bg-placeholder rounded w-1/2 mt-2"></div>
            </div>
          </div>
        {/each}
      </div>
    {:else if followLists.length === 0}
      <div class="bg-surface p-8 rounded-lg shadow-sm text-center">
        <p class="text-muted-foreground">No follow packs found in this time range. Try discovering older packs.</p>
      </div>
    {:else}
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {#each followLists as list (`${list.pubkey}:${list.id}`)}
          <a 
            href={packHref(list, packRelayHints(runtime, list))}
            class="bg-surface rounded-lg shadow-sm overflow-hidden transition-transform hover:scale-[1.02]"
          >
            <!-- Cover image -->
            <div class="h-36 bg-placeholder">
              {#if list.coverImageUrl}
                <img 
                  src={list.coverImageUrl} 
                  alt={list.name} 
                  class="w-full h-full object-cover"
                  on:error={(e) => {
                    (e.target as HTMLImageElement).src = 'https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp&f=y';
                  }}
                />
              {:else}
                <div class="w-full h-full flex items-center justify-center text-muted-foreground">
                  No cover image
                </div>
              {/if}
            </div>
            
            <!-- Content -->
            <div class="p-4">
              <h3 class="text-lg font-semibold mb-2">{list.name}</h3>
              
              <!-- Author info -->
              <div class="flex items-center mb-3">
                {#if runtime}<ReactiveProfile {runtime} pubkey={list.pubkey} size="xs" classes="mr-2" showName />{/if}
              </div>
              
              <!-- Preview of users in the list -->
              <div class="flex -space-x-2 overflow-hidden mt-4">
                {#each list.entries.slice(0, 5) as entry}
                  {#if runtime}<ReactiveProfile {runtime} pubkey={entry.pubkey} classes="border-2 border-surface" />{/if}
                {/each}
                
                {#if list.entries.length > 5}
                  <div class="w-8 h-8 rounded-full object-cover bg-placeholder border-2 border-surface flex items-center justify-center text-xs text-muted-foreground">
                    +{list.entries.length - 5}
                  </div>
                {/if}
              </div>
              
              <p class="text-sm text-muted-foreground mt-2">
                {list.entries.length} {list.entries.length === 1 ? 'user' : 'users'} · updated {getRelativeTime(list.createdAt)}
              </p>
            </div>
          </a>
        {/each}
      </div>
      
    {/if}
      <!-- Pagination -->
      {#if hasMoreLists}
        <div class="mt-8 text-center">
          <button 
            on:click={loadMore}
            class="btn btn-outline btn-sm px-4 {loadingMore ? 'loading' : ''}"
            disabled={loadingMore}
          >
            {loadingMore ? 'Loading...' : 'Discover more'}
          </button>
        </div>
      {/if}
  </div>
</div>
