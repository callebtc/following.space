<script lang="ts">
  import { onMount } from 'svelte';
  import { user, loadUser } from '$lib/stores/user';
  import { get } from 'svelte/store';
  import { goto } from '$app/navigation';

  import { getFollowLists, LIST_LIMIT, getAuthorProfile, getProfileInfoForEntries } from '$lib/services/follow-list.service';
  import type { FollowList } from '$lib/types/follow-list';
  import { getRelativeTime } from '$lib/utils/date';
  import ProfileImage from '$lib/components/ProfileImage.svelte';
  import { initializeAuth } from '$lib/services/auth';
  type FilterType = "none" | "follows" | "included" | "ours";
  const FILTER_NONE: FilterType = "none";
  const FILTER_USER_FOLLOWS: FilterType = "follows";
  const FILTER_USER_INCLUDED: FilterType = "included";
  const FILTER_USER_OURS: FilterType = "ours";

  let followLists: FollowList[] = [];
  let loading = true;
  let loadingMore = false;
  let hasMoreLists = false;
  let filterType: FilterType = FILTER_NONE;
  let dropdownOpen = false;
  let searchTerm = '';

  // Filter options for the dropdown
  const filterOptions = [
    { value: FILTER_NONE, label: 'Show all packs' },
    { value: FILTER_USER_FOLLOWS, label: 'From users I follow' },
    { value: FILTER_USER_INCLUDED, label: 'Packs I\'m in' },
    { value: FILTER_USER_OURS, label: 'My packs' }
  ];

  // Get the current filter label
  $: currentFilterLabel = filterOptions.find(option => option.value === filterType)?.label || 'Show all packs';

  // Handle clicks outside to close dropdown
  function handleClickOutside(event: MouseEvent) {
    const dropdown = document.getElementById('filter-dropdown');
    if (dropdown && !dropdown.contains(event.target as Node)) {
      dropdownOpen = false;
    }
  }

  // Set up or remove the click handler based on dropdown state
  $: if (typeof window !== 'undefined') {
    if (dropdownOpen) {
      window.addEventListener('click', handleClickOutside);
    } else {
      window.removeEventListener('click', handleClickOutside);
    }
  }
  
  // Clean up event listener on component unmount
  onMount(() => {
    return () => {
      if (typeof window !== 'undefined') {
        window.removeEventListener('click', handleClickOutside);
      }
    };
  });

  async function loadFollowLists(until?: number, filter: FilterType = FILTER_NONE) {
    try {
      let lists: FollowList[] = [];

      let ourUser = get(user);
      if (!ourUser) await loadUser();
      ourUser = get(user);
      if (filter === FILTER_NONE) {
        // Get all lists
        lists = await getFollowLists(LIST_LIMIT, undefined, until);
      } else {
          if (!ourUser) {
            return [];
          }
          if (filter === FILTER_USER_FOLLOWS) {
          // Get lists from followed users and self
          const followsArray = ourUser.following ? Array.from(ourUser.following) : [];
          lists = await getFollowLists(LIST_LIMIT, undefined, until, followsArray);
        } else if (filter === FILTER_USER_INCLUDED) {
          // Get lists that include the current user
          lists = await getFollowLists(LIST_LIMIT, undefined, until, undefined, [ourUser.pubkey]);
        } else if (filter === FILTER_USER_OURS) {
          // Get lists from the current user
          lists = await getFollowLists(LIST_LIMIT, undefined, until, [ourUser.pubkey]);
        }
      }
      
    
      // Determine if we might have more lists
      hasMoreLists = lists.length >= LIST_LIMIT;
      
      return lists;
    } catch (error) {
      console.error('Error fetching follow lists:', error);
      return [];
    }
  }

  async function loadMore() {
    if (followLists.length === 0 || loadingMore) return;
    
    loadingMore = true;
    
    try {
      // Get the oldest list's timestamp
      const oldestList = followLists[followLists.length - 1];
      const until = oldestList.createdAt;
      
      // Create a promise that resolves after 5 seconds
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Request timed out after 10 seconds')), 10000);
      });
      
      // Race between the actual request and the timeout
      const moreLists = await Promise.race([
        loadFollowLists(until, filterType),
        timeoutPromise
      ]) as FollowList[];
      
      // Append new lists to existing ones, avoiding duplicates
      const uniqueNewLists = moreLists.filter(list => !followLists.some(existing => existing.id === list.id));
      followLists = [...followLists, ...uniqueNewLists];

      loadingMore = false;
      
      // Load author profiles for each list one by one
      for (let i = 0; i < followLists.length; i++) {
        // Load author profile
        const listWithAuthor = await getAuthorProfile(followLists[i]);
        if (listWithAuthor) {
          followLists[i] = listWithAuthor;
          // Force reactivity by reassigning the array
          followLists = [...followLists];
        }
        // Load profile info for entries
        loadProfilesForList(i);
      }
    } catch (error) {
      console.error('Error loading more follow lists:', error);
      // Show error message to the user (optional)
    } finally {
      loadingMore = false;
    }
  }

  async function loadAllFollowLists(isFiltered = false, filter: FilterType = FILTER_NONE) {
    // Load follow lists first and render them immediately
    const lists = await loadFollowLists(undefined, filter);
    if (!isFiltered && followLists.length != 0) {
      return;
    } 
    followLists = lists;
    loading = false;
      
      // Then load author profiles for each list one by one
      for (let i = 0; i < followLists.length; i++) {
        // Load author profile
        const listWithAuthor = await getAuthorProfile(followLists[i]);
        if (listWithAuthor) {
          followLists[i] = listWithAuthor;
          // Force reactivity by reassigning the array
          followLists = [...followLists];
        }
        
        // Load profile info for entries
        // Use a separate function to process each entry individually
        loadProfilesForList(i);
      }
  }

  onMount(async () => {
    const currentUser = get(user);
    // Load filter preference from localStorage
    if (typeof localStorage !== 'undefined') {
      const savedFilter = localStorage.getItem('filterType');
      if (savedFilter !== null) {
        filterType = savedFilter as FilterType;
      }
    }
    loadAllFollowLists(false, currentUser ? filterType : undefined);
    try {
      initializeAuth(() => {
        // if filter type is none, we don't need to reload the lists  
        if (filterType === FILTER_NONE) {
          return;
        }
        loadAllFollowLists(true, filterType);
      });
    } catch (error) {
      console.error('Error fetching follow lists:', error);
      loading = false;
    }
  });
  
  // Function to load profiles for entries in a specific list
  async function loadProfilesForList(listIndex: number) {
    const list = followLists[listIndex];
    const maxEntries = 5; // Only load first 5 profiles
    
    // Load profiles one by one
    for (let i = 0; i < Math.min(list.entries.length, maxEntries); i++) {
      try {
        // Call getProfileInfoForEntries with a single entry index
        const updatedList = await getProfileInfoForEntries(
          { ...list, entries: [...list.entries] }, // Clone to avoid mutation
          undefined, // We're using entryIndex instead
          i  // Process this specific index
        );
        
        if (updatedList) {
          // Update just this one entry in our local list
          followLists[listIndex].entries[i] = updatedList.entries[i];
          // Force reactivity by reassigning the array
          followLists = [...followLists];
        }
      } catch (error) {
        console.error(`Error loading profile for entry ${i} in list ${listIndex}:`, error);
      }
    }
  }

  function handleCreateClick() {
    goto('/create');
  }

  async function handleFilterChange() {
    // Save filter preference to localStorage
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('filterType', filterType);
    }
    
    followLists = [];
    loading = true;
    await loadAllFollowLists(true, filterType);
    loading = false;
  }

  $: isSearchingNpub = isValidNpub(searchTerm);

  $: filteredFollowLists = followLists.filter(list => {
    const term = searchTerm.trim();
    if (!term) return true;
    if (isSearchingNpub) {
      const hex = npubToHex(term);
      if (hex && list.pubkey) {
        return list.pubkey === hex;
      }
      return false;
    }
    return list.name?.toLowerCase().includes(term.toLowerCase());
  });

  $: if (
    searchTerm.trim() &&
    !loading &&
    hasMoreLists &&
    filteredFollowLists.length < LIST_LIMIT &&
    followLists.length > 0 &&
    !loadingMore
  ) {
    // Try to load more lists if searching and not enough results
    loadMore();
  }
</script>

<svelte:head>
  <title>Following._ Nostr Follow Packs</title>
</svelte:head>

<div class="container py-10">
  <!-- Hero section -->
  <div class="text-center mb-12">
    <h1 class="text-4xl font-bold text-gray-900 mb-4">Nostr Follow Packs</h1>
    <p class="text-xl text-gray-600 max-w-2xl mx-auto">
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
        <p class="text-sm text-gray-500 mt-4">Please log in to create a follow pack or to filter packs.</p>
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
            class="appearance-none bg-white border border-gray-200 rounded-md pl-4 pr-10 py-3 text-gray-600 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-purple-300 focus:border-transparent transition-all min-w-[180px] font-medium text-sm flex items-center justify-between"
            on:click|stopPropagation={() => dropdownOpen = !dropdownOpen}
          >
            <span>{currentFilterLabel}</span>
            <div class="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-gray-500">
              <svg class="h-4 w-4 fill-current" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
                <path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" />
              </svg>
            </div>
          </button>
          
          {#if dropdownOpen}
            <div class="absolute mt-1 w-full bg-white border border-gray-200 rounded-md shadow-lg z-10">
              {#each filterOptions as option}
                <button 
                  class="w-full text-left px-4 py-3 text-gray-600 hover:bg-gray-50 transition-colors {filterType === option.value ? 'bg-purple-50 text-purple-700' : ''}"
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
    <div class="flex flex-col mb-6">
      <input
        type="text"
        placeholder="Search packs by name..."
        bind:value={searchTerm}
        class="w-full px-4 py-3 border border-gray-200 rounded-md focus:outline-none focus:ring-2 focus:ring-purple-300 text-gray-700"
      />
      {#if searchTerm.length > 0}
        {#if isSearchingNpub}
          {#if filteredFollowLists.length > 0}
            <div class="flex items-center justify-center mt-2">
              <span class="text-sm text-gray-500 mr-2">Showing {filteredFollowLists.length} packs from</span>
              <ProfileImage
                src={filteredFollowLists[0].authorPicture}
                alt={filteredFollowLists[0].authorName || 'Author'}
                size="xs"
                classes="mr-1"
              />
              <span class="text-sm text-gray-500">
                {filteredFollowLists[0].authorName || searchTerm.slice(0, 12) + '...'}
              </span>
            </div>
          {:else}
            <p class="text-sm text-gray-500 mt-2 text-center">
              No packs found for {searchTerm.slice(0, 12) + '...'}
            </p>
          {/if}
        {:else}
          <p class="text-sm text-gray-500 mt-2 text-center">Showing {filteredFollowLists.length} of {followLists.length} packs</p>
        {/if}
      {/if}
    </div>
    {#if loading}
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {#each Array(6) as _, i}
          <div class="bg-white rounded-lg shadow-sm overflow-hidden animate-pulse">
            <!-- Skeleton cover image -->
            <div class="h-36 bg-gray-200"></div>
            
            <!-- Skeleton content -->
            <div class="p-4">
              <div class="h-5 bg-gray-200 rounded w-3/4 mb-2"></div>
              
              <!-- Skeleton author info -->
              <div class="flex items-center mb-3">
                <div class="w-5 h-5 rounded-full bg-gray-200 mr-2"></div>
                <div class="h-4 bg-gray-200 rounded w-1/3"></div>
              </div>
              
              <!-- Skeleton user avatars -->
              <div class="flex -space-x-2 overflow-hidden mt-4">
                {#each Array(5) as _, j}
                  <div class="w-8 h-8 rounded-full bg-gray-200 border-2 border-white"></div>
                {/each}
              </div>
              
              <div class="h-4 bg-gray-200 rounded w-1/2 mt-2"></div>
            </div>
          </div>
        {/each}
      </div>
    {:else if followLists.length === 0}
      <div class="bg-white p-8 rounded-lg shadow-sm text-center">
        <p class="text-gray-600">No follow lists found. Be the first to create one!</p>
      </div>
    {:else}
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {#each filteredFollowLists as list}
          <a
            href="/d/{list.id}?p={list.pubkey}"
            class="bg-white rounded-lg shadow-sm overflow-hidden transition-transform hover:scale-[1.02]"
          >
            <!-- Cover image -->
            <div class="h-36 bg-gray-200">
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
                <div class="w-full h-full flex items-center justify-center text-gray-400">
                  No cover image
                </div>
              {/if}
            </div>
            
            <!-- Content -->
            <div class="p-4">
              <h3 class="text-lg font-semibold mb-2">{list.name}</h3>
              
              <!-- Author info -->
              <div class="flex items-center mb-3">
                <ProfileImage 
                  src={list.authorPicture} 
                  alt={list.authorName || 'Author'} 
                  size="xs" 
                  classes="mr-2"
                />
                <span class="text-sm text-gray-600">{list.authorName || 'Unknown User'}</span>
              </div>
              
              <!-- Preview of users in the list -->
              <div class="flex -space-x-2 overflow-hidden mt-4">
                {#each list.entries.slice(0, 5) as entry}
                  <ProfileImage 
                    src={entry.picture} 
                    alt={entry.name || 'User'} 
                    size="md" 
                    classes="border-2 border-white"
                    style="margin-top: 0px;"
                  />
                {/each}
                
                {#if list.entries.length > 5}
                  <div class="w-8 h-8 rounded-full object-cover bg-gray-200 border-2 border-white flex items-center justify-center text-xs text-gray-600">
                    +{list.entries.length - 5}
                  </div>
                {/if}
              </div>
              
              <p class="text-sm text-gray-500 mt-2">
                {list.entries.length} {list.entries.length === 1 ? 'user' : 'users'} · updated {getRelativeTime(list.createdAt)}
              </p>
            </div>
          </a>
        {/each}
      </div>
      
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
    {/if}
  </div>
</div>
