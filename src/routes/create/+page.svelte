<script lang="ts">
  import { onMount, onDestroy, tick } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { user } from '$lib/stores/user';
  import { isValidNpub, npubToHex, isValidNprofile, nprofileToNpubAndRelays } from '$lib/utils/npub';
  import { publishFollowList, getFollowListById, deleteFollowList } from '$lib/services/follow-list.service';
  import { getProfileByPubkey } from '$lib/stores/user';
  import { type UserSearchResult, searchUsersByName, debouncedSearch } from '$lib/services/user-search';
  import type { FollowListEntry } from '$lib/types/follow-list';
  import PublicKeyDisplay from '$lib/components/PublicKeyDisplay.svelte';
  import ProfileImage from '$lib/components/ProfileImage.svelte';
  const DEBUG = true;
  const logDebug = (...args: any[]) => {
    if (DEBUG) console.log('[Create Page]', ...args);
  };

  // Validierungsfunktionen stärken
  function validateInput(input: string): string {
    // Entferne potenziell gefährliche Zeichen
    return input.replace(/<[^>]*>/g, '').trim();
  }

  // Form state
  let name = '';
  let coverImageUrl = '';
  let description = '';
  let searchQuery = '';
  let searching = false;
  let searchResults: UserSearchResult[] = [];
  let selectedEntries: FollowListEntry[] = [];
  let submitting = false;
  let error = '';
  let duplicateEntryError = false;
  let noSearchResults = false;
  let editMode = false;
  let editId = '';
  let listId = '';
  let listEventId = '';
  let showDeleteConfirm = false;
  let deleting = false;
  let loading = false;
  let showRemoveAllConfirm = false;
  let showSuccess = false;

  // Validation state
  let nameValid = true;
  let entriesValid = true;

  // State for optimized search
  let searchTimeout: ReturnType<typeof setTimeout> | null = null;
  let lastQuery = '';

  onMount(async () => {
    // Check if we're in edit mode
    const editParam = $page.url.searchParams.get('edit');
    if (editParam) {
      const pubkey = $page.url.searchParams.get('p');
      editMode = true;
      editId = editParam;
      logDebug('Loading existing list for editing:', editId, pubkey);
      loading = true;
      try {
        await loadExistingList(editParam, pubkey ? pubkey : undefined);
      } finally {
        loading = false;
      }
    }

    document.addEventListener('keydown', handleDocumentKeydown);
  });

  onDestroy(() => {
    document.removeEventListener('keydown', handleDocumentKeydown);
  });

  // Handle delete button click
  function handleDelete() {
    showDeleteConfirm = true;
  }

  // Handle delete confirmation
  async function confirmDelete() {
    if (!listEventId) return;

    deleting = true;
    try {
      const deleted = await deleteFollowList(listEventId);
      if (deleted) {
        // Navigate back to home
        goto('/');
      } else {
        // Handle error
        error = 'Failed to delete follow list';
        showDeleteConfirm = false;
      }
    } catch (err: any) {
      console.error('Error deleting follow list:', err);
      error = `Error deleting: ${err.message || 'An unknown error occurred'}`;
      showDeleteConfirm = false;
    } finally {
      deleting = false;
    }
  }

  // Cancel deletion
  function cancelDelete() {
    showDeleteConfirm = false;
  }

  // Load an existing list for editing
  async function loadExistingList(id: string, pubkey?: string) {
    try {
      const list = await getFollowListById(id, pubkey);
      if (!list) {
        error = 'Could not find the follow list to edit';
        editMode = false;
        return;
      }

      // // Check if the user is the author
      // if (!$user || $user.pubkey !== list.pubkey) {
      //   error = 'You are not authorized to edit this follow list';
      //   editMode = false;
      //   return;
      // }

      // Load the list data into the form
      name = validateInput(list.name);
      coverImageUrl = list.coverImageUrl;
      description = validateInput(list.description || '');
      listId = list.id;
      listEventId = list.eventId;
      selectedEntries = [...list.entries];

      // reactively get profile info for each entry
      selectedEntries.forEach(async (entry) => {
        const profile = await getProfileByPubkey(entry.pubkey);
        entry.name = profile.name;
        entry.picture = profile.picture;
        entry.bio = profile.bio;
        entry.nip05 = profile.nip05;
      });

      logDebug('Loaded existing list for editing:', { id, name, entries: selectedEntries.length });
    } catch (err: any) {
      console.error('Error loading follow list for editing:', err);
      error = `Error loading list: ${err.message || 'Unknown error'}`;
      editMode = false;
    }
  }

  // Handle user search
  async function handleSearch() {
    if (!searchQuery.trim()) return;

    searching = true;
    searchResults = [];
    duplicateEntryError = false;
    noSearchResults = false; // Reset no results flag
    error = ''; // Clear previous errors

    try {
      if (isValidNpub(searchQuery)) {
        // Convert npub to hex
        const pubkey = await npubToHex(searchQuery);

        if (!pubkey) {
          error = 'Invalid npub';
          return;
        }

        // Get profile
        const profile = await getProfileByPubkey(pubkey);

        if (selectedEntries.some(entry => entry.pubkey === pubkey)) {
          logDebug('Entry already in list:', pubkey);
          duplicateEntryError = true;
          setTimeout(() => {
            duplicateEntryError = false;
          }, 3000);
          searching = false;
          return;
        }

        // Create a single search result
        searchResults = [{
          pubkey,
          relays: [],
          rank: 0,
          name: profile.name || 'Unknown',
          picture: profile.picture || '',
        }];
      } else if (isValidNprofile(searchQuery)) {
        // Convert nprofile to npub and relays
        const { npub, relays } = await nprofileToNpubAndRelays(searchQuery);
        if (!npub) {
          error = 'Invalid nprofile';
          return;
        }

        // Convert npub to hex
        const pubkey = await npubToHex(npub);

        if (!pubkey) {
          error = 'Invalid npub';
          return;
        }

        // Get profile
        const profile = await getProfileByPubkey(pubkey);

        if (selectedEntries.some(entry => entry.pubkey === pubkey)) {
          logDebug('Entry already in list:', pubkey);
          duplicateEntryError = true;
          setTimeout(() => {
            duplicateEntryError = false;
          }, 3000);
          searching = false;
          return;
        }

        // Create a single search result
        searchResults = [{
          pubkey,
          relays,
          rank: 0,
          name: profile.name || 'Unknown',
          picture: profile.picture || '',
        }];
      } else {
        // Search for users by name
        const results = await searchUsersByName(searchQuery);

        // Filter out duplicates that are already in the selected entries
        searchResults = results.filter(result =>
          !selectedEntries.some(entry => entry.pubkey === result.pubkey)
        );

        if (results.length > 0 && searchResults.length === 0) {
          noSearchResults = true;
          setTimeout(() => {
            noSearchResults = false;
          }, 3000);
        }
      }

      logDebug(`Search returned ${searchResults.length} results`);
    } catch (err: any) {
      console.error('Error searching:', err);
      error = `Search error: ${err.message || 'An unknown error occurred'}`;
    } finally {
      searching = false;
    }
  }

  // Add a search result to the selected entries
  function addEntry(result: UserSearchResult) {
    // Check if already added
    if (selectedEntries.some(entry => entry.pubkey === result.pubkey)) {
      logDebug('Entry already in list:', result.pubkey);
      return;
    }

    logDebug('Adding entry to list:', result);

    // Add to selections
    selectedEntries = [
      ...selectedEntries,
      {
        pubkey: result.pubkey,
        relay: result.relays[0] || '',
        name: result.name,
        picture: result.picture
      }
    ];

    // Clear search
    searchQuery = '';
    searchResults = [];
    showSuccess = true;
    setTimeout(() => {
      showSuccess = false;
    }, 3000);
  }

  // Remove a selected entry
  function removeEntry(index: number) {
    selectedEntries = selectedEntries.filter((_, i) => i !== index);
  }

  // Move entry up in the list
  function moveEntryUp(index: number) {
    if (index <= 0) return; // Can't move up if already at the top

    const newEntries = [...selectedEntries];
    const temp = newEntries[index];
    newEntries[index] = newEntries[index - 1];
    newEntries[index - 1] = temp;

    selectedEntries = newEntries;
  }

  // Move entry down in the list
  function moveEntryDown(index: number) {
    if (index >= selectedEntries.length - 1) return; // Can't move down if already at the bottom

    const newEntries = [...selectedEntries];
    const temp = newEntries[index];
    newEntries[index] = newEntries[index + 1];
    newEntries[index + 1] = temp;

    selectedEntries = newEntries;
  }

  // Handle form submission
  async function handleSubmit() {
    // Reset validation
    nameValid = !!name.trim();
    entriesValid = selectedEntries.length > 0;

    logDebug('Form submission - validation:', { nameValid, entriesValid });

    // Check validation
    if (!nameValid || !entriesValid) {
      error = 'Please fix the validation errors and try again.';
      logDebug('Validation failed:', error);
      return;
    }

    submitting = true;
    error = '';

    logDebug('Publishing follow list:', { name, description, entries: selectedEntries.length, editMode });

    try {
      // Publish the follow list (same method for create and edit)
      const event = await publishFollowList(name, coverImageUrl, selectedEntries, editMode ? listId : undefined, description);
      logDebug('Published event with ID:', event?.id);
      if (event) {
        // Navigate to the new follow list
        logDebug('Redirecting to follow list page');
        const dTag = event.tags.find(tag => tag[0] === 'd');
        if (!dTag) {
          error = 'Failed to publish follow list. Please try again.';
          logDebug('Publish failed - no ID returned');
          return;
        }
        goto(`/d/${dTag[1]}?p=${event.pubkey}`);
      } else {
        error = 'Failed to publish follow list. Please try again.';
        logDebug('Publish failed - no ID returned');
      }
    } catch (err: any) {
      console.error('Error publishing follow list:', err);
      logDebug('Publish error:', err);
      error = `Error publishing: ${err.message || 'An unknown error occurred'}`;
    } finally {
      submitting = false;
    }
  }

  // Handle remove all confirmation
  function confirmRemoveAll() {
    selectedEntries = [];
    showRemoveAllConfirm = false;
  }

  // Cancel remove all
  function cancelRemoveAll() {
    showRemoveAllConfirm = false;
  }

  // Optimized input change handler function
  function handleInputChange() {
    // Clear any existing timeout
    if (searchTimeout) clearTimeout(searchTimeout);

    // Cancel existing search
    if (searching) {
      searching = false;
      noSearchResults = false;
    }

    // Set new timeout for search (debouncing)
    if (searchQuery.length >= 3 && searchQuery !== lastQuery) {
      searchTimeout = setTimeout(() => {
        lastQuery = searchQuery;
        handleSearch();
      }, 500);
    }
  }

  // Function to handle keydown events
  function handleDocumentKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter' && e.target instanceof HTMLElement &&
        e.target.tagName !== 'TEXTAREA' && e.target.tagName !== 'BUTTON') {
      e.preventDefault();
    }
  }
</script>

<div class="container py-4 sm:py-10 px-4 sm:px-0">
  <div class="mx-auto max-w-full sm:max-w-2xl">
    <div class="flex justify-between items-center mb-8">
      <h1 class="text-3xl font-bold text-gray-900">{editMode ? 'Edit' : 'Create'} Follow Pack</h1>
      <a href="/" class="btn btn-secondary">Cancel</a>
    </div>

    {#if !$user}
      <div class="bg-yellow-50 border border-yellow-200 rounded-md p-6 text-center">
        <h2 class="text-xl font-medium text-yellow-800 mb-2">Login Required</h2>
        <p class="text-yellow-700 mb-4">
          You need to be logged in to create a follow list.
        </p>
        <a href="/" class="btn btn-primary">Back to Home</a>
      </div>
    {:else if editMode && loading}
      <div class="flex justify-center py-12">
        <div class="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-purple-500"></div>
      </div>
    {:else}
      <!-- Improved Feedback Component -->
      {#if error}
        <div class="bg-red-50 border-l-4 border-red-500 p-4 mb-4 text-red-700 rounded-md transition-all animate-fadeIn">
          <div class="flex">
            <div class="flex-shrink-0">
              <svg class="h-5 w-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 101.414 1.414L10 11.414l1.293 1.293a1 1 001.414-1.414L11.414 10l1.293-1.293a1 1 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
              </svg>
            </div>
            <div class="ml-3">
              <p class="text-sm">{error}</p>
            </div>
            <div class="ml-auto pl-3">
              <button type="button" on:click={() => error = ''} class="inline-flex text-red-400 focus:outline-none">
                <span class="sr-only">Dismiss</span>
                <svg class="h-5 w-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                  <path fill-rule="evenodd" d="M4.293 4.293a1 1 011.414 0L10 8.586l4.293-4.293a1 1 111.414 1.414L11.414 10l4.293 4.293a1 1 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 01-1.414-1.414L8.586 10 4.293 5.707a1 1 010-1.414z" clip-rule="evenodd" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      {/if}

      <!-- Success Message -->
      {#if showSuccess}
        <div class="bg-green-50 border-l-4 border-green-500 p-4 mb-4 text-green-700 rounded-md transition-all animate-fadeIn">
          <div class="flex">
            <div class="flex-shrink-0">
              <svg class="h-5 w-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
              </svg>
            </div>
            <div class="ml-3">
              <p class="text-sm">User successfully added to your pack!</p>
            </div>
            <div class="ml-auto pl-3">
              <button type="button" on:click={() => showSuccess = false} class="inline-flex text-green-400 focus:outline-none">
                <span class="sr-only">Dismiss</span>
                <svg class="h-5 w-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                  <path fill-rule="evenodd" d="M4.293 4.293a1 1 011.414 0L10 8.586l4.293-4.293a1 1 111.414 1.414L11.414 10l4.293 4.293a1 1 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 01-1.414-1.414L8.586 10 4.293 5.707a1 1 010-1.414z" clip-rule="evenodd" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      {/if}

      <!-- Delete Confirmation Modal -->
      {#if showDeleteConfirm}
        <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div class="bg-white rounded-lg p-6 max-w-md w-full">
            <h3 class="text-xl font-bold text-gray-900 mb-4">Delete Follow Pack</h3>
            <p class="text-gray-700 mb-6">
              Are you sure you want to delete the follow list "{name}"? This action cannot be undone.
            </p>
            <div class="flex justify-end space-x-3">
              <button 
                on:click={cancelDelete} 
                class="btn btn-secondary"
                disabled={deleting}
              >
                Cancel
              </button>
              <button 
                on:click={confirmDelete} 
                class="btn btn-error"
                disabled={deleting}
              >
                {deleting ? 'Deleting...' : 'Delete Forever'}
              </button>
            </div>
          </div>
        </div>
      {/if}
      
      <form 
        on:submit|preventDefault={handleSubmit} 
        class="bg-white shadow-sm rounded-lg overflow-hidden"
      >
        <div class="p-6 border-b">
          <h2 class="text-xl font-medium mb-6">Follow Pack Details</h2>
          
          <!-- Name field -->
          <div class="mb-4">
            <label for="name" class="block text-sm font-medium text-gray-700 mb-1">
              List Name <span class="text-red-500">*</span>
            </label>
            <input
              type="text"
              id="name"
              bind:value={name}
              on:blur={() => nameValid = !!name.trim()}
              class="w-full px-3 py-2 border {!nameValid ? 'border-red-500' : 'border-gray-300'} rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500"
              placeholder="E.g., Nostr Developers to Follow"
            />
            {#if !nameValid}
              <p class="mt-1 text-sm text-red-600">Name is required</p>
            {/if}
          </div>
          
          <!-- Cover image URL field -->
          <div class="mb-6">
            <label for="coverImageUrl" class="block text-sm font-medium text-gray-700 mb-1">
              Cover Image URL
            </label>
            <input
              type="url"
              id="coverImageUrl"
              bind:value={coverImageUrl}
              class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500"
              placeholder="https://example.com/image.jpg"
            />
            <p class="mt-1 text-xs text-gray-500">Optional: URL to an image that represents this list</p>
          </div>
          
          <!-- Description field -->
          <div class="mb-6">
            <label for="description" class="block text-sm font-medium text-gray-700 mb-1">
              Description
            </label>
            <textarea
              id="description"
              bind:value={description}
              class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500"
              placeholder="Enter a description for this follow list"
            ></textarea>
          </div>
          
          {#if coverImageUrl}
            <div class="mb-6">
              <p class="block text-sm font-medium text-gray-700 mb-2">Cover Image Preview</p>
              <div class="h-36 bg-gray-100 rounded-md overflow-hidden">
                <img 
                  src={coverImageUrl} 
                  alt="Cover Preview" 
                  class="w-full h-full object-cover"
                  on:error={(e) => {
                    (e.target as HTMLImageElement).src = 'https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp&f=y';
                  }} 
                />
              </div>
            </div>
          {/if}
        </div>
        
        <div class="p-6 border-b">
          <h2 class="text-xl font-medium mb-6">Add Users to Follow Pack</h2>
          
          <!-- Improved search field with clear focus state -->
          <div class="relative">
            <div class="flex">
              <input
                type="text"
                id="search"
                bind:value={searchQuery}
                class="flex-1 px-3 py-2 border border-gray-300 rounded-l-md shadow-sm focus:ring-2 focus:ring-purple-500 focus:border-purple-500 transition-all"
                placeholder="Enter username or npub"
                on:keydown={e => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleSearch();
                  }
                }}
                on:input={handleInputChange}
              />
              <button
                type="button"
                on:click={handleSearch}
                disabled={searching || searchQuery.length < 3}
                class="px-4 py-2 bg-purple-600 text-white rounded-r-md hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 disabled:opacity-50 transition-all"
                aria-label="Search for users"
              >
                {searching ? 'Searching...' : 'Search'}
              </button>
            </div>
          </div>
          
          <!-- Search tips -->
          <div class="mt-2 text-xs text-gray-500">
            <p class="font-medium mb-1">Search Tips:</p>
            <ul class="list-disc pl-5">
              <li>Search for known developers like "Gigi" or "Aldo Barazutti"</li>
              <li>Search directly with an npub or nprofile</li>
              <li>To find users with many followers, search for general terms</li>
            </ul>
          </div>
          
          <!-- Search results -->
          {#if searching}
            <div class="bg-white rounded-md shadow-sm mt-4 p-4 text-center">
              <div class="flex justify-center">
                <div class="animate-spin rounded-full h-6 w-6 border-t-2 border-b-2 border-purple-600"></div>
              </div>
              <p class="mt-2 text-gray-600">Searching...</p>
            </div>
          {:else if searchResults.length > 0}
            <div class="bg-white rounded-md shadow-sm mt-4">
              <ul class="divide-y divide-gray-200">
                {#each searchResults as result}
                  <li class="p-4 flex items-center justify-between">
                    <div class="flex items-center">
                      <ProfileImage 
                        src={result.picture} 
                        alt={result.name || 'User'} 
                        size="md" 
                        classes="mr-3"
                      />
                      <div>
                        <div class="flex items-center">
                          <h4 class="text-lg font-medium text-gray-900">{result.name || 'Unknown User'}</h4>
                          {#if $user?.following?.has(result.pubkey)}
                            <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">Following</span>
                          {/if}
                        </div>
                        <PublicKeyDisplay pubkey={result.pubkey} />
                        {#if result.relays.length > 0}
                          <p class="text-xs text-gray-500">
                            {result.relays.join(', ')}
                          </p>
                        {/if}
                        <div class="flex items-center mt-1">
                          {#if result.followerCount !== undefined}
                            <span class="text-xs text-gray-600 flex items-center mr-2">
                              <svg xmlns="http://www.w3.org/2000/svg" class="h-3 w-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                              </svg>
                              {result.followerCount || 0} {result.followerCount === 1 ? 'Follower' : 'Followers'}
                            </span>
                          {/if}
                        </div>
                      </div>
                    </div>
                    <button
                      type="button"
                      on:click={() => addEntry(result)}
                      class="btn btn-primary btn-sm"
                    >
                      Add to List
                    </button>
                  </li>
                {/each}
              </ul>
            </div>
          {:else if searchQuery.length >= 3 && noSearchResults}
            <div class="bg-white rounded-md shadow-sm mt-4 p-4 text-center text-gray-600">
              No users found matching "{searchQuery}"
            </div>
          {/if}
          
          <!-- Selected entries -->
          <div>
            <div class="flex justify-between items-center mb-2">
              <div class="flex items-center space-x-4">
                <h3 class="text-lg font-medium">Selected Users ({selectedEntries.length})</h3>
                {#if selectedEntries.length > 1}
                  <div class="flex space-x-2">
                    <button
                      type="button"
                      on:click={() => {
                        // Sort by name
                        selectedEntries = [...selectedEntries].sort((a, b) => 
                          (a.name || '').localeCompare(b.name || '')
                        );
                      }}
                      class="text-sm text-purple-600 hover:text-purple-800"
                      aria-label="Sort by name"
                    >
                      Sort by Name
                    </button>
                  </div>
                {/if}
                {#if selectedEntries.length > 0}
                  <button
                    type="button"
                    on:click={() => showRemoveAllConfirm = true}
                    class="text-sm text-red-600 hover:text-red-800"
                  >
                    Remove All
                  </button>
                {/if}
              </div>
              {#if !entriesValid}
                <p class="text-sm text-red-600">Add at least one user to your list</p>
              {/if}
            </div>
            
            <!-- Remove All Confirmation Modal -->
            {#if showRemoveAllConfirm}
              <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                <div class="bg-white rounded-lg p-6 max-w-md w-full">
                  <h3 class="text-xl font-bold text-gray-900 mb-4">Remove All Users</h3>
                  <p class="text-gray-700 mb-6">
                    Are you sure you want to remove all users from your list? This action cannot be undone.
                  </p>
                  <div class="flex justify-end space-x-3">
                    <button 
                      on:click={cancelRemoveAll} 
                      class="btn btn-secondary"
                    >
                      Cancel
                    </button>
                    <button 
                      on:click={confirmRemoveAll} 
                      class="btn btn-error"
                    >
                      Remove All
                    </button>
                  </div>
                </div>
              </div>
            {/if}
            
            {#if selectedEntries.length === 0}
              <div class="bg-gray-50 border border-gray-200 rounded-md p-4 text-center text-gray-500">
                No users selected yet. Search for users to add them to your list.
              </div>
            {:else}
              <ul class="border border-gray-200 rounded-md divide-y divide-gray-200">
                {#each selectedEntries as entry, i}
                  <li class="p-3 flex flex-col sm:flex-row sm:items-center justify-between">
                    <div class="flex items-center mb-2 sm:mb-0">
                      <ProfileImage 
                        src={entry.picture} 
                        alt={entry.name || 'User'} 
                        size="md" 
                        classes="mr-3"
                      />
                      <div>
                        <p class="font-medium">{entry.name || 'Unknown User'}</p>
                        {#if entry.nip05}
                          <p class="text-xs text-gray-500">
                            {entry.nip05}
                          </p>
                        {/if}
                        <PublicKeyDisplay pubkey={entry.pubkey} />
                        {#if entry.relay}
                          <p class="text-xs text-gray-500">
                            {entry.relay}
                          </p>
                        {/if}
                      </div>
                    </div>
                    <div class="flex items-center justify-end sm:space-x-2">
                      <div class="flex flex-col mr-3">
                        <button
                          type="button"
                          on:click={() => moveEntryUp(i)}
                          disabled={i === 0}
                          class="text-gray-500 hover:text-purple-600 disabled:opacity-30 disabled:hover:text-gray-500 focus:outline-none"
                          title="Move up"
                          aria-label="Move up in list"
                        >
                          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M14.707 12.707a1 1 0 01-1.414 0L10 9.414l-3.293 3.293a1 1 01-1.414-1.414l-4 4a1 1 010-1.414z" clip-rule="evenodd" />
                          </svg>
                        </button>
                        <button
                          type="button"
                          on:click={() => moveEntryDown(i)}
                          disabled={i === selectedEntries.length - 1}
                          class="text-gray-500 hover:text-purple-600 disabled:opacity-30 disabled:hover:text-gray-500 focus:outline-none"
                          title="Move down"
                          aria-label="Move down in list"
                        >
                          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 011.414 1.414l-4 4a1 1 01-1.414 0l-4-4a1 1 010-1.414z" clip-rule="evenodd" />
                          </svg>
                        </button>
                      </div>
                      <button
                        type="button"
                        on:click={() => removeEntry(i)}
                        class="text-sm text-red-600 hover:text-red-800"
                      >
                        Remove
                      </button>
                    </div>
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        </div>
        
        <div class="p-6 flex justify-between">
          {#if editMode}
            <button
              type="button"
              on:click={handleDelete}
              class="btn btn-error px-6 py-3 text-base"
            >
              Delete List
            </button>
          {:else}
            <div></div>
          {/if}
          
          <button
            type="submit"
            disabled={submitting}
            class="btn btn-primary px-6 py-3 text-base {submitting ? 'opacity-70' : ''}"
          >
            {submitting ? (editMode ? 'Updating...' : 'Publishing...') : (editMode ? 'Update' : 'Publish') + ' Follow Pack'}
          </button>
        </div>
      </form>
    {/if}
  </div>
</div>