<script lang="ts">
  import { packHref, packRelayHints } from '$lib/nostr/protocol/pack-link';
  import { onMount, onDestroy } from 'svelte';
  import { requireAuth } from '$lib/services/auth';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { user } from '$lib/stores/user';
  import { publishFollowList, deleteFollowList } from '$lib/features/packs/commands';
  import { loadPack } from '$lib/features/packs/detail';
  import { type UserSearchResult, searchUsersByName } from '$lib/features/profiles/user-search';
  import type { FollowListEntry } from '$lib/types/follow-list';
  import PublicKeyDisplay from '$lib/components/PublicKeyDisplay.svelte';
  import ReactiveProfile from '$lib/components/ReactiveProfile.svelte';
  import type { NostrRuntime } from '$lib/nostr/runtime';
  import { getNostrRuntime } from '$lib/nostr/runtime.client';
  import { accounts } from '$lib/nostr/accounts';
  import { uploadPackMedia } from '$lib/features/media/blossom';
  import { loadBlossomServers } from '$lib/features/media/servers';
  let uploading = false;
  let uploadMessage = '';
  async function handleMediaUpload(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file || uploading || submitting) return;
    uploading = true; error = ''; uploadMessage = '';
    const account = accounts.active;
    try {
      if (!account) throw new Error('Sign in first');
      const blob = await uploadPackMedia(file, await loadBlossomServers(await getNostrRuntime(), account.pubkey), async (draft) => {
        if (accounts.active !== account) throw new Error('Account changed. Please retry.');
        const signed = await account.signEvent(draft);
        if (accounts.active !== account) throw new Error('Account changed. Please retry.');
        return signed;
      }, pageController.signal);
      if (accounts.active !== account) throw new Error('Account changed. Please retry.');
      if (!pageController.signal.aborted) {
        coverImageUrl = blob.url;
        uploadMessage = 'Cover image uploaded.';
      }
    } catch (err) {
      if (!pageController.signal.aborted) error = err instanceof Error ? err.message : 'Upload failed';
    } finally { uploading = false; input.value = ''; }
  }
  let runtime: NostrRuntime | undefined;
  const DEBUG = true;
  const logDebug = (...args: any[]) => {
    if (DEBUG) console.log('[Create Page]', ...args);
  };

  // Form state
  let name = '';
  let coverImageUrl = '';
  let description = '';
  let searchQuery = '';
  let searchSource: 'ranking' | 'relay' = 'ranking';
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
  let listAuthor = '';
  let searchController: AbortController | undefined;
  const pageController = new AbortController();
  onDestroy(() => { searchController?.abort(); pageController.abort(); });
  let showDeleteConfirm = false;
  let deleting = false;
  let loading = false;
  let showRemoveAllConfirm = false;
  
  // Validation state
  let nameValid = true;
  let entriesValid = true;
  
  onMount(async () => {
    if (!(await requireAuth()) || pageController.signal.aborted) return;
    runtime = await getNostrRuntime();
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
      const list = await loadPack(await getNostrRuntime(), id, pubkey, pageController.signal);
      if (!list) {
        error = 'Could not find the follow list to edit';
        editMode = false;
        return;
      }
      
      if (pageController.signal.aborted) return;
      if (!$user || list.pubkey !== $user.pubkey) throw new Error('Only the author can edit this pack');
      listAuthor = list.pubkey;
      // Load the list data into the form
      name = list.name;
      coverImageUrl = list.coverImageUrl;
      description = list.description || '';
      listId = list.id;
      listEventId = list.eventId;
      selectedEntries = [...list.entries];

      logDebug('Loaded existing list for editing:', { id, name, entries: selectedEntries.length });
    } catch (err: any) {
      console.error('Error loading follow list for editing:', err);
      error = `Error loading list: ${err.message || 'Unknown error'}`;
      editMode = false;
    }
  }
  
  // Handle user search
  async function handleSearch() {
    searchController?.abort();
    const controller = searchController = new AbortController();
    searching = true; error = ''; searchResults = []; duplicateEntryError = false; noSearchResults = false;
    try {
      const results = await searchUsersByName(searchQuery, 10, controller.signal, searchSource);
      if (controller.signal.aborted) return;
      searchResults = results.filter((result) => !selectedEntries.some((entry) => entry.pubkey === result.pubkey));
      duplicateEntryError = results.length > 0 && searchResults.length === 0;
      noSearchResults = results.length === 0;
    } catch (err) { if (!controller.signal.aborted) error = err instanceof Error ? err.message : 'Search failed'; }
    finally { if (!controller.signal.aborted) searching = false; }
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
        relay: result.relays[0] || ''
      }
    ];
    
    // Clear search
    searchQuery = '';
    searchResults = [];
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
    if (uploading || submitting) return;
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
      const event = await publishFollowList(name, coverImageUrl, selectedEntries, editMode ? listId : undefined, description, editMode ? listAuthor : undefined);
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
        const hints = packRelayHints(runtime ?? await getNostrRuntime(), { pubkey: event.pubkey, eventId: event.id });
        goto(packHref({ id: dTag[1], pubkey: event.pubkey }, hints));
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

  // Function to handle input changes in the search box
  function handleInputChange() {
    searchController?.abort();
    searching = false;
    searchResults = [];
    noSearchResults = false;
    duplicateEntryError = false;
    error = '';
  }
</script>

<div class="container py-10">
  <div class="max-w-2xl mx-auto">
    <div class="flex justify-between items-center mb-8">
      <h1 class="text-3xl font-bold text-foreground">{editMode ? 'Edit' : 'Create'} Follow Pack</h1>
      <a href="/" class="btn btn-secondary">Cancel</a>
    </div>
    
    {#if !$user}
      <div class="bg-warning-soft border border-warning rounded-md p-6 text-center">
        <h2 class="text-xl font-medium text-warning mb-2">Login Required</h2>
        <p class="text-warning mb-4">
          You need to be logged in to create a follow list.
        </p>
        <a href="/" class="btn btn-primary">Back to Home</a>
      </div>
    {:else if editMode && loading}
      <div class="flex justify-center py-12">
        <div class="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-purple-500"></div>
      </div>
    {:else}
      {#if error}
        <div class="bg-danger-soft border border-danger rounded-md p-4 mb-6 text-danger">
          {error}
        </div>
      {/if}
      
      <!-- Delete Confirmation Modal -->
      {#if showDeleteConfirm}
        <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div class="bg-surface rounded-lg p-6 max-w-md w-full">
            <h3 class="text-xl font-bold text-foreground mb-4">Delete Follow Pack</h3>
            <p class="text-body mb-6">
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
        on:keydown={(e) => {
          if (e.key === 'Enter' && e.target instanceof HTMLElement && e.target.tagName !== 'TEXTAREA') {
            e.preventDefault();
          }
        }}
        class="bg-surface shadow-sm rounded-lg overflow-hidden"
      >
        <div class="p-6 border-b">
          <h2 class="text-xl font-medium mb-6">Follow Pack Details</h2>
          
          <!-- Name field -->
          <div class="mb-4">
            <label for="name" class="block text-sm font-medium text-body mb-1">
              List Name <span class="text-danger">*</span>
            </label>
            <input
              type="text"
              id="name"
              bind:value={name}
              on:blur={() => nameValid = !!name.trim()}
              class="w-full px-3 py-2 border {!nameValid ? 'border-red-500' : 'border-strong'} rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500"
              placeholder="E.g., Nostr Developers to Follow"
            />
            {#if !nameValid}
              <p class="mt-1 text-sm text-danger">Name is required</p>
            {/if}
          </div>
          
          <!-- Cover image URL field -->
          <div class="mb-6">
            <label for="coverImageUrl" class="block text-sm font-medium text-body mb-1">
              Cover Image URL
            </label>
            <input
              type="url"
              id="coverImageUrl"
              disabled={uploading || submitting}
              bind:value={coverImageUrl}
              class="w-full px-3 py-2 border border-strong rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500"
              placeholder="https://example.com/image.jpg"
            />
            <p class="mt-1 text-xs text-muted-foreground">Optional: URL to an image that represents this list</p>
          </div>
          
          <div class="mb-6">
            <label for="cover-upload" class="block text-sm font-medium text-body mb-1">Upload cover image</label>
            <input id="cover-upload" type="file" accept="image/*" on:change={handleMediaUpload} disabled={uploading || submitting} />
            <p class="mt-1 text-xs text-muted-foreground">Choose an image to fill the cover URL. Configure Blossom media servers in <a class="underline" href="/settings">Settings</a>.</p>
            {#if uploading}<p role="status">Uploading image…</p>{/if}
            {#if uploadMessage}<p role="status">{uploadMessage}</p>{/if}
          </div>

          <!-- Description field -->
          <div class="mb-6">
            <label for="description" class="block text-sm font-medium text-body mb-1">
              Description
            </label>
            <textarea
              id="description"
              bind:value={description}
              class="w-full px-3 py-2 border border-strong rounded-md shadow-sm focus:ring-purple-500 focus:border-purple-500"
              placeholder="Enter a description for this follow list"
            ></textarea>
          </div>
          
          {#if coverImageUrl}
            <div class="mb-6">
              <p class="block text-sm font-medium text-body mb-2">Cover Image Preview</p>
              <div class="h-36 bg-muted rounded-md overflow-hidden">
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
          
          <label class="block text-sm mb-3">
            Search provider
            <select bind:value={searchSource} on:change={handleInputChange} class="ml-2 border border-strong rounded px-2 py-1">
              <option value="ranking">Open Ranking (Vertex)</option>
              <option value="relay">Relay search (fallback)</option>
            </select>
          </label>
          <!-- Search field -->
          <div class="mb-4">
            <label for="search" class="block text-sm font-medium text-body mb-1">
              Search for Nostr Users
            </label>
            <div class="flex">
              <input
                type="text"
                id="search"
                bind:value={searchQuery}
                class="flex-1 px-3 py-2 border border-strong rounded-l-md shadow-sm focus:ring-purple-500 focus:border-purple-500"
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
                class="px-4 py-2 bg-purple-600 text-white rounded-r-md hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 disabled:opacity-50"
              >
                {searching ? 'Searching...' : 'Search'}
              </button>
            </div>
            <p class="mt-1 text-xs text-muted-foreground">
              {#if duplicateEntryError}
                <span class="text-danger">This user is already in your list!</span>
              {:else}
                Search by username or paste a nostr npub or nprofile
              {/if}
            </p>
            
            {#if error}
              <p class="mt-2 text-sm text-danger">{error}</p>
            {/if}
          </div>
          
          <!-- Search results -->
          {#if searching}
            <div class="bg-surface rounded-md shadow-sm mt-4 p-4 text-center">
              <div class="flex justify-center">
                <div class="animate-spin rounded-full h-6 w-6 border-t-2 border-b-2 border-purple-600"></div>
              </div>
              <p class="mt-2 text-muted-foreground">Searching...</p>
            </div>
          {:else if searchResults.length > 0}
            <div class="bg-surface rounded-md shadow-sm mt-4">
              <ul class="divide-y divide-line">
                {#each searchResults as result}
                  <li class="p-4 flex items-center justify-between">
                    <div class="flex items-center">
                      <div>
                        <div class="flex items-center gap-3">
                          {#if runtime}<ReactiveProfile {runtime} pubkey={result.pubkey} relays={result.relays} showName />{/if}
                          {#if $user?.following?.has(result.pubkey)}
                            <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-success-soft text-success">Following</span>
                          {/if}
                        </div>
                        <PublicKeyDisplay pubkey={result.pubkey} />
                        {#if result.relays.length > 0}
                          <p class="text-xs text-muted-foreground">
                            {result.relays.join(', ')}
                          </p>
                        {/if}
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
            <div class="bg-surface rounded-md shadow-sm mt-4 p-4 text-center text-muted-foreground">
              No users found matching "{searchQuery}"
            </div>
          {/if}
          
          <!-- Selected entries -->
          <div>
            <div class="flex justify-between items-center mb-2">
              <div class="flex items-center space-x-4">
                <h3 class="text-lg font-medium">Selected Users ({selectedEntries.length})</h3>
                {#if selectedEntries.length > 0}
                  <button
                    type="button"
                    on:click={() => showRemoveAllConfirm = true}
                    class="text-sm text-danger hover:text-danger"
                  >
                    Remove All
                  </button>
                {/if}
              </div>
              {#if !entriesValid}
                <p class="text-sm text-danger">Add at least one user to your list</p>
              {/if}
            </div>
            
            <!-- Remove All Confirmation Modal -->
            {#if showRemoveAllConfirm}
              <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                <div class="bg-surface rounded-lg p-6 max-w-md w-full">
                  <h3 class="text-xl font-bold text-foreground mb-4">Remove All Users</h3>
                  <p class="text-body mb-6">
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
              <div class="bg-subtle border border-line rounded-md p-4 text-center text-muted-foreground">
                No users selected yet. Search for users to add them to your list.
              </div>
            {:else}
              <ul class="border border-line rounded-md divide-y divide-line">
                {#each selectedEntries as entry, i}
                  <li class="p-3 flex items-center justify-between">
                    <div class="flex items-center">
                      <div>
                        {#if runtime}<div class="flex items-center gap-2"><ReactiveProfile {runtime} pubkey={entry.pubkey} showName /></div>
                        {:else}<p class="font-medium">{entry.name || 'Unknown User'}</p>{/if}
                        {#if entry.nip05}
                          <p class="text-xs text-muted-foreground">
                            {entry.nip05}
                          </p>
                        {/if}
                        <PublicKeyDisplay pubkey={entry.pubkey} />
                        {#if entry.relay}
                          <p class="text-xs text-muted-foreground">
                            {entry.relay}
                          </p>
                        {/if}
                      </div>
                    </div>
                    <div class="flex items-center space-x-2">
                      <div class="flex flex-col mr-3">
                        <button
                          type="button"
                          on:click={() => moveEntryUp(i)}
                          disabled={i === 0}
                          class="text-muted-foreground hover:text-accent disabled:opacity-30 disabled:hover:text-muted-foreground focus:outline-none"
                          title="Move up"
                          aria-label="Move up"
                        >
                          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M14.707 12.707a1 1 0 01-1.414 0L10 9.414l-3.293 3.293a1 1 0 01-1.414-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 010 1.414z" clip-rule="evenodd" />
                          </svg>
                        </button>
                        <button
                          type="button"
                          on:click={() => moveEntryDown(i)}
                          disabled={i === selectedEntries.length - 1}
                          class="text-muted-foreground hover:text-accent disabled:opacity-30 disabled:hover:text-muted-foreground focus:outline-none"
                          title="Move down"
                          aria-label="Move down"
                        >
                          <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 011.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
                          </svg>
                        </button>
                      </div>
                      <button
                        type="button"
                        on:click={() => removeEntry(i)}
                        class="text-sm text-danger hover:text-danger"
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
            disabled={submitting || uploading}
            class="btn btn-primary px-6 py-3 text-base {submitting ? 'opacity-70' : ''}"
          >
            {submitting ? (editMode ? 'Updating...' : 'Publishing...') : (editMode ? 'Update' : 'Publish') + ' Follow Pack'}
          </button>
        </div>
      </form>
    {/if}
  </div>
</div>
