<script lang="ts">
  import '../app.css';
  import { onMount, onDestroy } from 'svelte';
  import { beforeNavigate, onNavigate } from '$app/navigation';
  import { restoreScroll } from '$lib/navigation/scroll-restoration';
  import { user, userWarning } from '$lib/stores/user';
  import { publishNotice } from '$lib/nostr/publish';
  import { logoutUser } from '$lib/services/logout';
  import { initializeAuth } from '$lib/services/auth';
  import { getNostrRuntime } from '$lib/nostr/runtime.client';
  import { getPackDirectory } from '$lib/features/packs/directory';
  import type { Subscription } from 'rxjs';
  import LoginButton from '$lib/components/LoginButton.svelte';
  import ProfileImage from '$lib/components/ProfileImage.svelte';

  let showUserMenu = false;
  let showLogoutConfirm = false;
  let loggingOut = false;

  let stopScrollRestoration: (() => void) | undefined;
  beforeNavigate(() => stopScrollRestoration?.());
  onNavigate((navigation) => {
    // Capture before the router replaces to.scroll with the clamped position.
    const position = navigation.type === 'popstate' ? navigation.to?.scroll : null;
    if (position) return () => { stopScrollRestoration = restoreScroll(position); };
  });
  onDestroy(() => stopScrollRestoration?.());

  onMount(() => {
    let disposed = false;
    let directory: Subscription | undefined;
    void getNostrRuntime().then((runtime) => {
      if (!disposed) directory = getPackDirectory(runtime).state$.subscribe();
    }).catch(() => {});
    void initializeAuth().catch(() => userWarning.set('Login could not be restored. Please sign in again.'));
    const closeMenu = (event: MouseEvent) => {
      if (showUserMenu && !(event.target as HTMLElement).closest('.user-menu-container')) showUserMenu = false;
    };
    document.addEventListener('click', closeMenu);
    return () => { disposed = true; directory?.unsubscribe(); document.removeEventListener('click', closeMenu); };
  });

  function toggleUserMenu(e: MouseEvent) {
    e.stopPropagation();
    showUserMenu = !showUserMenu;
  }
  

  function handleLogout() {
    showUserMenu = false;
    showLogoutConfirm = true;
  }

  async function confirmLogout() {
    loggingOut = true;
    
    try {
      // Use the centralized logout service
      await logoutUser();
    } catch (error) {
      console.error('Error during logout:', error);
    } finally {
      loggingOut = false;
      showLogoutConfirm = false;
    }
  }

  function cancelLogout() {
    showLogoutConfirm = false;
  }
</script>

<svelte:head>
  <title>Following._</title>
  <meta name="description" content="Create, share, and discover Nostr Follow Packs" />
</svelte:head>

<div class="min-h-screen flex flex-col">
  <header class="bg-surface shadow-sm">
    <div class="container py-4 flex justify-between items-center">
      <div class="flex items-center">
        <a class="hidden sm:inline"href="/"><img src="/farm.png" alt="Sheep" class="mx-auto mr-2 dark:invert" style="max-height: 40px;"></a>
        <a href="/" class="text-2xl font-bold text-foreground">Following._</a>
      </div>
      <div class="flex items-center gap-3">
          <a href="/settings" aria-label="Settings" title="Settings" class="inline-flex h-10 w-10 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="m9.5 3-.6 2.4-1.6.9L5 5.6 2.5 10l1.7 1.7v1.8L2.5 15 5 19.4l2.3-.7 1.6.9.6 2.4h5l.6-2.4 1.6-.9 2.3.7 2.5-4.4-1.7-1.5v-1.8l1.7-1.7L19 5.6l-2.3.7-1.6-.9L14.5 3z" />
              <circle cx="12" cy="12.5" r="3" />
            </svg>
          </a>
        {#if $user}
          <div class="relative user-menu-container">
            <button 
              on:click={toggleUserMenu}
              class="flex items-center space-x-2 focus:outline-none"
            >
              <ProfileImage 
                src={$user.picture} 
                alt={$user.name || 'User'} 
                size="md"
              />
              <span class="font-medium">{$user.name || 'Anonymous'}</span>
              <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-muted-foreground" viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
              </svg>
            </button>
            
            {#if showUserMenu}
              <div class="absolute right-0 mt-2 w-48 py-2 bg-surface rounded-md shadow-lg z-10 border border-line">
                <button
                  on:click={handleLogout}
                  class="block w-full text-left px-4 py-2 text-sm text-danger hover:bg-muted"
                >
                  Logout
                </button>
              </div>
            {/if}
          </div>
        {:else}
          <LoginButton />
        {/if}
      </div>
    </div>
  </header>

  <!-- Logout Confirmation Modal -->
  {#if showLogoutConfirm}
    <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div class="bg-surface rounded-lg p-6 max-w-md w-full">
        <h3 class="text-xl font-bold text-foreground mb-4">Logout Confirmation</h3>
        <p class="text-body mb-6">
          Are you sure you want to log out? You will need to log in again to access your account.
        </p>
        <div class="flex justify-end space-x-3">
          <button 
            on:click={cancelLogout} 
            class="btn btn-secondary"
            disabled={loggingOut}
          >
            Cancel
          </button>
          <button 
            on:click={confirmLogout} 
            class="btn btn-error"
            disabled={loggingOut}
          >
            {loggingOut ? 'Logging out...' : 'Logout'}
          </button>
        </div>
      </div>
    </div>
  {/if}

  <main class="flex-1">
    {#if $userWarning || $publishNotice}<p role="status" class="container p-4 text-warning">{$userWarning || $publishNotice}</p>{/if}
    <slot />
  </main>

  <footer class="bg-surface border-t">
    <div class="container py-6 text-center text-muted-foreground">
      <p><strong>Following._</strong> is open source and made by <a href="https://github.com/callebtc/nostr-follow-packs" class="text-accent hover:text-accent">calle</a> with love.</p>
    </div>
  </footer>
</div>
