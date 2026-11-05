<script lang="ts">
  import { user } from '$lib/stores/user';
  import { logout } from '$lib/stores/login';
  import { initializingAuth } from '$lib/services/auth';
  import LoginModal from './LoginModal.svelte';

  let isLoginModalOpen = false;
  let isLoggedIn = false;

  // Subscribe to the user store to know if the user is logged in
  $: isLoggedIn = !!$user;

  function openLoginModal() {
    isLoginModalOpen = true;
    // abort any existing login attempt
    initializingAuth.set(false);
  }

  function closeLoginModal() {
    isLoginModalOpen = false;
  }

  function handleLogin() {
    // The modal will handle the login process
    // This is a callback that will be fired when login is complete
  }

  function handleLogout() {
    logout();

  }
</script>

<div>
  {#if $initializingAuth}
    <button 
    on:click={openLoginModal}
      class="px-4 py-2 text-sm font-medium text-white bg-purple-500 rounded-lg flex items-center"
    >
      <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
      </svg>
      Logging in...
    </button>
  {:else if isLoggedIn}
    <button 
      on:click={handleLogout}
      class="px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-lg"
    >
      Log out
    </button>
  {:else}
    <button 
      on:click={openLoginModal}
      class="px-4 py-2 text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 rounded-lg"
    >
      Log in
    </button>
  {/if}
</div>

<LoginModal 
  isOpen={isLoginModalOpen} 
  onClose={closeLoginModal} 
  onLogin={handleLogin}
/> 