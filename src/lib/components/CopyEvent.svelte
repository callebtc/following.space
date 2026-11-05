<script lang="ts">
  import { packNaddr } from '$lib/nostr/protocol/pack-link';
  
  export let identifier: string;
  export let pubkey: string;
  export let relays: string[] = [];
  
  let copied = false;
  
  async function copyEvent() {
    const nostrLink = `nostr:${packNaddr({ id: identifier, pubkey }, relays)}`;

    // Copy to clipboard using execCommand as fallback
    try {
      // Modern method
      await navigator.clipboard.writeText(nostrLink);
      
      // Show copied state
      copied = true;
      setTimeout(() => {
        copied = false;
      }, 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
      // Fallback for older browsers
      const textarea = document.createElement('textarea');
      textarea.textContent = nostrLink;
      textarea.style.position = 'fixed';
      document.body.appendChild(textarea);
      textarea.select();
      
      try {
        document.execCommand('copy');
        copied = true;
        setTimeout(() => {
          copied = false;
        }, 2000);
      } catch (e) {
        console.error('Fallback copy failed:', e);
      } finally {
        document.body.removeChild(textarea);
      }
    }
  }
</script>

<button 
  on:click={copyEvent} 
  class="inline-flex items-center justify-center px-2 py-1 text-xs font-medium text-body bg-muted rounded-full hover:bg-placeholder transition-colors min-w-[110px]"
  title="Copy Nostr pack link"
>
  {#if copied}
    <span>Copied!</span>
  {:else}
    <span>Copy Pack Link</span>
  {/if}
</button>
