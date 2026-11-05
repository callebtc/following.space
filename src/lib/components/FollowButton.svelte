<script lang="ts">
  import { user, followUsers, unfollowUsers } from '$lib/stores/user';
  import type { FollowListEntry } from '$lib/types/follow-list';
  export let entry: FollowListEntry;
  export let variant: 'primary' | 'outline' = 'primary';
  let busy = false;
  let error = '';
  $: following = $user?.following.has(entry.pubkey) ?? false;
  async function toggle() {
    if (busy) return;
    busy = true; error = '';
    try { await (following ? unfollowUsers([entry.pubkey]) : followUsers([entry.pubkey])); }
    catch (err) { error = err instanceof Error ? err.message : 'Follow update failed'; }
    finally { busy = false; }
  }
</script>
{#if $user}
  <div><button disabled={busy} on:click={toggle} class="btn {following || variant === 'outline' ? 'btn-outline' : 'btn-primary'}">{busy ? 'Saving…' : following ? 'Following' : 'Follow'}</button>
    {#if error}<p role="alert" class="mt-2 text-xs text-danger max-w-48">{error}</p>{/if}
  </div>
{/if}
