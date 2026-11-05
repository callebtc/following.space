<script lang="ts">
  import ProfileImage from './ProfileImage.svelte';
  import type { NostrRuntime } from '$lib/nostr/runtime';
  import { observeProfile } from '$lib/features/profiles/profile';
  import { observableReadable } from '$lib/reactivity/readable';

  export let runtime: NostrRuntime;
  export let pubkey: string;
  export let relays: string[] | undefined = undefined;
  export let showName = false;
  export let size: 'xs' | 'sm' | 'md' | 'lg' | 'xl' = 'md';
  export let classes = '';
  $: profile = observableReadable(observeProfile(runtime, pubkey, relays), {});
</script>

<ProfileImage src={$profile.picture} alt={$profile.name || 'User'} {size} {classes} style="margin-top: 0px;" />
{#if showName}<span class="text-sm text-muted-foreground">{$profile.name || pubkey.slice(0, 12) + '…'}</span>{/if}
