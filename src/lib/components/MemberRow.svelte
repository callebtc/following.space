<script lang="ts">
  import type { NostrRuntime } from '$lib/nostr/runtime';
  import type { FollowListEntry } from '$lib/types/follow-list';
  import { observeProfile } from '$lib/features/profiles/profile';
  import { observableReadable } from '$lib/reactivity/readable';
  import ProfileImage from './ProfileImage.svelte';
  import PublicKeyDisplay from './PublicKeyDisplay.svelte';
  import FollowButton from './FollowButton.svelte';
  import { npubEncode } from 'applesauce-core/helpers';
  export let runtime: NostrRuntime;
  export let entry: FollowListEntry;
  $: profile = observableReadable(observeProfile(runtime, entry.pubkey), {});
</script>
<li class="p-4 sm:p-6 flex items-start justify-between gap-4">
  <a href={'https://njump.me/' + npubEncode(entry.pubkey)} target="_blank" rel="noopener noreferrer" class="flex items-start min-w-0">
    <ProfileImage src={$profile.picture} alt={$profile.name || 'User'} size="lg" classes="mr-4" />
    <div class="min-w-0"><h3 class="text-lg font-medium">{$profile.name || 'Unknown User'}</h3>
      <div class="text-xs text-muted-foreground"><PublicKeyDisplay pubkey={entry.pubkey} /> {$profile.nip05 || ''}</div>
      {#if $profile.bio}<p class="text-sm text-muted-foreground break-words">{$profile.bio.slice(0, 160)}</p>{/if}
    </div>
  </a>
  <FollowButton {entry} />
</li>
