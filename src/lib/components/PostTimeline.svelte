<script lang="ts">
  import { onMount } from 'svelte';
  import type { NostrRuntime } from '$lib/nostr/runtime';
  import { createPostTimeline, type PostState } from '$lib/features/timeline/posts';
  import { observableReadable } from '$lib/reactivity/readable';
  import { BehaviorSubject } from 'rxjs';
  import { getRelativeTime } from '$lib/utils/date';
  import ReactiveProfile from './ReactiveProfile.svelte';
  import NoteContent from './NoteContent.svelte';
  import FollowButton from './FollowButton.svelte';
  export let pubkeys: string[] = [];
  let runtime: NostrRuntime | undefined;
  let timeline: ReturnType<typeof createPostTimeline> | undefined;
  let state = observableReadable(new BehaviorSubject<PostState>({ events: [], loading: true }), { events: [], loading: true });
  onMount(() => {
    let cancelled = false;
    void import('$lib/nostr/runtime.client').then(({ getNostrRuntime }) => getNostrRuntime()).then((value) => {
      if (!cancelled) runtime = value;
    });
    return () => { cancelled = true; };
  });
  $: if (runtime) {
    timeline = createPostTimeline(runtime, pubkeys);
    state = observableReadable(timeline.state$, { events: [], loading: true });
  }
</script>
<div class="bg-surface rounded-lg shadow-sm overflow-hidden mx-auto max-w-[800px]">
  {#if $state.warning}<p role="status" class="p-4 text-warning">{$state.warning}</p>{/if}
  {#if $state.loading && !$state.events.length}<p class="p-8 text-muted-foreground">Loading posts…</p>
  {:else if !$state.events.length}<p class="p-8 text-muted-foreground">No posts found in this time range.</p>{/if}
  <ul class="divide-y divide-line">
    {#each $state.events as event (event.id)}
      <li class="p-4 sm:p-8">
        <div class="flex items-center mb-4 gap-2">
          {#if runtime}<ReactiveProfile {runtime} pubkey={event.pubkey} showName />{/if}
          <span class="text-xs text-muted-foreground">{getRelativeTime(event.created_at)}</span>
          <div class="ml-auto"><FollowButton entry={{ pubkey: event.pubkey }} /></div>
        </div>
        <NoteContent {event} />
      </li>
    {/each}
  </ul>
  <div class="p-4 text-center"><button class="btn btn-outline" disabled={$state.loading} on:click={() => timeline?.loadMore()}>Discover older posts</button></div>
</div>
