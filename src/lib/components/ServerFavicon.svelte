<script lang="ts">
  export let server: string;
  let failed = false;
  $: source = new URL('/favicon.ico', server).href;
  $: if (source) failed = false;
</script>

<span class="flex h-5 w-5 shrink-0 items-center justify-center" aria-hidden="true">
  {#if failed}
    <svg class="h-5 w-5 text-muted-foreground" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="4" width="18" height="16" rx="3" /><path d="M3 14h18M7 17h.01M11 17h.01" /></svg>
  {:else}
    <img src={source} alt="" class="h-5 w-5 object-contain" loading="lazy" referrerpolicy="no-referrer" on:error={() => failed = true} />
  {/if}
</span>
