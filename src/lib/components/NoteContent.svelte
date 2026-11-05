<script lang="ts">
  import { getParsedContent } from 'applesauce-content/text';
  import { isImageURL, type NostrEvent } from 'applesauce-core/helpers';
  export let event: NostrEvent;
  $: nodes = getParsedContent(event).children;
  function safeURL(value: string) {
    try { const url = new URL(value); return ['https:', 'http:'].includes(url.protocol) ? url.href : undefined; }
    catch { return undefined; }
  }
</script>
<div class="whitespace-pre-wrap break-words">
  {#each nodes as node}
    {#if node.type === 'text'}{node.value}{:else if node.type === 'link'}
      {#if safeURL(node.href)}
        {#if isImageURL(node.href)}<img src={safeURL(node.href)} alt="Post attachment" loading="lazy" class="mt-2 rounded-lg max-w-full max-h-96" />
        {:else}<a href={safeURL(node.href)} target="_blank" rel="noopener noreferrer" class="text-accent underline">{node.value}</a>{/if}
      {:else}{node.value}{/if}
    {:else if node.type === 'mention'}<a href={'https://njump.me/' + node.encoded} target="_blank" rel="noopener noreferrer" class="text-accent">{node.encoded}</a>
    {:else if node.type === 'hashtag'}<span class="text-accent">#{node.name}</span>
    {:else if node.type === 'emoji'}{#if safeURL(node.url)}<img src={safeURL(node.url)} alt={node.raw} loading="lazy" class="inline h-6 w-6" />{:else}{node.raw}{/if}
    {:else if node.type === 'gallery'}{#each node.links as link}{#if safeURL(link)}<img src={safeURL(link)} alt="Post attachment" loading="lazy" class="mt-2 rounded-lg max-w-full max-h-96" />{/if}{/each}
    {:else if node.type === 'blossom'}{node.raw}
    {/if}
  {/each}
</div>
