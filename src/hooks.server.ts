import type { Handle } from '@sveltejs/kit';
import { getPreview } from '$lib/server/previews';
import { previewMeta } from '$lib/server/previews/metadata';
export const handle: Handle = async ({ event, resolve }) => {
  const match = event.url.pathname.match(/^\/d\/([^/]+)$/);
  if (!match || !/bot|facebook|twitter|slack|discord|telegram|linkedin|whatsapp|signal|Amethyst/i.test(event.request.headers.get('user-agent') || '')) return resolve(event);
  try {
    const signal = AbortSignal.any([event.request.signal, AbortSignal.timeout(9000)]);
    const preview = await getPreview(decodeURIComponent(match[1]), event.url.searchParams.get('p') || undefined, signal);
    if (!preview) return resolve(event);
    return resolve(event, { transformPageChunk: ({ html }) => html.replace('</head>', previewMeta(preview.pack, event.url.origin, preview.image) + '</head>') });
  } catch { return resolve(event); }
};
