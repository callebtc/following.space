import { readPreviewImage } from '$lib/server/previews';
import type { RequestHandler } from './$types';
export const GET: RequestHandler = async ({ params }) => {
  const image = await readPreviewImage(params.key);
  return image ? new Response(new Uint8Array(image), { headers: { 'content-type': 'image/png', 'cache-control': 'public, max-age=31536000, immutable' } }) : new Response('Preview not found', { status: 404 });
};
