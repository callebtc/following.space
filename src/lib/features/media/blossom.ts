import { ensureHttpURL } from 'applesauce-core/helpers';
import { createUploadAuth, type Signer } from 'blossom-client-sdk';
import { uploadBlob } from 'blossom-client-sdk/actions/upload';

export const DEFAULT_BLOSSOM_SERVERS = ['https://blossom.primal.net/', 'https://blossom.ditto.pub/'];
export function normalizeBlossomServers(values: string[]): string[] {
  const servers = values.map((value) => {
    try {
      const url = new URL(ensureHttpURL(value.trim()));
      if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error();
      return url.origin + '/';
    } catch { throw new Error(`Invalid Blossom server URL: ${value}. Enter an HTTP or HTTPS server address.`); }
  });
  if (!servers.length) throw new Error('Add at least one Blossom server.');
  return [...new Set(servers)];
}

/** All pack media uploads use the SDK, trying configured servers in order. */
export async function uploadPackMedia(file: File, servers: string[], signer: Signer, signal?: AbortSignal) {
  if (!file.size) throw new Error('Choose a non-empty media file.');
  const normalized = normalizeBlossomServers(servers);
  const failures: string[] = [];
  for (const server of normalized) {
    signal?.throwIfAborted();
    try {
      const blob = await uploadBlob(server, file, {
        signal, timeout: 30000,
        onAuth: async (target, hash, type) => {
          signal?.throwIfAborted();
          return createUploadAuth(signer, hash, { type, servers: [target] });
        }
      });
      const url = new URL(blob.url);
      if (!['https:', 'http:'].includes(url.protocol)) throw new Error('Server returned an invalid media URL');
      return blob;
    } catch (error) {
      signal?.throwIfAborted();
      failures.push(`${server}: ${error instanceof Error ? error.message : 'Upload failed'}`);
    }
  }
  throw new Error(`Media upload failed. ${failures.join('; ')}`);
}
