import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { previewKey } from './metadata';
import { readPreview } from './reader';

const directory = path.join(process.cwd(), '.cache/previews');
const pending = new Map<string, ReturnType<typeof generate>>();
const metadata = new Map<string, { until: number; result: Awaited<ReturnType<typeof generate>> }>();
async function generate(id: string, pubkey: string | undefined, signal: AbortSignal) {
  const result = await readPreview(id, pubkey, signal);
  if (!result) return null;
  const key = previewKey(result.pack);
  let image = '/farm.png';
  try {
    await mkdir(directory, { recursive: true });
    try { await readFile(path.join(directory, `${key}.png`)); }
    catch {
      const { renderPreview } = await import('./render');
      const buffer = await renderPreview(result.pack, result.pictures, signal);
      await writeFile(path.join(directory, `${key}.png`), buffer);
    }
    image = `/preview-images/${key}.png`;
  } catch { /* Metadata remains useful without generated images. */ }
  return { pack: result.pack, image };
}
export function getPreview(id: string, pubkey: string | undefined, signal: AbortSignal) {
  const key = JSON.stringify([id, pubkey]);
  const cached = metadata.get(key);
  if (cached && cached.until > Date.now()) return Promise.resolve(cached.result);
  if (pending.has(key)) return pending.get(key)!;
  const task = generate(id, pubkey, signal).then((result) => {
    metadata.set(key, { result, until: Date.now() + 60000 });
    if (metadata.size > 64) metadata.delete(metadata.keys().next().value!);
    return result;
  }).finally(() => pending.delete(key));
  pending.set(key, task); return task;
}
export async function readPreviewImage(key: string) {
  if (!/^[0-9a-f]{64}$/.test(key)) return null;
  try { return await readFile(path.join(directory, `${key}.png`)); } catch { return null; }
}
