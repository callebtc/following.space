import { beforeEach, expect, it, vi } from 'vitest';
vi.mock('blossom-client-sdk/actions/upload', () => ({ uploadBlob: vi.fn() }));
vi.mock('blossom-client-sdk', () => ({ createUploadAuth: vi.fn() }));
import { uploadBlob } from 'blossom-client-sdk/actions/upload';
import { createUploadAuth } from 'blossom-client-sdk';
import { DEFAULT_BLOSSOM_SERVERS, normalizeBlossomServers, uploadPackMedia } from '../src/lib/features/media/blossom';
beforeEach(() => vi.resetAllMocks());
it('normalizes bare hosts and includes Ditto in defaults', () => {
  expect(DEFAULT_BLOSSOM_SERVERS).toContain('https://blossom.ditto.pub/');
  expect(normalizeBlossomServers(['media.example', 'wss://secure.example'])).toEqual(['http://media.example/', 'https://secure.example/']);
  for (const invalid of [[], ['javascript:alert(1)'], ['https://user:password@media.example'], ['https://media.example/path']]) expect(() => normalizeBlossomServers(invalid)).toThrow();
});
it('uploads media through the SDK with server scoped auth and ordered fallback', async () => {
  const file = new File(['image'], 'cover.png', { type: 'image/png' });
  const signed = { id: 'auth' } as any;
  const signer = vi.fn();
  vi.mocked(createUploadAuth).mockResolvedValue(signed);
  vi.mocked(uploadBlob).mockRejectedValueOnce(new Error('Offline')).mockImplementationOnce(async (server, blob, options) => {
    expect(blob).toBe(file);
    expect(await options?.onAuth?.(server, 'hash', 'upload', blob)).toBe(signed);
    return { url: 'https://second.example/hash.png', sha256: 'hash', size: 5, uploaded: 1 };
  });
  const result = await uploadPackMedia(file, ['https://first.example', 'https://second.example'], signer);
  expect(result.url).toBe('https://second.example/hash.png');
  expect(createUploadAuth).toHaveBeenCalledWith(signer, 'hash', { type: 'upload', servers: ['https://second.example/'] });
  expect(uploadBlob).toHaveBeenCalledTimes(2);
});
it('reports complete upload failure and does not upload after cancellation', async () => {
  const file = new File(['data'], 'media.mp4');
  vi.mocked(uploadBlob).mockRejectedValue(new Error('Rejected'));
  await expect(uploadPackMedia(file, ['https://media.example'], vi.fn())).rejects.toThrow('Rejected');
  vi.mocked(uploadBlob).mockClear();
  const controller = new AbortController(); controller.abort();
  await expect(uploadPackMedia(file, ['https://media.example'], vi.fn(), controller.signal)).rejects.toThrow();
  expect(uploadBlob).not.toHaveBeenCalled();
});
