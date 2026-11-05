import { createCanvas, loadImage, registerFont } from 'canvas';
import { lookup } from 'node:dns/promises';
import type { LookupAddress } from 'node:dns';
import type { FollowList } from '../../nostr/protocol/follow-pack';
import path from 'node:path';
import { APP_NAME } from '../../constants';
let fontsReady = false;

async function remoteImage(value: string, signal: AbortSignal) {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(1500)]);
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Unsupported image URL');
  const addresses = await new Promise<LookupAddress[]>((resolve, reject) => {
    const abort = () => reject(new Error('Image lookup timed out'));
    deadline.throwIfAborted();
    deadline.addEventListener('abort', abort, { once: true });
    void lookup(url.hostname, { all: true }).then(resolve, reject).finally(() => deadline.removeEventListener('abort', abort));
  });
  // Reject local addresses before fetching profile images.
  if (!Array.isArray(addresses) || !addresses.length || addresses.some(({ address }) => /^(127\.|10\.|192\.168\.|169\.254\.|0\.|172\.(1[6-9]|2\d|3[01])\.|::|fc|fd|fe80:)/i.test(address))) throw new Error('Private image host');
  const response = await fetch(url, { signal: deadline, redirect: 'error' });
  if (!response.ok || !response.headers.get('content-type')?.startsWith('image/')) throw new Error('Image unavailable');
  const reader = response.body!.getReader();
  const chunks: Uint8Array[] = []; let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      bytes += value.length; if (bytes > 2_000_000) throw new Error('Image too large'); chunks.push(value);
    }
  } finally { await reader.cancel(); }
  return loadImage(Buffer.concat(chunks));
}
export async function renderPreview(pack: FollowList, pictures: string[], signal: AbortSignal) {
  if (!fontsReady) {
    registerFont(path.join(process.cwd(), 'static/fonts/Manrope-Regular.ttf'), { family: 'Manrope' });
    registerFont(path.join(process.cwd(), 'static/fonts/Manrope-Bold.ttf'), { family: 'Manrope', weight: 'bold' });
    fontsReady = true;
  }
  const images = await Promise.allSettled(pictures.slice(0, 6).map((url) => remoteImage(url, signal)));
  signal.throwIfAborted();
  const canvas = createCanvas(1200, 630); const ctx = canvas.getContext('2d');
  const gradient = ctx.createLinearGradient(0, 0, 1200, 630);
  gradient.addColorStop(0, '#6366f1'); gradient.addColorStop(1, '#8b5cf6');
  ctx.fillStyle = gradient; ctx.fillRect(0, 0, 1200, 630);
  ctx.fillStyle = '#ffffff'; ctx.textAlign = 'center'; ctx.font = 'bold 40px Manrope';
  ctx.fillText('NOSTR FOLLOW PACK', 600, 85);
  const loaded = images.flatMap((image) => image.status === 'fulfilled' ? [image.value] : []);
  loaded.forEach((image, i) => {
    const x = 600 - loaded.length * 85 + i * 170;
    ctx.save(); ctx.beginPath(); ctx.arc(x + 80, 220, 75, 0, Math.PI * 2); ctx.clip();
    const size = Math.min(image.width, image.height);
    ctx.drawImage(image, (image.width - size) / 2, (image.height - size) / 2, size, size, x + 5, 145, 150, 150); ctx.restore();
  });
  ctx.font = 'bold 70px Manrope';
  const words = pack.name.slice(0, 200).split(' '); let line = ''; const lines: string[] = [];
  for (const word of words) {
    if (ctx.measureText(line + word).width > 1080 && line) { lines.push(line); line = ''; }
    line += word + ' ';
  }
  lines.push(line);
  lines.slice(0, 2).forEach((text, index) => ctx.fillText(text.trim(), 600, 400 + index * 80, 1080));
  ctx.font = '32px Manrope'; ctx.fillText(`${pack.entries.length} people · ${APP_NAME}`, 600, 570);
  return canvas.toBuffer('image/png');
}
