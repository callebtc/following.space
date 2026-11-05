// Run against the dev/preview server: BASE_URL=http://127.0.0.1:5189 node tests/home-first-render.mjs
import { chromium } from 'playwright';
import { finalizeEvent, matchFilters } from 'applesauce-core/helpers';
import { PrivateKeySigner } from 'applesauce-signers';
import assert from 'node:assert/strict';

const signer = new PrivateKeySigner();
const pack = finalizeEvent({ kind: 39089, created_at: Math.floor(Date.now() / 1000), content: '',
  tags: [['d', 'first-render'], ['title', 'First render garden']] }, signer.key);
const browser = await chromium.launch({ headless: true,
  ...(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {}), args: ['--no-sandbox'] });
try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('https://**', (route) => route.fulfill({ json: { supported_nips: [] }, headers: { 'access-control-allow-origin': '*' } }));
  await page.routeWebSocket(/.*/, (socket) => socket.onMessage((raw) => {
    const message = JSON.parse(String(raw));
    if (message[0] !== 'REQ') return;
    if (matchFilters(message.slice(2), pack)) socket.send(JSON.stringify(['EVENT', message[1], pack]));
    socket.send(JSON.stringify(['EOSE', message[1]]));
  }));
  await page.addInitScript((pack) => {
    window.nostrdb = { query: async () => [pack], add: async () => true };
  }, pack);
  await page.goto(process.env.BASE_URL || 'http://127.0.0.1:5189');
  const card = page.getByRole('link').filter({ has: page.getByRole('heading', { name: 'First render garden', exact: true }) });
  await card.waitFor();
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await page.getByRole('heading', { name: 'Settings', exact: true }).waitFor();
  await page.evaluate(() => {
    window.homeFlashes = [];
    new MutationObserver(() => {
      if (document.querySelector('main h1')?.textContent?.includes('Nostr Follow Packs')) {
        if (document.querySelector('main .animate-pulse')) window.homeFlashes.push('skeleton');
        if (!document.querySelector('main a[href^="/d/"]')) window.homeFlashes.push('missing cards');
      }
    }).observe(document.querySelector('main'), { childList: true, subtree: true });
  });
  await page.goBack();
  await card.waitFor();
  assert.deepEqual(await page.evaluate(() => window.homeFlashes), []);
  assert.deepEqual(errors, []);
  console.log('Home revisit renders cached cards on the first DOM update without a skeleton flash.');
} finally { await browser.close(); }
