// Run against `npm run build && npm run preview -- --port 5188` with `npm run test:browser`.
// Uses generated keys, a simulated cache, and simulated relay traffic; no public writes.
import { chromium } from 'playwright';
import { finalizeEvent, matchFilters, nsecEncode, decodePointer } from 'applesauce-core/helpers';
import { PrivateKeySigner } from 'applesauce-signers';
import assert from 'node:assert/strict';
const base = process.env.BASE_URL || 'http://127.0.0.1:5188';
const signer = new PrivateKeySigner(); const member = new PrivateKeySigner();
const key = signer.key; const pubkey = await signer.getPublicKey(); const memberPubkey = await member.getPublicKey();
const now = Math.floor(Date.now() / 1000);
const pack = finalizeEvent({ kind: 39089, created_at: now - 120, content: '', tags: [['d', 'browser-smoke'], ['title', 'Reactive Garden'], ['p', memberPubkey]] }, key);
const events = [pack,
  finalizeEvent({ kind: 0, created_at: now - 100, tags: [], content: JSON.stringify({ name: 'Garden Author' }) }, key),
  finalizeEvent({ kind: 0, created_at: now - 100, tags: [], content: JSON.stringify({ name: 'Garden Member' }) }, member.key),
  finalizeEvent({ kind: 1, created_at: now - 60, tags: [], content: '<img src=x onerror="window.smokeXss=true"> https://example.com/article' }, member.key)
];
const browser = await chromium.launch({ headless: true,
  ...(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {}), args: ['--no-sandbox'] });
const page = await browser.newPage(); page.setDefaultTimeout(20000);
const errors = []; const published = []; const frames = []; const active = new Map();
page.on('pageerror', (error) => errors.push(error.message));
await page.exposeFunction('extensionPubkey', () => pubkey);
await page.exposeFunction('extensionSign', (template) => finalizeEvent(template, key));
await page.route('https://**', (route) => route.fulfill({ json: { supported_nips: [] }, headers: { 'access-control-allow-origin': '*' } }));
await page.route('https://ranking.vertexlab.io/**', (route) => route.fulfill({
  json: route.request().url().endsWith('/.well-known/open-ranking.json')
    ? { '/search/pubkeys': [{ id: 'global' }] }
    : { results: [{ pubkey: memberPubkey, rank: 42 }] },
  headers: { 'access-control-allow-origin': '*' }
}));
await page.routeWebSocket(/.*/, (socket) => {
  const requests = new Map(); active.set(socket, requests);
  socket.onMessage((raw) => {
    const msg = JSON.parse(String(raw)); frames.push(msg[0]);
    if (msg[0] === 'REQ') {
      requests.set(msg[1], msg.slice(2));
      for (const event of events.filter((event) => matchFilters(msg.slice(2), event))) socket.send(JSON.stringify(['EVENT', msg[1], event]));
      socket.send(JSON.stringify(['EOSE', msg[1]]));
    } else if (msg[0] === 'CLOSE') requests.delete(msg[1]);
    else if (msg[0] === 'EVENT') {
      const event = msg[1];
      if (!events.some((known) => known.id === event.id)) { events.push(event); published.push(event); }
      socket.send(JSON.stringify(['OK', event.id, true, '']));
      for (const [destination, filters] of active) for (const [id, fs] of filters) {
        if (matchFilters(fs, event)) destination.send(JSON.stringify(['EVENT', id, event]));
      }
    }
  });
  socket.onClose(() => active.delete(socket));
});
await page.addInitScript((initial) => {
  window.nostrdb = { query: async (filters) => initial.filter((event) => filters.some((f) =>
    (!f.kinds || f.kinds.includes(event.kind)) && (!f.authors || f.authors.includes(event.pubkey)) &&
    (f.since === undefined || event.created_at >= f.since) && (f.until === undefined || event.created_at <= f.until) &&
    Object.entries(f).filter(([key]) => key.startsWith('#')).every(([key, values]) => event.tags.some((tag) => tag[0] === key.slice(1) && values.includes(tag[1])))
  )), add: async (event) => { if (!initial.some((known) => known.id === event.id)) initial.push(event); return true; } };
  localStorage.setItem('unrelated-preference', 'keep');
}, events);
try {
  await page.goto(base);
  await page.getByRole('heading', { name: 'Reactive Garden', exact: true }).waitFor();
  const card = page.getByRole('link').filter({ has: page.getByRole('heading', { name: 'Reactive Garden', exact: true }) });
  const cardHref = await card.getAttribute('href');
  assert.ok(cardHref?.startsWith('/d/'));
  const pointer = decodePointer(cardHref.slice('/d/'.length));
  assert.equal(pointer.type, 'naddr');
  assert.equal(pointer.data.kind, 39089);
  assert.equal(pointer.data.pubkey, pubkey);
  assert.equal(pointer.data.identifier, 'browser-smoke');
  assert.ok((pointer.data.relays ?? []).length <= 3);
  await card.click();
  await page.getByRole('heading', { name: 'Reactive Garden', exact: true }).waitFor();
  await page.goto(`${base}/d/browser-smoke?p=${pubkey}`);
  await page.getByRole('heading', { name: 'Reactive Garden', exact: true }).waitFor();
  await page.getByRole('button', { name: 'Posts', exact: true }).click();
  await page.getByText('<img src=x onerror="window.smokeXss=true">', { exact: false }).waitFor();
  assert.equal(await page.evaluate(() => window.smokeXss), undefined);
  await page.getByRole('link', { name: 'https://example.com/article', exact: true }).waitFor();
  await page.getByRole('button', { name: 'People', exact: true }).click();
  await page.getByRole('button', { name: 'Log in', exact: true }).click();
  await page.getByPlaceholder('nsec1...').fill(nsecEncode(key));
  await page.getByRole('button', { name: 'Login with Nsec', exact: true }).click();
  await page.getByRole('link', { name: 'Edit List', exact: true }).waitFor();
  assert.ok(!JSON.stringify(await page.evaluate(() => ({ ...localStorage, ...sessionStorage }))).includes(nsecEncode(key)));
  await page.getByRole('button', { name: 'Follow All', exact: true }).click();
  await page.getByText('Follow list updated.', { exact: true }).waitFor();
  assert.equal(published.filter((event) => event.kind === 3).length, 1);
  await page.getByRole('button', { name: 'Following', exact: true }).waitFor();
  await page.getByRole('link', { name: 'Edit List', exact: true }).click();
  await page.locator('#name').fill('Updated Garden');
  await page.getByRole('button', { name: 'Update Follow Pack', exact: true }).click();
  await page.getByRole('heading', { name: 'Updated Garden', exact: true }).waitFor();
  assert.equal(published.filter((event) => event.kind === 39089).length, 1);
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await page.getByRole('heading', { name: 'Settings', exact: true }).waitFor();
  const mediaServers = page.getByRole('list', { name: 'Media servers', exact: true });
  await mediaServers.getByText('blossom.ditto.pub', { exact: true }).waitFor();
  await page.getByLabel('Add a media server', { exact: true }).fill('media.example');
  await page.getByRole('button', { name: 'Add server', exact: true }).click();
  await mediaServers.getByText('media.example', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Make media.example default', exact: true }).click();
  await page.getByText('Media servers saved.', { exact: true }).waitFor();
  assert.equal((await mediaServers.getByRole('listitem').first().innerText()).includes('media.example'), true);
  assert.equal(published.filter((event) => event.kind === 10063).at(-1).tags.find((tag) => tag[0] === 'server')[1], 'http://media.example/');
  await page.getByLabel('Add a media server', { exact: true }).fill('media.example');
  await page.getByRole('button', { name: 'Add server', exact: true }).click();
  await page.getByText('This server is already in your list.', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Remove media.example', exact: true }).click();
  await mediaServers.getByText('media.example', { exact: true }).waitFor({ state: 'detached' });

  await page.getByRole('button', { name: 'Restore', exact: true }).first().click();
  await page.getByText(/Successfully restored 1 follows/).waitFor();
  assert.equal(published.filter((event) => event.kind === 3).length, 2);
  await page.locator('header .user-menu-container > button').click();
  await page.getByRole('button', { name: 'Logout', exact: true }).click();
  await page.getByRole('button', { name: 'Logout', exact: true }).click();
  await page.getByRole('button', { name: 'Log in', exact: true }).waitFor();
  assert.equal(await page.evaluate(() => localStorage.getItem('unrelated-preference')), 'keep');
  assert.ok(await page.evaluate((pubkey) => localStorage.getItem(`following:v2:snapshots:${pubkey}`), pubkey));
  // A real extension API shape signs generated fixtures through the Node test process.
  await page.addInitScript(() => { window.nostr = { getPublicKey: () => window.extensionPubkey(), signEvent: (draft) => window.extensionSign(draft) }; });
  await page.reload();
  await page.getByRole('button', { name: 'Log in', exact: true }).click();
  await page.getByRole('button', { name: 'Login with Extension', exact: true }).click();
  await page.locator('header .user-menu-container > button').waitFor();
  await page.reload();
  await page.locator('header .user-menu-container > button').waitFor();
  await page.goto(base);
  await page.getByRole('heading', { name: 'Updated Garden', exact: true }).waitFor();
  await page.getByRole('link').filter({ has: page.getByRole('heading', { name: 'Updated Garden', exact: true }) }).click();
  await page.getByRole('link', { name: 'Edit List', exact: true }).click();
  await page.getByRole('button', { name: 'Delete List', exact: true }).click();
  await page.getByRole('button', { name: 'Delete Forever', exact: true }).click();
  await page.waitForURL(base + '/');
  assert.equal(published.filter((event) => event.kind === 5).length, 1);
  const deletion = published.find((event) => event.kind === 5);
  assert.ok(deletion.tags.some((tag) => tag[0] === 'a' && tag[1] === `39089:${pubkey}:browser-smoke`));
  await page.getByRole('button', { name: 'Create New Follow Pack', exact: true }).click();
  await page.locator('#name').fill('New Garden');
  await page.locator('#search').fill('Garden');
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await page.getByRole('button', { name: 'Add to List', exact: true }).click();
  await page.getByRole('button', { name: 'Publish Follow Pack', exact: true }).click();
  await page.getByRole('heading', { name: 'New Garden', exact: true }).waitFor();
  assert.equal(published.filter((event) => event.kind === 39089).length, 2);
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ guestReads: true, safePosts: true, nsecLogin: true, bulkFollow: true, edit: true, snapshots: true,
    logoutPreservesStorage: true, extensionLoginAndReload: true, deletion: true, createAndSearch: true, pageErrors: errors,
    publishedKinds: published.map((event) => event.kind), closeFrames: frames.filter((frame) => frame === 'CLOSE').length }));
} catch (error) {
  console.error('Browser smoke failed at', page.url(), '\n', (await page.locator('body').innerText()).slice(-5000));
  throw error;
} finally { await browser.close(); }
