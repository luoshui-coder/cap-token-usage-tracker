import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chromium } from 'playwright-core';

const [htmlPath, chromePath] = process.argv.slice(2);
const html = (await readFile(htmlPath, 'utf8')).replace('function cpamcNameRegistries(){', 'window.testCPAMCSHA256=cpamcSHA256;window.testCPAMCRegistries=cpamcNameRegistries;function cpamcNameRegistries(){');
const base = '/v0/resource/plugins/key-share-test';
const alice = 'g1:' + 'a'.repeat(32), bob = 'g1:' + 'b'.repeat(32);
const labels = {};
const aliceName = '测试用户甲', bobName = '测试用户乙 <script>alert(1)</script>';
const all = [
  { ref: alice, key: 'sk-fixture-alice', status: 'available', requests: 3, total_tokens: 10, failed_requests: 1 },
  { ref: bob, key: 'sk-fixture-bob', status: 'available', requests: 1, total_tokens: 90, failed_requests: 0 },
];
const server = createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname.endsWith('/dashboard')) {
    res.writeHead(200, { 'content-type': 'text/html' }); res.end(html); return;
  }
  let data = {};
  const path = url.pathname.slice(base.length);
  if (path === '/full-mode/data') data = { api_key_tracking_enabled: true, api_key_labels: labels };
  if (path === '/full-mode/api-key-labels') {
    const update = JSON.parse(req.headers['x-api-key-label']); labels[update.ref] = update.label;
  }
  if (path === '/stats/initial') {
    const refs = url.searchParams.getAll('api_key_ref');
    const keys = all.map(item => refs.length && !refs.includes(item.ref) ? { ...item, requests: 0, total_tokens: 0, failed_requests: 0 } : item);
    data = { api_keys: keys, summary: { requests: keys.reduce((sum, item) => sum + item.requests, 0), total_tokens: keys.reduce((sum, item) => sum + item.total_tokens, 0) }, models: [], sources: [], series: [] };
  }
  if (path === '/stats/groups' || path === '/requests') data = { items: [], total: 0 };
  if (path === '/stats/trends') data = { model_series: [] };
  if (path === '/costs') data = { models: [], summary: {}, api_keys: [{ref: alice, total_usd: 1.25, requests:3, priced_requests:2, unpriced_requests:1}, {ref:bob,total_usd:3.5,requests:1,priced_requests:1,unpriced_requests:0}] };
  if (path === '/prices') data = { prices: {} };
  res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(data));
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const browser = await chromium.launch({ executablePath: chromePath, headless: true });
try {
  const page = await browser.newPage({ locale: 'zh-CN', viewport: { width: 1280, height: 1000 } });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const registry = Object.fromEntries(all.map((item, i) => [createHash('sha256').update(JSON.stringify(['api-key-name', origin, item.key])).digest('hex'), i ? bobName : aliceName]));
  await page.addInitScript(({ registry }) => {
    const plain = new TextEncoder().encode(JSON.stringify(registry));
    const salt = new TextEncoder().encode('cli-proxy-api-webui::secure-storage|' + location.host);
    const encoded = Array.from(plain, (byte, i) => String.fromCharCode(byte ^ salt[i % salt.length])).join('');
    localStorage.setItem('api-key-names:v1:' + location.origin, 'enc::v2::' + btoa(encoded));
  }, { registry });
  const errors = [];
  page.on('pageerror', error => errors.push(String(error)));
  await page.goto(`http://127.0.0.1:${server.address().port}${base}/dashboard#session=test`);
  const rows = page.locator('#apiKeyShareRows tr');
  await rows.first().waitFor();
  await page.waitForFunction(() => document.querySelector('#apiKeyShareRows').textContent.includes('测试用户甲'));
  assert.match(await rows.first().innerText(), /测试用户甲.*3.*10.*1.*75\.0%/s);
  assert.equal(await page.locator('#apiKeyShareRows script').count(), 0);
  await page.waitForFunction(() => document.querySelector('#apiKeyShareRows').textContent.includes('$1.25'));
  assert.match(await rows.first().innerText(), /\$1\.25 \*/);
  const shaInputs = ['', 'abc', '备注名字😀', 'x'.repeat(120)];
  for (const input of shaInputs) assert.equal(await page.evaluate(v => window.testCPAMCSHA256(v), input), createHash('sha256').update(input).digest('hex'));
  const donut = await page.locator('#apiKeyShareDonut').boundingBox();
  await page.mouse.move(donut.x + donut.width * 226 / 280, donut.y + donut.height / 2);
  await page.waitForFunction(() => document.querySelector('#tooltip').classList.contains('visible'));
  assert.ok(await page.locator('#apiKeySharePanel .table-scroll').evaluate(el => el.scrollWidth <= el.clientWidth + 1), 'desktop columns clipped');
  assert.match(await page.locator('#tooltip').innerText(), /测试用户甲/);
  assert.match(await page.locator('#tooltip').innerText(), /sk-••••ice/);
  assert.match(await page.locator('#tooltip').innerText(), /\$1\.25/);
  await page.locator('[data-api-key-share-metric="cost"]').click();
  assert.match(await rows.first().innerText(), /测试用户乙.*73\.7%/s);
  await page.locator('[data-api-key-share-metric="tokens"]').click();
  assert.match(await rows.first().innerText(), /测试用户乙.*90\.0%/s);
  await page.locator(`#apiKeyShareRows [data-api-key-label-ref="${alice}"]`).click();
  await page.locator('#apiKeyLabelInput').fill('测试用户甲（运维）');
  await page.locator('#saveAPIKeyLabel').click();
  await page.waitForFunction(() => document.querySelector('#apiKeyShareRows').textContent.includes('测试用户甲（运维）'));
  await page.locator(`#apiKeyShareRows [data-api-key-label-ref="${bob}"]`).click();
  await page.locator('#apiKeyLabelInput').fill('测试用户乙');
  await page.locator('#saveAPIKeyLabel').click();
  await page.waitForFunction(() => !document.querySelector('#apiKeyShareRows').textContent.includes('<script>'));
  await page.locator('#apiKeySharePanel').screenshot({path: new URL('../dist/key-share-panel.png', import.meta.url).pathname});
  await page.locator('#apiKeyFilterButton').click();
  await page.locator(`input[data-api-key-ref="${alice}"]`).check();
  await page.waitForFunction(() => document.querySelectorAll('#apiKeyShareRows tr').length === 1);
  assert.match(await rows.first().innerText(), /测试用户甲（运维）.*100\.0%/s);
  await page.locator('#apiKeyFilterButton').click();
  await page.setViewportSize({ width: 390, height: 844 });
  const bounds = await page.locator('#apiKeySharePanel').boundingBox();
  assert.ok(bounds.width <= 390, `mobile panel overflow: ${bounds.width}`);
  const padding = await page.locator('#apiKeySharePanel').evaluate(el => {const s=getComputedStyle(el);return [s.paddingTop,s.paddingRight,s.paddingBottom,s.paddingLeft].map(parseFloat);});
  assert.ok(padding.every(value => value >= 16), `missing panel padding: ${padding}`);
  await page.screenshot({path: new URL('../dist/key-share-mobile.png', import.meta.url).pathname, fullPage:false});
  await page.setViewportSize({width:1280,height:1000});
  await page.screenshot({path: new URL('../dist/key-share-desktop.png', import.meta.url).pathname, fullPage:false});
  assert.deepEqual(errors, []);
  console.log('API-key shares, sorting, labels, XSS, filtering and mobile layout passed');
} finally {
  await browser.close(); await new Promise(resolve => server.close(resolve));
}
