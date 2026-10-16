'use strict';

// Run with Node.js and Playwright. Set PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
// when using an existing Chromium installation instead of Playwright's browser.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {after, before, test} = require('node:test');
const {chromium} = require('playwright');

const ROOT = path.resolve(__dirname, '../..');
const UI = path.join(ROOT, 'client/ui');
const ORIGIN = 'http://oniondesk.test';
const CHOICES = [
  {device: 'windows', name: 'Windows', prefix: 'windows', count: 4},
  {device: 'macos', name: 'macOS', prefix: 'macos', count: 4},
  {device: 'linux', name: 'Linux', prefix: 'linux', count: 4},
  {device: 'tails', name: 'Tails', prefix: 'tails', count: 3},
  {device: 'android', method: 'usb', name: 'Android · USB', prefix: 'android-usb', count: 8},
  {device: 'android', method: 'phone', name: 'Android · без USB', prefix: 'android', count: 4},
  {device: 'iphone', name: 'iPhone', prefix: 'iphone', count: 5}
];
let browser;

before(async () => {
  const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
  browser = await chromium.launch({headless: true, args: ['--no-sandbox'], ...(executablePath ? {executablePath} : {})});
});
after(async () => { if (browser) await browser.close(); });

async function fixture(t, viewport = {width: 1280, height: 900}) {
  const session = await browser.newContext({viewport, reducedMotion: 'reduce'});
  t.after(() => session.close());
  const page = await session.newPage();
  const errors = [];
  const requests = [];
  const failed = new Set();
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    requests.push(url.href);
    if (url.origin !== ORIGIN) return route.abort('blockedbyclient');
    if (failed.has(url.pathname)) return route.abort('failed');
    const filename = path.join(url.pathname.startsWith('/assets/') ? ROOT : UI, url.pathname === '/' ? 'index.html' : url.pathname);
    const types = {'.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.png': 'image/png', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.svg': 'image/svg+xml'};
    try {
      const body = await fs.readFile(filename);
      return route.fulfill({contentType: types[path.extname(filename)] || 'application/octet-stream', body});
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      return route.fulfill({status: 404, body: 'Not found'});
    }
  });
  await page.goto(ORIGIN);
  await page.locator('[data-step="12"]').click();
  t.after(() => {
    assert.deepEqual(errors, [], 'The actual wizard must not produce JavaScript errors');
    assert.ok(requests.every((url) => url.startsWith(ORIGIN + '/')), 'No external request may escape the fixture');
    assert.ok(requests.every((url) => !url.includes('/api/')), 'Artwork navigation must not launch application operations');
  });
  return {page, failed};
}

async function selectChoice(page, choice) {
  await page.locator('#daily-device').selectOption(choice.device);
  if (choice.method) await page.locator('#daily-method').selectOption(choice.method);
}

async function art(page, source, state = 'ready', stage = 12) {
  await page.waitForFunction(({source, state, stage}) => {
    const image = document.querySelector(`[data-page="${stage}"] [data-goal-image]`);
    return image.getAttribute('src') === source && image.dataset.artState === state
      && image.complete && image.naturalWidth > 0;
  }, {source, state, stage});
  return page.locator(`[data-page="${stage}"] [data-goal-image]`);
}

async function assertChoice(page, choice, index) {
  const source = `/assets/device-steps/${choice.prefix}-${String(index + 1).padStart(2, '0')}.png`;
  const image = await art(page, source);
  const title = await page.locator('#daily-guide-title').textContent();
  const frame = page.locator('[data-page="12"] .goal-art-frame');
  assert.equal(await image.getAttribute('alt'), `Художественная иллюстрация действия: ${choice.name}: ${title}`);
  assert.equal(await frame.getAttribute('aria-label'), `${choice.name} · шаг ${index + 1} из ${choice.count}. Иллюстрация: ${choice.name}: ${title}`);
  assert.equal(await frame.locator('[data-art-step-label]').textContent(), `ЭТАП 12 / ${choice.name.toLocaleUpperCase('ru')} / ШАГ ${index + 1} ИЗ ${choice.count}`);
  assert.equal(await frame.getAttribute('aria-describedby'), 'daily-guide-position daily-guide-title');
  assert.equal(await frame.evaluate((element) => document.activeElement === element), true, 'Each hint starts at its illustration');
  assert.equal(await page.locator('#daily-guide-back').isDisabled(), index === 0);
  assert.equal(await page.locator('#daily-guide-next').isDisabled(), index === choice.count - 1);
  await page.locator('#view-scene').click();
  assert.equal(await page.locator('#guide-shot-viewer').evaluate((dialog) => dialog.open), true);
  assert.equal(await page.locator('#guide-shot-viewer-image').getAttribute('src'), source);
  assert.equal(await page.locator('#guide-shot-viewer-image').getAttribute('alt'), await image.getAttribute('alt'));
  await page.locator('#guide-shot-viewer-close').click();
  return source;
}

test('all 65 main actions retain their distinct original illustrations', {timeout: 60000}, async (t) => {
  const {page} = await fixture(t);
  const sources = new Set();
  for (let stage = 0; stage < 14; stage++) {
    await page.locator(`[data-step="${stage}"]`).click();
    const section = page.locator(`[data-page="${stage}"]`);
    const count = await section.locator('[data-inner-step]').count();
    for (let index = 0; index < count; index++) {
      if (index) await section.locator('[data-inner-next]').click();
      const card = section.locator(`[data-inner-step="${index}"]`);
      const key = await card.getAttribute('data-art-key');
      const source = `/assets/microsteps/${key}.png`;
      const image = await art(page, source, 'ready', stage);
      assert.equal(await image.getAttribute('data-art-key'), key);
      assert.equal(await image.getAttribute('alt'), 'Художественная иллюстрация действия: ' + await card.locator(':scope > h2').textContent());
      assert.equal(await section.locator('[data-art-step-label]').textContent(), `ЭТАП ${String(stage).padStart(2, '0')} / ДЕЙСТВИЕ ${index + 1}`);
      sources.add(source);
    }
  }
  assert.equal(sources.size, 65);
});

test('all 32 conditional device hints select unique artwork and open the matching illustration', {timeout: 60000}, async (t) => {
  const {page} = await fixture(t);
  const sources = new Set();
  for (const choice of CHOICES) {
    await selectChoice(page, choice);
    for (let index = 0; index < choice.count; index++) {
      if (index) await page.locator('#daily-guide-next').click();
      sources.add(await assertChoice(page, choice, index));
    }
  }
  assert.equal(sources.size, 32);
});

test('leaving, returning, changing a hidden guide, and clearing invalid selections restore the right main artwork', {timeout: 30000}, async (t) => {
  const {page} = await fixture(t);
  const section = page.locator('[data-page="12"]');
  await selectChoice(page, CHOICES[6]);
  await page.locator('#daily-guide-next').click();
  await page.locator('#daily-guide-next').click();
  await art(page, '/assets/device-steps/iphone-03.png');
  await section.locator('[data-inner-next]').click();
  await art(page, '/assets/microsteps/g12-s02.png');
  assert.equal(await section.locator('.goal-art-frame').getAttribute('aria-describedby'), null);
  await page.locator('#daily-device').selectOption('windows', {force: true});
  await art(page, '/assets/microsteps/g12-s02.png');
  await section.locator('[data-inner-back]').click();
  await art(page, '/assets/device-steps/windows-01.png');
  await selectChoice(page, CHOICES[6]);
  await art(page, '/assets/device-steps/iphone-03.png');
  await page.locator('[data-step="11"]').click();
  assert.equal(await section.locator('[data-goal-image]').getAttribute('src'), '/assets/microsteps/g12-s01.png');
  await art(page, '/assets/microsteps/g11-s01.png', 'ready', 11);
  await page.locator('[data-step="12"]').click();
  await art(page, '/assets/device-steps/iphone-03.png');
  await page.locator('#daily-device').selectOption('');
  await art(page, '/assets/microsteps/g12-s01.png');
  assert.equal(await page.locator('#daily-guide').isVisible(), false);
  assert.equal(await section.locator('.goal-art-frame').getAttribute('aria-describedby'), null);
  await selectChoice(page, CHOICES[6]);
  await art(page, '/assets/device-steps/iphone-03.png');
  await page.locator('#daily-device').evaluate((select) => select.add(new Option('Unknown device', 'unknown')));
  await page.locator('#daily-device').selectOption('unknown');
  await art(page, '/assets/microsteps/g12-s01.png');
  assert.equal(await page.locator('#daily-guide').isVisible(), false);
  await selectChoice(page, CHOICES[4]);
  await page.locator('#daily-method').evaluate((select) => select.add(new Option('Unknown method', 'unknown')));
  await page.locator('#daily-method').selectOption('unknown');
  await art(page, '/assets/microsteps/g12-s01.png');
  assert.equal(await page.locator('#daily-guide').isVisible(), false);
  await page.locator('#daily-method').selectOption('usb');
  await art(page, '/assets/device-steps/android-usb-01.png');
});

test('a failed image uses the stage fallback, recovers on the next hint, and ignores stale handlers', {timeout: 30000}, async (t) => {
  const {page, failed} = await fixture(t);
  failed.add('/assets/device-steps/windows-01.png');
  await selectChoice(page, CHOICES[0]);
  const image = await art(page, '/assets/steps/06-daily.png', 'fallback');
  assert.ok((await image.getAttribute('alt')).includes('Windows: Подготовьте Tor Browser'));
  assert.equal(await page.locator('#view-scene').isDisabled(), false);
  await page.locator('#view-scene').click();
  assert.equal(await page.locator('#guide-shot-viewer-image').getAttribute('src'), '/assets/steps/06-daily.png');
  await page.locator('#guide-shot-viewer-close').click();
  await page.locator('#daily-guide-next').click();
  await art(page, '/assets/device-steps/windows-02.png');
  await image.evaluate((element) => {
    window.previousArtLoad = element.onload;
    window.previousArtError = element.onerror;
  });
  await page.locator('#daily-guide-next').click();
  await art(page, '/assets/device-steps/windows-03.png');
  await image.evaluate(() => { window.previousArtError(); window.previousArtLoad(); });
  await art(page, '/assets/device-steps/windows-03.png');
  // The enlargement whitelist must reject a query even when the PNG itself loads.
  await image.evaluate((element) => { element.src = '/assets/device-steps/windows-03.png?other=1'; });
  await page.waitForFunction(() => document.querySelector('[data-page="12"] [data-goal-image]').complete);
  await page.locator('#view-scene').click();
  assert.equal(await page.locator('#guide-shot-viewer').evaluate((dialog) => dialog.open), false);
});

test('mobile reduced-motion hint navigation returns the illustration to the visible step start', {timeout: 30000}, async (t) => {
  const {page} = await fixture(t, {width: 390, height: 844});
  await selectChoice(page, CHOICES[4]);
  for (let index = 0; index < 8; index++) {
    if (index) await page.locator('#daily-guide-next').click();
    await art(page, `/assets/device-steps/android-usb-0${index + 1}.png`);
    const geometry = await page.locator('[data-page="12"]').evaluate((section) => ({
      focused: document.activeElement === section.querySelector('.goal-art-frame'),
      top: section.getBoundingClientRect().top,
      inset: document.querySelector('.sidebar').getBoundingClientRect().height + 12,
      overflow: document.documentElement.scrollWidth - innerWidth,
      reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches
    }));
    assert.equal(geometry.focused, true);
    assert.ok(Math.abs(geometry.top - geometry.inset) <= 1, JSON.stringify(geometry));
    assert.ok(geometry.overflow <= 1, JSON.stringify(geometry));
    assert.equal(geometry.reducedMotion, true);
  }
});
