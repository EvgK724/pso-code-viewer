import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile, access} from 'node:fs/promises';
import {linkForToken, tokenFromInput} from '../docs/crypto.mjs';
import {cardLinkFor, cardFromInput, compactLinkContents} from '../docs/sharing.mjs';

const token = 'PSO1.recipient.sender.cipher.signature';
const origin = 'https://viewer.example';

test('encrypted links retain root or GitHub project path, including index.html entry', () => {
  for (const path of ['/', '/pso-code-viewer/']) {
    const base = origin + path;
    assert.equal(linkForToken(token, base), base + '#pso=' + token);
    assert.equal(linkForToken(token, base + 'index.html'), base + '#pso=' + token);
    assert.equal(tokenFromInput(base + '#pso=' + token, base), token);
    assert.equal(tokenFromInput(base + 'index.html#pso=' + token, base), token);
    const url = new URL(linkForToken(token, base));
    assert.equal(url.search, '');
    assert.equal(url.hash, '#pso=' + token);
  }
});

test('an app accepts only links for its own origin and app path', () => {
  const base = origin + '/pso-code-viewer/';
  for (const invalid of [
    origin + '/#pso=' + token,
    origin + '/another-app/#pso=' + token,
    origin + '/pso-code-viewer/extra/#pso=' + token,
    'https://other.example/pso-code-viewer/#pso=' + token,
    base + '?data=anything#pso=' + token,
    'https://user:password@viewer.example/pso-code-viewer/#pso=' + token,
    base + '#unrelated=' + token
  ]) assert.throws(() => tokenFromInput(invalid, base), /данному просмотрщику/);
});

test('public-card links preserve complete cards and support existing raw cards and both hosting paths', () => {
  const card = 'PSO-CARD1.eyJ2IjoxLCJuIjoiRG9jdG9yIn0';
  for (const path of ['/', '/pso-code-viewer/']) {
    const base = origin + path;
    const url = cardLinkFor(card, base);
    assert.equal(url, base + '#card=' + card);
    assert.equal(cardLinkFor(card, base + 'index.html'), url);
    assert.equal(cardFromInput(card, base), card, 'Raw cards remain supported');
    assert.equal(cardFromInput(url, base), card);
    assert.equal(cardFromInput(base + 'index.html#card=' + card, base), card);
    assert.equal(new URL(url).search, '', 'Card material must remain in the URL fragment');
  }
});

test('public-card URL parser rejects foreign destinations, query payloads, credentials and wrong routes', () => {
  const base = origin + '/pso-code-viewer/';
  const card = 'PSO-CARD1.eyJ2IjoxLCJuIjoiRG9jdG9yIn0';
  for (const invalid of [
    origin + '/#card=' + card,
    origin + '/another-app/#card=' + card,
    'https://other.example/pso-code-viewer/#card=' + card,
    base + '?tracking=anything#card=' + card,
    'https://user:password@viewer.example/pso-code-viewer/#card=' + card,
    base + '#pso=' + card,
    base + '#card=%',
    base + '#card=' + 'x'.repeat(6000)
  ]) assert.throws(() => cardFromInput(invalid, base), 'Untrusted or malformed card URL must be rejected');
});

test('compact clipboard payload preserves the entire target and escapes labels without HTML injection', () => {
  const base = origin + '/pso-code-viewer/';
  const url = linkForToken(token, base);
  const content = compactLinkContents(url, 'Открыть запись', base);
  assert.equal(content.plain, url);
  assert.ok(content.html.includes('href="' + url + '"'));
  assert.equal(content.html.replace(/<[^>]*>/g, ''), 'Открыть запись');
  const maliciousLabel = '<img src=x onerror=alert(1)> & "Доктор"';
  const escaped = compactLinkContents(url, maliciousLabel, base);
  assert.ok(!escaped.html.includes('<img'));
  assert.ok(escaped.html.includes('&lt;img'));
  assert.ok(escaped.html.includes('&amp;'));
  assert.equal(escaped.plain, url);
  for (const invalid of [
    'javascript:alert(1)',
    'https://other.example/pso-code-viewer/#pso=' + token,
    origin + '/another-app/#pso=' + token,
    base + '?data=anything#pso=' + token
  ]) assert.throws(() => compactLinkContents(invalid, 'Открыть', base));
});

test('PWA entry, scope and icon resources resolve inside both deployment locations', async () => {
  const manifest = JSON.parse(await readFile(new URL('../docs/manifest.webmanifest', import.meta.url), 'utf8'));
  for (const path of ['/', '/pso-code-viewer/']) {
    const manifestURL = origin + path + 'manifest.webmanifest';
    for (const key of ['id', 'start_url', 'scope']) {
      assert.equal(new URL(manifest[key], manifestURL).href, origin + path);
    }
    for (const icon of manifest.icons) {
      assert.equal(new URL(icon.src, manifestURL).pathname, path + icon.src);
      await access(new URL('../docs/' + icon.src, import.meta.url));
    }
  }
  const html = await readFile(new URL('../docs/index.html', import.meta.url), 'utf8');
  for (const match of html.matchAll(/<link\b[^>]*href="([^"]+)"/g)) {
    assert.ok(!match[1].startsWith('/'), 'All document resources must stay under the app directory');
    await access(new URL('../docs/' + match[1], import.meta.url));
  }
});

test('service worker serves its own offline shell and leaves sibling app requests/caches alone', async () => {
  const source = await readFile(new URL('../docs/sw.js', import.meta.url), 'utf8');
  for (const path of ['/', '/pso-code-viewer/']) {
    const handlers = new Map(), deleted = [], installed = [];
    const prefix = 'pso-viewer-' + encodeURIComponent(path) + '-shell-';
    const current = prefix + 'github-v4-open-feedback';
    const unrelated = 'pso-viewer-%2Fanother-app%2F-shell-github-v1';
    const cached = {status:200, body:'offline-shell'};
    const cache = {
      async addAll(files) { installed.push(...files); },
      async match() { return cached; }
    };
    vm.runInNewContext(source, {
      URL,
      self:{location:new URL(origin + path + 'sw.js'), addEventListener(name, fn) { handlers.set(name, fn); }},
      caches:{
        async open(name) { assert.equal(name, current); return cache; },
        async keys() { return [current, prefix + 'old', unrelated]; },
        async delete(name) { deleted.push(name); }
      },
      fetch() { throw new Error('Offline shell must not make a network request'); }
    });
    let installation;
    handlers.get('install')({waitUntil(promise) { installation = promise; }});
    await installation;
    assert.ok(installed.includes('./') && installed.includes('./index.html'));
    assert.ok(installed.includes('./sharing.mjs'), 'Compact-sharing logic must be available offline');
    assert.ok(installed.every(file => new URL(file, origin + path + 'sw.js').pathname.startsWith(path)));
    let activation;
    handlers.get('activate')({waitUntil(promise) { activation = promise; }});
    await activation;
    assert.deepEqual(deleted, [prefix + 'old']);

    let response;
    handlers.get('fetch')({request:{method:'GET', url:origin + path}, respondWith(promise) { response = promise; }});
    assert.equal(await response, cached);
    for (const url of [origin + '/another-app/', origin + path + '?data=anything', 'https://other.example' + path]) {
      handlers.get('fetch')({request:{method:'GET', url}, respondWith() { assert.fail('Unrelated requests must not be intercepted'); }});
    }
  }
});
