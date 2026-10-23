// UI event integration only. The DOM and storage adapter are intentionally fake;
// RSA/ECDSA operations use the production crypto modules and Node WebCrypto.
// This does not test IndexedDB, Safari, Home Screen storage or the system clipboard.
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
import {webcrypto} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import * as cryptography from '../docs/crypto.mjs';
import * as exchange from '../docs/exchange.mjs';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const html = await readFile(new URL('../docs/index.html', import.meta.url), 'utf8');
const appSource = await readFile(new URL('../docs/app.mjs', import.meta.url), 'utf8');
const origin = 'https://viewer.example';
const appPath = '/pso-code-viewer/';

class Element {
  constructor(tag, attrs = '') {
    this.tag = tag;
    this.children = [];
    this.listeners = new Map();
    this.attributes = new Map();
    this.classList = {toggle() {}};
    this.value = '';
    this.textContent = '';
    this.checked = /\bchecked\b/.test(attrs);
    this.disabled = /\bdisabled\b/.test(attrs);
    this.hidden = /\bhidden\b/.test(attrs);
  }
  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(listener); this.listeners.set(type, listeners);
  }
  async fire(type) {
    for (const listener of this.listeners.get(type) || []) {
      await listener({preventDefault() {}, target:this});
    }
  }
  setAttribute(name, value) { this.attributes.set(name, value); }
  append(...nodes) {
    this.children.push(...nodes);
    if (this.tag === 'select' && this.children.length === nodes.length) this.value = this.children[0]?.value || '';
  }
  replaceChildren(...nodes) {
    this.children = [];
    if (this.tag === 'select') this.value = '';
    this.append(...nodes);
  }
  get options() { return this.children.filter(node => node.tag === 'option'); }
  querySelectorAll(tag) {
    return this.children.flatMap(child => [...(child.tag === tag ? [child] : []), ...child.querySelectorAll(tag)]);
  }
  scrollIntoView() {}
  focus() {}
  select() {}
}

async function waitUntil(condition, description) {
  const stop = performance.now() + 4000;
  while (!condition()) {
    if (performance.now() > stop) throw new Error('Timed out: ' + description);
    await new Promise(resolve => setTimeout(resolve, 5));
  }
}

async function persistentDevice() {
  return {device:await cryptography.makeDevice(), contacts:new Map(), name:''};
}

async function harness(persistent, initialHash = '') {
  const elements = new Map();
  for (const match of html.matchAll(/<([a-z][a-z0-9-]*)\b([^>]*)>/gi)) {
    const id = match[2].match(/\bid="([^"]+)"/);
    if (id) elements.set(id[1], new Element(match[1].toLowerCase(), match[2]));
  }
  const el = id => {
    const found = elements.get(id);
    assert.ok(found, 'App referenced an existing HTML id: ' + id);
    return found;
  };
  el('expiry').value = '1440';
  const docListeners = new Map(), globalListeners = new Map(), intervals = new Map();
  let nextTimer = 1, clipboard = '', clock = 0;
  const document = {
    hidden:false,
    getElementById:el,
    createElement:tag => new Element(tag),
    addEventListener(type, fn) { docListeners.set(type, fn); }
  };
  const location = {origin, pathname:appPath, hash:initialHash};
  const storage = {
    async readDevice() { return persistent.device; },
    async loadContacts() {
      const contacts = [];
      for (const entry of persistent.contacts.values()) {
        const parsed = await exchange.importPublicCard(entry.card);
        assert.equal(parsed.id, entry.id);
        contacts.push({...parsed, verified:entry.verified});
      }
      return contacts;
    },
    async saveContact(contact) {
      assert.equal(contact.verified, true, 'Only explicitly verified cards may be saved');
      persistent.contacts.set(contact.id, {id:contact.id, card:contact.card, verified:true});
    },
    async deleteContact(id) { persistent.contacts.delete(id); },
    async getMyName() { return persistent.name; },
    async setMyName(name) { persistent.name = name; }
  };
  const context = vm.createContext({
    document, location,
    history:{replaceState() { location.hash = ''; }},
    navigator:{clipboard:{async writeText(value) { clipboard = value; }}},
    crypto:webcrypto, URL, console,
    performance:{now:() => clock},
    setInterval(fn) { const id = nextTimer++; intervals.set(id, fn); return id; },
    clearInterval(id) { intervals.delete(id); },
    addEventListener(type, fn) { globalListeners.set(type, fn); }
  });
  const exportsFor = {'./crypto.mjs':cryptography, './exchange.mjs':exchange, './storage.mjs':storage};
  const module = new vm.SourceTextModule(appSource, {context, identifier:origin + appPath + 'app.mjs', initializeImportMeta(meta) { meta.url = origin + appPath + 'app.mjs'; }});
  await module.link(specifier => {
    const entries = exportsFor[specifier];
    assert.ok(entries, 'Known app import: ' + specifier);
    return new vm.SyntheticModule(Object.keys(entries), function () {
      for (const [name, value] of Object.entries(entries)) this.setExport(name, value);
    }, {context, identifier:specifier});
  });
  await module.evaluate();
  await waitUntil(() => el('status').textContent !== 'Подготовка…' && el('status').textContent !== '', 'initialization');
  assert.match(el('status').textContent, /готов/, el('notice').textContent);
  await waitUntil(() => !el('open').disabled, 'ready controls');
  return {
    el, persistent, location,
    clipboard:() => clipboard,
    async event(id, type = 'click') { await el(id).fire(type); },
    async idle() { await waitUntil(() => !el('open').disabled, 'async operation completion'); },
    async hide() { document.hidden = true; await docListeners.get('visibilitychange')(); },
    async show() { document.hidden = false; await docListeners.get('visibilitychange')(); },
    async pagehide() { await globalListeners.get('pagehide')(); },
    advance(milliseconds) { clock += milliseconds; for (const fn of [...intervals.values()]) fn(); }
  };
}

async function exportCard(app, name) {
  app.el('my-name').value = name;
  await app.event('export-card'); await app.idle();
  assert.equal(app.el('my-card-box').hidden, false);
  assert.match(app.el('my-card').value, /^PSO-CARD1\./);
  await app.event('copy-card');
  assert.equal(app.clipboard(), app.el('my-card').value);
  return app.el('my-card').value;
}

async function addCard(app, card) {
  app.el('contact-input').value = card;
  await app.event('contact-input', 'input');
  await app.event('contact-form', 'submit'); await app.idle();
  assert.equal(app.el('contact-confirm').hidden, false, app.el('notice').textContent);
  assert.equal(app.el('save-contact').disabled, true);
  const before = app.persistent.contacts.size;
  // Even a direct event call cannot bypass the explicit fingerprint checkbox.
  await app.event('save-contact');
  assert.equal(app.persistent.contacts.size, before);
  app.el('confirm-fingerprint').checked = true;
  await app.event('confirm-fingerprint', 'change');
  assert.equal(app.el('save-contact').disabled, false);
  await app.event('save-contact'); await app.idle();
  assert.equal(app.persistent.contacts.size, before + 1);
  assert.equal(app.el('contact-confirm').hidden, true);
  assert.equal(app.el('contact-input').value, '');
}

test('two-device UI flow: reciprocal verified cards, compose/copy/open, visibility clearing and reload', async () => {
  const storeA = await persistentDevice(), storeB = await persistentDevice();
  const a = await harness(storeA), b = await harness(storeB);
  const acard = await exportCard(a, 'Доктор А'), bcard = await exportCard(b, 'Доктор Б');
  await addCard(a, bcard); await addCard(b, acard);
  const bid = (await exchange.importPublicCard(bcard)).id;

  await a.event('show-write');
  assert.equal(a.el('write-panel').hidden, false);
  assert.equal(a.el('read-panel').hidden, true);
  a.el('recipient').value = bid;
  await a.event('recipient', 'change');
  a.el('compose-surname').value = 'Петрова';
  a.el('compose-orit').checked = true;
  await a.event('compose-form', 'submit'); await a.idle();
  assert.equal(a.el('compose-output').hidden, false, a.el('notice').textContent);
  assert.equal(a.el('compose-surname').value, '');
  assert.match(a.el('output-recipient').textContent, /Доктор Б/);
  const link = a.el('output-link').value;
  assert.ok(link.startsWith(origin + appPath + '#pso=PSO1.'));
  assert.ok(!link.includes('Петрова'));
  await a.event('copy-composed');
  assert.equal(a.clipboard(), link);

  b.el('token').value = link;
  await b.event('open-form', 'submit'); await b.idle();
  assert.equal(b.el('result').hidden, false, b.el('notice').textContent);
  assert.equal(b.el('surname').textContent, 'Петрова');
  assert.equal(b.el('department').textContent, 'ОРИТ');
  assert.match(b.el('case-code').textContent, /Доктор А/);
  assert.equal(b.el('token').value, '');
  b.el('compose-surname').value = 'Иванов';
  await b.hide();
  assert.equal(b.el('result').hidden, true);
  assert.equal(b.el('surname').textContent, '');
  assert.equal(b.el('department').textContent, '');
  assert.equal(b.el('compose-surname').value, '');

  // Fresh app instance, same fake durable keys and saved public cards.
  const bReloaded = await harness(storeB, new URL(link).hash);
  await bReloaded.idle();
  assert.equal(bReloaded.location.hash, '');
  assert.equal(bReloaded.el('surname').textContent, 'Петрова');
  assert.equal(bReloaded.el('my-name').value, 'Доктор Б');
  bReloaded.advance(30001);
  assert.equal(bReloaded.el('result').hidden, true);
  assert.equal(bReloaded.el('surname').textContent, '');
});

test('incoming link from unknown sender remains hidden until the sender card is verified', async () => {
  const sender = await persistentDevice(), recipient = await persistentDevice();
  const app = await harness(recipient);
  const recipientCard = {...await exchange.importPublicCard(await exchange.exportPublicCard(recipient.device, 'Получатель')), verified:true};
  const token = await exchange.sealSurname(sender.device, recipientCard, 'Иванов');
  app.el('token').value = origin + appPath + '#pso=' + token;
  await app.event('open-form', 'submit'); await app.idle();
  assert.equal(app.el('result').hidden, true);
  assert.equal(app.el('surname').textContent, '');
  assert.match(app.el('notice').textContent, /Отправитель не подтверждён/);

  await addCard(app, await exchange.exportPublicCard(sender.device, 'Отправитель'));
  await app.event('open-form', 'submit'); await app.idle();
  assert.equal(app.el('surname').textContent, 'Иванов');
  await app.pagehide();
  assert.equal(app.el('result').hidden, true);
  assert.equal(app.el('surname').textContent, '');
});
