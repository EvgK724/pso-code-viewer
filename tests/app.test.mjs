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
import * as sharing from '../docs/sharing.mjs';
import * as shortlinks from '../docs/shortlinks.mjs';
import * as push from '../docs/push.mjs';
import {createShortlinkHandler} from '../server/shortlink-handler.mjs';

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
    this.scrollCalls = [];
    this.focusCalls = [];
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
  removeAttribute(name) { this.attributes.delete(name); }
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
  scrollIntoView(options) { this.scrollCalls.push(options); }
  focus(options) { this.focusCalls.push(options); }
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

async function harness(persistent, initialHash = '', {
  richClipboard = false, rejectRich = false, rejectText = false,
  readText = '', rejectRead = false, deferRead = false, standalone = false, legacyStandalone = false, initialHidden = false,
  nativeCopy = undefined, shortlinkEndpoint = '', shortlinkFetch = undefined,
  pushEndpoint = '', pushFetch = undefined, notificationPermission = 'default', pushSubscription = null, permissionResult = 'granted', rejectSubscribe = false, rejectUnsubscribe = false
} = {}) {
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
  el('message-caption').value = 'patient';
  const docListeners = new Map(), globalListeners = new Map(), intervals = new Map();
  let nextTimer = 1, clipboard = '', clock = 0, richItems = [], richAttempts = 0, plainAttempts = 0;
  let readAttempts = 0, nextReadText = readText, nativeAttempts = 0, nativePayload = null;
  const selectedRanges = [];
  const selection = {
    get rangeCount() { return selectedRanges.length; },
    getRangeAt(index) { return selectedRanges[index]; },
    removeAllRanges() { selectedRanges.length = 0; },
    addRange(range) { selectedRanges.push(range); }
  };
  const pendingReads = [];
  let permissionCalls=0,subscribeCalls=0,unsubscribeCalls=0,currentSubscription=pushSubscription;
  const subscription = {toJSON(){return {endpoint:'https://web.push.apple.com/test-device',keys:{p256dh:'test-key',auth:'test-auth'}};},async unsubscribe(){unsubscribeCalls++;if(rejectUnsubscribe)throw new Error('unsubscribe failed');currentSubscription=null;return true;}};
  const registration = {pushManager:{async getSubscription(){return currentSubscription;},async subscribe(options){subscribeCalls++;assert.equal(options.userVisibleOnly,true);assert.equal(options.applicationServerKey.length,65);if(rejectSubscribe)throw new Error('Subscribe failed');currentSubscription=subscription;return subscription;}}};
  if(pushSubscription===true)currentSubscription=subscription;
  const notification = {permission:notificationPermission,requestPermission(){permissionCalls++;notification.permission=permissionResult;return Promise.resolve(permissionResult);}};

  const document = {
    hidden:initialHidden,
    getElementById:el,
    createElement:tag => new Element(tag),
    addEventListener(type, fn) { docListeners.set(type, fn); }
  };
  if (nativeCopy !== undefined) {
    document.createRange = () => ({selectNode(node) { this.node = node; }});
    document.execCommand = command => {
      nativeAttempts++;
      assert.equal(command, 'copy');
      if (nativeCopy === 'throw') throw new Error('Native copy unavailable');
      if (!nativeCopy) return false;
      const anchor = selectedRanges[0]?.node;
      assert.ok(anchor, 'Native copy selects the actual rendered anchor');
      nativePayload = {url:anchor.href, label:anchor.textContent};
      clipboard = anchor.textContent;
      return true;
    };
  }
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
  class FakeClipboardItem {
    constructor(contents) { this.contents = contents; this.types = Object.keys(contents); }
    async getType(type) {
      assert.ok(this.types.includes(type), 'Requested clipboard type exists');
      return await this.contents[type];
    }
  }
  const clipboardAPI = {
    readText() {
      readAttempts++;
      if (rejectRead) return Promise.reject(new Error('Clipboard read permission denied'));
      if (deferRead) return new Promise((resolve, reject) => pendingReads.push({resolve, reject}));
      return Promise.resolve(nextReadText);
    },
    async writeText(value) {
      plainAttempts++;
      if (rejectText) throw new Error('Plain clipboard permission denied');
      clipboard = value;
    }
  };
  if (richClipboard) clipboardAPI.write = async items => {
    richAttempts++;
    if (rejectRich) throw new Error('Rich clipboard permission denied');
    richItems = items;
    clipboard = await (await items[0].getType('text/plain')).text();
  };
  const context = vm.createContext({
    document, location, getSelection:() => selection,
    history:{replaceState() { location.hash = ''; }},
    navigator:{clipboard:clipboardAPI, standalone:legacyStandalone,...(pushEndpoint?{serviceWorker:{register:async()=>registration,ready:Promise.resolve(registration)}}:{})},
    ...(pushEndpoint?{Notification:notification,PushManager:class {}}:{}),
    matchMedia(query) { return {matches:query === '(display-mode: standalone)' && standalone}; },
    crypto:webcrypto, URL, console, Blob,
    ClipboardItem:richClipboard ? FakeClipboardItem : undefined,
    performance:{now:() => clock},
    setInterval(fn) { const id = nextTimer++; intervals.set(id, fn); return id; },
    clearInterval(id) { intervals.delete(id); },
    addEventListener(type, fn) { globalListeners.set(type, fn); }
  });
  // Exercise the actual client and HTTP handler while replacing only transport.
  class InjectedShortLinkClient extends shortlinks.ShortLinkClient {
    constructor(endpoint) { super(endpoint, {fetch:shortlinkFetch}); }
  }
  class InjectedPushClient extends push.PushClient { constructor(endpoint){super(endpoint,{fetch:pushFetch});} }
  const exportsFor = {
    './crypto.mjs':cryptography, './exchange.mjs':exchange, './storage.mjs':storage, './sharing.mjs':sharing,
    './shortlinks.mjs':{...shortlinks, ShortLinkClient:InjectedShortLinkClient},
    './shortlink-config.mjs':{SHORTLINK_ENDPOINT:shortlinkEndpoint,PUSH_ENDPOINT:pushEndpoint},
    './push.mjs':{...push,PushClient:InjectedPushClient}
  };
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
    richItems:() => richItems,
    clipboardAttempts:() => ({rich:richAttempts, plain:plainAttempts}),
    nativeCopyAttempts:() => nativeAttempts,
    nativePayload:() => nativePayload,
    clipboardReadAttempts:() => readAttempts,
    pushCounts:()=>({permission:permissionCalls,subscribe:subscribeCalls,unsubscribe:unsubscribeCalls}),
    async pushIdle(){await waitUntil(()=>!el('push-enable').disabled || el('push-test').disabled===false || /выключены|запрещены|значок|Не удалось/.test(el('push-status').textContent),'push completion');},
    setReadText(value) { nextReadText = value; },
    resolveClipboardRead(value) {
      const read = pendingReads.shift();
      assert.ok(read, 'A clipboard read is awaiting resolution');
      read.resolve(value);
    },
    async event(id, type = 'click') { await el(id).fire(type); },
    async idle() { await waitUntil(() => !el('open').disabled, 'async operation completion'); },
    async hide() { document.hidden = true; await docListeners.get('visibilitychange')(); },
    async show() { document.hidden = false; await docListeners.get('visibilitychange')(); },
    async pagehide() { await globalListeners.get('pagehide')(); },
    async hashchange(hash) { location.hash = hash; await globalListeners.get('hashchange')(); },
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
  assert.ok(app.el('notice').scrollCalls.length > 0, 'Unknown-sender error must be brought into view');
  assert.ok(app.el('notice').focusCalls.length > 0, 'Unknown-sender error must receive accessible focus');

  await addCard(app, await exchange.exportPublicCard(sender.device, 'Отправитель'));
  await app.event('open-form', 'submit'); await app.idle();
  assert.equal(app.el('surname').textContent, 'Иванов');
  await app.pagehide();
  assert.equal(app.el('result').hidden, true);
  assert.equal(app.el('surname').textContent, '');
});

async function composeForSelf(app, surname = 'Петрова') {
  await app.event('show-write');
  app.el('recipient').value = (await exchange.deviceIdentity(app.persistent.device)).id;
  await app.event('recipient', 'change');
  app.el('compose-surname').value = surname;
  await app.event('compose-form', 'submit'); await app.idle();
  assert.equal(app.el('compose-output').hidden, false, app.el('notice').textContent);
  const link = app.el('output-link').value;
  assert.ok(link.startsWith(origin + appPath + '#pso=PSO1.'));
  return link;
}

async function assertCompactPayload(app, expectedURL) {
  const items = app.richItems();
  assert.equal(items.length, 1);
  const item = items[0];
  assert.deepEqual([...item.types].sort(), ['text/html', 'text/plain']);
  const rich = await (await item.getType('text/html')).text();
  const plain = await (await item.getType('text/plain')).text();
  assert.equal(plain, expectedURL, 'Plain paste must preserve the complete actionable URL');
  assert.ok(rich.includes('href="' + expectedURL + '"'), 'Compact text must retain the complete target');
  const visible = rich.replace(/<[^>]*>/g, '').trim();
  assert.ok(visible.length > 0 && visible.length < 100, 'The visible label is compact');
  assert.ok(!visible.includes('PSO1.') && !visible.includes('PSO-CARD1.'), 'Full payload is hidden in the link target');
  for (const representation of [rich, plain]) {
    assert.ok(!representation.includes('Петрова'), 'Clipboard must not contain the plaintext patient surname');
  }
}

test('compact copy supplies labeled HTML and the complete plain URL, retaining old copy and encryption', async () => {
  const app = await harness(await persistentDevice(), '', {richClipboard:true});
  const card = await exportCard(app, 'Доктор А');
  const cardURL = app.el('my-card-link').value;
  assert.equal(sharing.cardFromInput(cardURL, origin + appPath), card);
  assert.equal(app.el('my-card-preview').href, cardURL);
  await app.event('copy-card-compact');
  await assertCompactPayload(app, cardURL);
  assert.equal(app.el('my-card').value, card, 'Sharing must not replace the original compatible card');
  await app.event('copy-card');
  assert.equal(app.clipboard(), card, 'Legacy raw-card copy remains available');

  const messageURL = await composeForSelf(app);
  assert.equal(app.el('output-preview').href, messageURL);
  await app.event('copy-composed-compact');
  await assertCompactPayload(app, messageURL);
  await app.event('copy-composed-address');
  assert.equal(app.clipboard(), messageURL, 'Explicit full-link copy remains available');
  app.el('token').value = messageURL;
  await app.event('open-form', 'submit'); await app.idle();
  assert.equal(app.el('surname').textContent, 'Петрова', 'Presentation changes must preserve decryption');
});

test('unsupported or rejected rich clipboard falls back to full URLs for cards and encrypted records', async t => {
  for (const options of [{richClipboard:false}, {richClipboard:true, rejectRich:true}]) {
    await t.test(options.richClipboard ? 'rich clipboard rejects' : 'rich clipboard unavailable', async () => {
      const app = await harness(await persistentDevice(), '', options);
      const card = await exportCard(app, 'Доктор А');
      const cardURL = app.el('my-card-link').value;
      let before = app.clipboardAttempts();
      await app.event('copy-card-compact');
      assert.equal(app.clipboard(), cardURL);
      assert.equal(app.clipboardAttempts().plain, before.plain + 1);
      assert.equal(app.el('my-card').value, card);

      const messageURL = await composeForSelf(app);
      before = app.clipboardAttempts();
      await app.event('copy-composed-compact');
      assert.equal(app.clipboard(), messageURL);
      assert.equal(app.clipboardAttempts().plain, before.plain + 1);
      if (options.richClipboard) assert.equal(app.clipboardAttempts().rich, 2);
    });
  }
});

test('when both clipboard methods reject, manual-copy details expose the complete card and message URLs', async () => {
  const app = await harness(await persistentDevice(), '', {richClipboard:true, rejectRich:true, rejectText:true});
  app.el('my-name').value = 'Доктор А';
  await app.event('export-card'); await app.idle();
  const card = app.el('my-card').value, cardURL = app.el('my-card-link').value;
  await app.event('copy-card-compact');
  assert.equal(app.el('my-card-full').open, true);
  assert.equal(app.el('my-card-link').value, cardURL);
  assert.equal(app.el('my-card').value, card);
  assert.match(app.el('notice').textContent, /Скопировать/);
  const messageURL = await composeForSelf(app);
  await app.event('copy-composed-compact');
  assert.equal(app.el('compose-full-link').open, true);
  assert.equal(app.el('output-link').value, messageURL);
  assert.match(app.el('notice').textContent, /Скопировать/);
});

test('compact demo copy preserves a complete legacy demo link that opens on the same device', async () => {
  const app = await harness(await persistentDevice(), '', {richClipboard:true});
  await app.event('demo'); await app.idle();
  const link = app.el('open-link').href;
  assert.ok(link.startsWith(origin + appPath + '#pso=PSO-DEMO1.'));
  await app.event('copy-demo-compact');
  await assertCompactPayload(app, link);
  app.el('token').value = link;
  await app.event('open-form', 'submit'); await app.idle();
  assert.equal(app.el('surname').textContent, 'Иванов');
});

async function assertUnverifiedPreview(app, expectedName, expectedFingerprint) {
  await waitUntil(() => !app.el('contact-confirm').hidden, 'incoming card preview');
  await app.idle();
  assert.equal(app.el('candidate-name').textContent, expectedName);
  assert.equal(app.el('candidate-fingerprint').textContent, expectedFingerprint);
  assert.equal(app.el('confirm-fingerprint').checked, false);
  assert.equal(app.el('save-contact').disabled, true);
  assert.equal(app.persistent.contacts.size, 0, 'Opening a link never trusts or saves its public keys');
  await app.event('save-contact');
  assert.equal(app.persistent.contacts.size, 0, 'A direct event cannot bypass fingerprint confirmation');
}

test('card links on startup and hashchange only preview the contact and require explicit verification', async () => {
  const sender = await persistentDevice(), recipient = await persistentDevice();
  const card = await exchange.exportPublicCard(sender.device, 'Доктор А');
  const imported = await exchange.importPublicCard(card);
  const cardURL = sharing.cardLinkFor(card, origin + appPath);
  const app = await harness(recipient, new URL(cardURL).hash);
  await assertUnverifiedPreview(app, 'Доктор А', imported.fingerprint);
  assert.equal(app.location.hash, '');

  // A later incoming card must reset a checkbox left checked for an earlier candidate.
  app.el('confirm-fingerprint').checked = true;
  await app.event('confirm-fingerprint', 'change');
  await app.hashchange(new URL(cardURL).hash);
  await assertUnverifiedPreview(app, 'Доктор А', imported.fingerprint);
  assert.equal(app.location.hash, '');

  app.el('confirm-fingerprint').checked = true;
  await app.event('confirm-fingerprint', 'change');
  await app.event('save-contact'); await app.idle();
  assert.equal(recipient.contacts.size, 1);
  assert.equal(recipient.contacts.get(imported.id).card, card, 'Persist the unchanged canonical card');
});

test('pasted card URL uses the same verification flow and stores an old-format compatible card', async () => {
  const sender = await persistentDevice(), recipient = await persistentDevice();
  const card = await exchange.exportPublicCard(sender.device, 'Доктор А');
  const app = await harness(recipient);
  await addCard(app, sharing.cardLinkFor(card, origin + appPath));
  const imported = await exchange.importPublicCard(card);
  assert.equal(recipient.contacts.get(imported.id).card, card);
});

async function selfMessageURL(store, surname = 'Петрова') {
  const card = await exchange.exportPublicCard(store.device, 'Этот телефон');
  const recipient = {...await exchange.importPublicCard(card), verified:true};
  return cryptography.linkForToken(await exchange.sealSurname(store.device, recipient, surname), origin + appPath);
}

test('clipboard is read only after the paste button click and a complete message then decrypts', async () => {
  const store = await persistentDevice();
  const link = await selfMessageURL(store);
  const app = await harness(store, '', {readText:link, standalone:true});
  assert.equal(app.clipboardReadAttempts(), 0, 'Initialization must not inspect the clipboard');
  await app.hide(); await app.show();
  assert.equal(app.clipboardReadAttempts(), 0, 'Returning to the app must not inspect the clipboard');
  const paste = app.event('paste-open');
  assert.equal(app.clipboardReadAttempts(), 1, 'Clipboard read starts synchronously inside the click gesture');
  await paste; await app.idle();
  assert.equal(app.el('result').hidden, false, app.el('notice').textContent);
  assert.equal(app.el('surname').textContent, 'Петрова');
  assert.equal(app.el('token').value, '');
});

test('paste and ordinary open accept a card without bypassing fingerprint verification', async () => {
  const sender = await persistentDevice(), recipient = await persistentDevice();
  const card = await exchange.exportPublicCard(sender.device, 'Доктор А');
  const identity = await exchange.importPublicCard(card);
  const link = sharing.cardLinkFor(card, origin + appPath);
  const app = await harness(recipient, '', {readText:link, standalone:true});
  await app.event('paste-open'); await app.idle();
  await assertUnverifiedPreview(app, 'Доктор А', identity.fingerprint);

  app.el('confirm-fingerprint').checked = true;
  app.el('token').value = card;
  await app.event('open-form', 'submit'); await app.idle();
  await assertUnverifiedPreview(app, 'Доктор А', identity.fingerprint);
  assert.equal(recipient.contacts.size, 0);
});

test('clipboard denial and unrelated clipboard content preserve the existing manually typed value', async t => {
  for (const options of [
    {rejectRead:true},
    {readText:'https://other.example/pso-code-viewer/#pso=PSO1.a.b.c.d'},
    {readText:origin + appPath + '#pso=<script>'},
    {readText:'Это обычный текст из другого приложения'},
    {readText:''}
  ]) await t.test(options.rejectRead ? 'permission denied' : 'unrecognized clipboard ' + options.readText.slice(0, 25), async () => {
    const app = await harness(await persistentDevice(), '', options);
    const typed = 'Сохранившийся текст ручного ввода';
    app.el('token').value = typed;
    await app.event('paste-open'); await app.idle();
    assert.equal(app.el('token').value, typed);
    assert.equal(app.el('result').hidden, true);
    assert.equal(app.persistent.contacts.size, 0);
    assert.ok(app.el('notice').textContent, 'The failed paste must explain the manual fallback');
  });
});

test('a pending clipboard result cannot reveal a surname after the app was backgrounded', async () => {
  const store = await persistentDevice(), link = await selfMessageURL(store);
  const app = await harness(store, '', {deferRead:true, standalone:true});
  const typed = 'Ранее введённый текст';
  app.el('token').value = typed;
  const paste = app.event('paste-open');
  assert.equal(app.clipboardReadAttempts(), 1);
  await app.hide(); await app.show();
  app.resolveClipboardRead(link);
  await paste; await app.idle();
  assert.equal(app.el('result').hidden, true);
  assert.equal(app.el('surname').textContent, '');
  assert.equal(app.el('token').value, typed);
  assert.equal(app.clipboardReadAttempts(), 1, 'Foregrounding must not initiate another read');
});

test('incoming message handoff retains and copies the full original link despite a different browser key', async () => {
  const installedStore = await persistentDevice(), browserStore = await persistentDevice();
  const link = await selfMessageURL(installedStore);
  const browserKey = browserStore.device.encryption.privateKey;
  const app = await harness(browserStore, new URL(link).hash);
  await app.idle();
  assert.equal(app.location.hash, '');
  assert.equal(app.el('handoff-panel').hidden, false);
  assert.equal(app.el('handoff-link').value, link);
  assert.equal(app.el('result').hidden, true, 'The browser cannot decrypt a link for the installed app');
  assert.equal(app.clipboardReadAttempts(), 0);
  await app.event('copy-handoff');
  assert.equal(app.clipboard(), link);
  assert.ok(!app.clipboard().includes('Петрова'));
  assert.equal(browserStore.device.encryption.privateKey, browserKey, 'Handoff must not replace local keys');
  assert.equal(browserStore.contacts.size, 0);
});

test('card handoff is lossless and never automatically saves its contact', async () => {
  const sender = await persistentDevice(), recipient = await persistentDevice();
  const card = await exchange.exportPublicCard(sender.device, 'Доктор А');
  const link = sharing.cardLinkFor(card, origin + appPath);
  const app = await harness(recipient, new URL(link).hash);
  await app.idle();
  assert.equal(app.el('handoff-panel').hidden, false);
  assert.equal(app.el('handoff-link').value, link);
  await app.event('copy-handoff');
  assert.equal(app.clipboard(), link);
  assert.equal(recipient.contacts.size, 0);
  assert.equal(app.el('confirm-fingerprint').checked, false);
  assert.equal(app.clipboardReadAttempts(), 0);
});

test('handoff instructions stay hidden for installed mode detected by either supported signal', async t => {
  const store = await persistentDevice(), link = await selfMessageURL(store);
  for (const options of [{standalone:true}, {legacyStandalone:true}]) {
    await t.test(options.standalone ? 'display-mode media query' : 'navigator.standalone', async () => {
      const app = await harness(store, new URL(link).hash, options);
      await app.idle();
      assert.equal(app.el('handoff-panel').hidden, true);
      assert.equal(app.el('surname').textContent, 'Петрова');
      assert.equal(app.clipboardReadAttempts(), 0);
    });
  }
});

test('unrecognized or malformed incoming hashes do not offer a handoff link', async () => {
  const store = await persistentDevice();
  for (const hash of ['#unrelated=anything', '#card=%', '#pso=<script>']) {
    const app = await harness(store, hash);
    await app.idle();
    assert.equal(app.el('handoff-panel').hidden, true);
    assert.equal(app.el('handoff-link').value, '');
    assert.equal(app.clipboardReadAttempts(), 0);
  }
});

test('a failed new manual input or unknown incoming link cannot leave the previous surname visible', async () => {
  const store = await persistentDevice(), link = await selfMessageURL(store);
  const app = await harness(store);
  for (const source of ['manual', 'incoming']) {
    app.el('token').value = link;
    await app.event('open-form', 'submit'); await app.idle();
    assert.equal(app.el('surname').textContent, 'Петрова');
    if (source === 'manual') {
      app.el('token').value = 'Неполная ссылка';
      await app.event('open-form', 'submit');
    } else await app.hashchange('#unknown=link');
    await app.idle();
    assert.equal(app.el('result').hidden, true, source + ' must clear the previous result before reporting the error');
    assert.equal(app.el('surname').textContent, '');
  }
});

test('a newer incoming link cancels a pending older clipboard read and preserves the new handoff', async () => {
  const store = await persistentDevice();
  const oldLink = await selfMessageURL(store, 'Петрова'), newLink = await selfMessageURL(store, 'Иванов');
  const app = await harness(store, '', {deferRead:true});
  const paste = app.event('paste-open');
  assert.equal(app.clipboardReadAttempts(), 1);
  await app.hashchange(new URL(newLink).hash);
  app.resolveClipboardRead(oldLink);
  await paste; await app.idle();
  assert.notEqual(app.el('surname').textContent, 'Петрова', 'The obsolete clipboard result must not display');
  assert.equal(app.el('handoff-panel').hidden, false);
  assert.equal(app.el('handoff-link').value, newLink);
  await app.event('copy-handoff');
  assert.equal(app.clipboard(), newLink);
});

test('numeric and fingerprint input produce a visible focused explanation instead of appearing unresponsive', async () => {
  assert.match(html, /<p(?=[^>]*id="notice")(?=[^>]*tabindex="-1")[^>]*>/, 'The notice must be programmatically focusable');
  const app = await harness(await persistentDevice());
  for (const [input, explanation] of [
    ['12345678901234567890', /цифр|контрольн|отпечат/iu],
    [Array(16).fill('A1B2').join(' '), /контрольн|отпечат/iu],
    [Array(16).fill('a1b2').join(' '), /контрольн|отпечат/iu]
  ]) {
    const notice = app.el('notice');
    const oldScrolls = notice.scrollCalls.length, oldFocuses = notice.focusCalls.length;
    app.el('token').value = input;
    await app.event('open-form', 'submit'); await app.idle();
    assert.equal(app.el('token').value, input, 'An invalid input remains available for correction');
    assert.equal(app.el('result').hidden, true);
    assert.equal(app.el('surname').textContent, '');
    assert.match(notice.textContent, explanation, 'Explain why this value cannot identify a patient');
    assert.match(notice.textContent, /ссылк/iu, 'Explain what the user should copy instead');
    assert.equal(notice.scrollCalls.length, oldScrolls + 1, 'The error scrolls into view');
    assert.equal(notice.focusCalls.length, oldFocuses + 1, 'The error receives focus instead of leaving focus in the keyboard input');
    assert.equal(notice.attributes.get('role'), 'alert');
    assert.equal(notice.attributes.get('aria-live'), 'assertive');
    assert.equal(app.el('open').disabled, false, 'The user can correct the input and try again');
  }
});

test('all three captions copy the exact labeled target while retaining decryption and ORIT', async () => {
  const store = await persistentDevice();
  for (const [value, label, department] of [
    ['patient', 'Новый пациент', ''],
    ['orit', 'Новый пациент ОРИТ', 'ОРИТ'],
    ['test', 'Проверочная история', '']
  ]) {
    const app = await harness(store, '', {richClipboard:true});
    app.el('message-caption').value = value;
    await app.event('message-caption', 'change');
    assert.equal(app.el('compose-orit').checked, department === 'ОРИТ');
    const url = await composeForSelf(app);
    assert.equal(app.el('output-preview').textContent, label);
    for (const button of ['copy-composed', 'copy-composed-compact']) {
      await app.event(button);
      await assertCompactPayload(app, url);
      const rich = await (await app.richItems()[0].getType('text/html')).text();
      assert.equal(rich.replace(/<[^>]*>/g, ''), label);
    }
    await app.event('copy-composed-address');
    assert.equal(app.clipboard(), url, 'A complete URL remains available independently of rich paste support');
    app.el('token').value = url;
    await app.event('open-form', 'submit'); await app.idle();
    assert.equal(app.el('surname').textContent, 'Петрова');
    assert.equal(app.el('department').textContent, department);
  }
});

test('caption-only changes reuse the link, but department changes invalidate it and stay coherent', async () => {
  const app = await harness(await persistentDevice());
  const firstURL = await composeForSelf(app);
  app.el('message-caption').value = 'test';
  await app.event('message-caption', 'change');
  assert.equal(app.el('output-link').value, firstURL);
  assert.equal(app.el('output-preview').textContent, 'Проверочная история');
  assert.equal(app.el('compose-output').hidden, false);
  assert.equal(app.el('compose-orit').checked, false);

  app.el('message-caption').value = 'orit';
  await app.event('message-caption', 'change');
  assert.equal(app.el('compose-orit').checked, true);
  assert.equal(app.el('output-link').value, '');
  assert.equal(app.el('compose-output').hidden, true);
  const oritURL = await composeForSelf(app);
  assert.notEqual(oritURL, firstURL);
  assert.equal(app.el('output-preview').textContent, 'Новый пациент ОРИТ');

  app.el('compose-orit').checked = false;
  await app.event('compose-orit', 'input');
  assert.equal(app.el('message-caption').value, 'patient');
  assert.equal(app.el('output-link').value, '');
  app.el('compose-orit').checked = true;
  await app.event('compose-orit', 'input');
  assert.equal(app.el('message-caption').value, 'orit');
  app.el('message-caption').value = 'test';
  await app.event('message-caption', 'change');
  assert.equal(app.el('compose-orit').checked, true, 'Test caption alone must not change encrypted department');
  await composeForSelf(app);
  app.el('compose-orit').checked = false;
  await app.event('compose-orit', 'input');
  assert.equal(app.el('message-caption').value, 'test');
  assert.equal(app.el('output-link').value, '', 'Even test links are invalidated when department changes');
});

test('alternative native copy keeps the selected link without overwriting its platform clipboard formats', async () => {
  const app = await harness(await persistentDevice(), '', {nativeCopy:true, richClipboard:true});
  app.el('message-caption').value = 'test';
  await app.event('message-caption', 'change');
  const url = await composeForSelf(app);
  await app.event('copy-composed');
  assert.equal(app.nativeCopyAttempts(), 0, 'Primary action uses the standard clipboard even when native copy exists');
  await assertCompactPayload(app, url);
  const before = app.clipboardAttempts();
  await app.event('copy-composed-compact');
  assert.equal(app.nativeCopyAttempts(), 1);
  assert.deepEqual(app.nativePayload(), {url, label:'Проверочная история'});
  assert.deepEqual(app.clipboardAttempts(), before, 'Do not overwrite a native copy with async or plain clipboard');
  assert.equal(app.clipboard(), 'Проверочная история', 'Native plain text may be only the label');
  assert.ok(!JSON.stringify(app.nativePayload()).includes('Петрова'));
});

test('native copy rejection falls back to labeled HTML and finally the complete address', async () => {
  const store = await persistentDevice();
  for (const [nativeCopy, richClipboard] of [[false, true], ['throw', false]]) {
    const app = await harness(store, '', {nativeCopy, richClipboard});
    const url = await composeForSelf(app);
    await app.event('copy-composed-compact');
    assert.equal(app.nativeCopyAttempts(), 1);
    assert.equal(app.clipboard(), url);
    if (richClipboard) await assertCompactPayload(app, url);
    else assert.ok(app.clipboardAttempts().plain > 0);
  }
});

// No network or database is mocked above the HTTP boundary: these UI tests use
// real client validation, signed envelopes, broker verification and decryption.
async function shortlinkBroker(writerDevice) {
  const senderID = (await exchange.deviceIdentity(writerDevice)).id;
  const rows = new Map(), requests = [];
  let enabled = true, pendingResolve;
  const store = {
    async getWriter(id) {
      return id === senderID ? {enabled, signingPublicKey:writerDevice.signing.publicKey} : null;
    },
    async put(row) {
      // Atomic within this fake adapter: no await separates the checks and write.
      if (!enabled || row.senderID !== senderID) return 'denied';
      const existing = rows.get(row.idHash);
      if (existing) return existing.requestHash === row.requestHash && existing.senderID === row.senderID ? 'exists' : 'conflict';
      rows.set(row.idHash, row);
      return 'created';
    },
    async resolve(idHash, now) {
      const row = rows.get(idHash);
      return row && row.expires > now ? row : null;
    }
  };
  const handler = createShortlinkHandler({store, allowedOrigin:origin, crypto:webcrypto});
  const endpoint = 'https://relay.example/shortlinks';
  const fetcher = async (url, options) => {
    assert.equal(url, endpoint, 'All broker traffic uses the configured endpoint, without IDs in the URL');
    const body = JSON.parse(options.body);
    requests.push(body);
    if (body.op === 'resolve' && pendingResolve) {
      const gate = pendingResolve; pendingResolve = undefined;
      gate.enter(); await gate.wait;
    }
    return handler(new Request(url, {...options, headers:{...options.headers, Origin:origin}}));
  };
  return {
    rows, requests, options:{shortlinkEndpoint:endpoint, shortlinkFetch:fetcher},
    disableWriter() { enabled = false; },
    deferNextResolve() {
      let enter, release;
      const started = new Promise(resolve => { enter = resolve; });
      const wait = new Promise(resolve => { release = resolve; });
      pendingResolve = {enter, wait};
      return {started, release};
    }
  };
}

async function composeShortMessage(app, recipientID, caption = 'patient') {
  await app.event('show-write');
  app.el('recipient').value = recipientID;
  await app.event('recipient', 'change');
  app.el('message-caption').value = caption;
  await app.event('message-caption', 'change');
  app.el('compose-surname').value = 'Тестов';
  await app.event('compose-surname', 'input');
  await app.event('compose-form', 'submit'); await app.idle();
  assert.equal(app.el('compose-output').hidden, false, app.el('notice').textContent);
  const url = app.el('output-link').value;
  assert.equal(new URL(url).origin, origin);
  assert.equal(new URL(url).pathname, appPath);
  assert.match(new URL(url).hash, /^#r=[A-Za-z0-9_-]{22}$/);
  assert.ok(url.length < 80 && !url.includes('PSO1.') && !url.includes('Тестов'));
  return url;
}

test('short-link UI copies actual caption and short URL as plain text; recipient pastes full message or opens hash for 30 seconds', async () => {
  const sender = await persistentDevice(), recipient = await persistentDevice();
  const broker = await shortlinkBroker(sender.device);
  // Even with both rich and native copy available, the primary action is plain
  // text containing an actionable short URL, never the unlinked caption alone.
  const a = await harness(sender, '', {...broker.options, richClipboard:true, nativeCopy:true});
  const b = await harness(recipient, '', broker.options);
  const senderCard = await exportCard(a, 'Тестовый отправитель');
  const recipientCard = await exportCard(b, 'Тестовый получатель');
  await addCard(a, recipientCard); await addCard(b, senderCard);
  const recipientID = (await exchange.importPublicCard(recipientCard)).id;
  let lastURL;
  for (const [caption, label, department] of [
    ['patient', 'Новый пациент', ''],
    ['orit', 'Новый пациент ОРИТ', 'ОРИТ'],
    ['test', 'Проверочная история', 'ОРИТ']
  ]) {
    lastURL = await composeShortMessage(a, recipientID, caption);
    const before = a.clipboardAttempts();
    await a.event('copy-composed');
    assert.equal(a.clipboard(), label + '\n' + lastURL);
    assert.deepEqual(a.clipboardAttempts(), {rich:before.rich, plain:before.plain+1});
    assert.equal(a.nativeCopyAttempts(), 0);
    assert.equal(a.el('output-message').value, a.clipboard());
    assert.equal(a.el('compose-surname').value, '');
    b.setReadText(a.clipboard());
    await b.event('paste-open'); await b.idle();
    assert.equal(b.el('result').hidden, false, b.el('notice').textContent);
    assert.equal(b.el('surname').textContent, 'Тестов');
    assert.equal(b.el('department').textContent, department);
    assert.match(b.el('case-code').textContent, /Тестовый отправитель/);
    b.advance(30001);
    assert.equal(b.el('result').hidden, true);
    assert.equal(b.el('surname').textContent, '');
  }
  assert.equal(broker.rows.size, 3);
  assert.ok(!JSON.stringify(broker.requests).includes('Тестов'), 'Only ciphertext reaches the broker');
  const reopened = await harness(recipient, new URL(lastURL).hash, {...broker.options, standalone:true});
  await reopened.idle();
  assert.equal(reopened.location.hash, '', 'Incoming capability is removed from the address bar');
  assert.equal(reopened.el('handoff-panel').hidden, true);
  assert.equal(reopened.el('surname').textContent, 'Тестов');
  assert.equal(reopened.el('department').textContent, 'ОРИТ');
  reopened.advance(30001);
  assert.equal(reopened.el('result').hidden, true);
  assert.equal(reopened.el('surname').textContent, '');
});

test('failed broker registration clears prior output and does not expose a fallback long or unregistered short link', async () => {
  const device = await persistentDevice(), broker = await shortlinkBroker(device.device);
  const app = await harness(device, '', broker.options);
  await composeShortMessage(app, (await exchange.deviceIdentity(device.device)).id);
  broker.disableWriter();
  app.el('compose-surname').value = 'Тестов';
  await app.event('compose-surname', 'input');
  await app.event('compose-form', 'submit'); await app.idle();
  assert.match(app.el('notice').textContent, /не подключён/);
  assert.equal(app.el('compose-output').hidden, true);
  assert.equal(app.el('output-link').value, '');
  assert.equal(app.el('output-message').value, '');
  assert.equal(app.el('copy-composed').disabled, true);
  assert.equal(app.el('copy-composed-address').disabled, true);
  assert.equal(app.el('compose-surname').value, '');
  assert.equal(broker.rows.size, 1, 'Failed create does not register a second record');
});

test('a short-link resolve finishing after the app enters background cannot reveal a surname', async () => {
  const sender = await persistentDevice(), recipient = await persistentDevice();
  const broker = await shortlinkBroker(sender.device);
  const a = await harness(sender, '', broker.options), b = await harness(recipient, '', broker.options);
  const senderCard = await exportCard(a, 'Тестовый отправитель');
  const recipientCard = await exportCard(b, 'Тестовый получатель');
  await addCard(a, recipientCard); await addCard(b, senderCard);
  const url = await composeShortMessage(a, (await exchange.importPublicCard(recipientCard)).id);
  const gate = broker.deferNextResolve();
  b.setReadText('Новый пациент\n' + url);
  const opening = b.event('paste-open');
  await gate.started;
  await b.hide();
  gate.release(); await opening; await b.idle();
  assert.equal(b.el('result').hidden, true);
  assert.equal(b.el('surname').textContent, '');
  await b.show();
  assert.equal(b.el('result').hidden, true, 'Returning to the foreground must not reveal automatically');
  await b.event('paste-open'); await b.idle();
  assert.equal(b.el('surname').textContent, 'Тестов', 'An explicit new request can still open the same valid link');
});

test('notification launch queues its incoming link until the installed app becomes visible, without redisplaying it later', async () => {
  const persistent = await persistentDevice(), broker = await shortlinkBroker(persistent.device);
  const creator = await harness(persistent, '', broker.options);
  const url = await composeShortMessage(creator, (await exchange.deviceIdentity(persistent.device)).id);
  const resolveCount = () => broker.requests.filter(request => request.op === 'resolve').length;
  const before = resolveCount();
  const app = await harness(persistent, new URL(url).hash, {...broker.options, standalone:true, initialHidden:true});
  assert.equal(app.location.hash, '', 'Capability is removed from the address bar even while hidden');
  assert.equal(resolveCount(), before, 'Hidden startup does not resolve or decrypt');
  assert.equal(app.el('surname').textContent, '');
  await app.show(); await app.idle();
  assert.equal(app.el('surname').textContent, 'Тестов');
  assert.equal(resolveCount(), before + 1);
  await app.hide(); await app.show(); await app.idle();
  assert.equal(app.el('surname').textContent, '', 'A previously shown surname never reappears on foreground');
  assert.equal(app.el('result').hidden, true);
  assert.equal(resolveCount(), before + 1, 'A completed incoming link is not retried');
});

test('an incoming hash delivered to a hidden app opens only the newest pending link on foreground', async () => {
  const persistent = await persistentDevice(), broker = await shortlinkBroker(persistent.device);
  const creator = await harness(persistent, '', broker.options);
  const identity = await exchange.deviceIdentity(persistent.device);
  const first = await composeShortMessage(creator, identity.id);
  const second = await composeShortMessage(creator, identity.id, 'orit');
  const app = await harness(persistent, '', {...broker.options, standalone:true});
  await app.hide();
  const before = broker.requests.length;
  await app.hashchange(new URL(first).hash);
  await app.hashchange(new URL(second).hash);
  assert.equal(broker.requests.length, before);
  assert.equal(app.el('surname').textContent, '');
  await app.show(); await app.idle();
  assert.equal(app.el('surname').textContent, 'Тестов');
  assert.equal(app.el('department').textContent, 'ОРИТ');
  assert.equal(broker.requests.length, before + 1);
  assert.equal(broker.requests.at(-1).id, new URL(second).hash.slice(3));
});

test('an unprocessed incoming link interrupted by backgrounding is retried once when visible', async () => {
  const persistent = await persistentDevice(), broker = await shortlinkBroker(persistent.device);
  const creator = await harness(persistent, '', broker.options);
  const url = await composeShortMessage(creator, (await exchange.deviceIdentity(persistent.device)).id);
  const app = await harness(persistent, '', {...broker.options, standalone:true});
  const gate = broker.deferNextResolve();
  await app.hashchange(new URL(url).hash);
  await gate.started; await app.hide();
  gate.release(); await app.idle();
  assert.equal(app.el('surname').textContent, '');
  await app.show(); await app.idle();
  assert.equal(app.el('surname').textContent, 'Тестов');
  await app.pagehide(); await app.show(); await app.idle();
  assert.equal(app.el('surname').textContent, '', 'Page lifecycle cannot redisplay a completed name');
});

async function notificationService({enabled=false,notifyStatus='accepted',failNotify=false}={}) {
  const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const publicKey=Buffer.from(await crypto.subtle.exportKey('raw',pair.publicKey)).toString('base64url');
  const requests=[];
  return {requests,fetch:async(url,options)=>{
    const body=JSON.parse(options.body);requests.push(body);
    if(body.op==='config')return new Response(JSON.stringify({v:1,publicKey}),{headers:{'Content-Type':'application/json'}});
    const op=body.envelope.op;
    if(op==='notify'&&failNotify)throw new TypeError('Network down');
    if(op==='register')enabled=true;
    if(op==='unregister')enabled=false;
    const status=['register','unregister','status'].includes(op)?(enabled?'enabled':'disabled'):notifyStatus;
    return new Response(JSON.stringify({status}),{headers:{'Content-Type':'application/json'}});
  }};
}

test('notifications request permission only on explicit Home Screen click and preserve existing keys',async()=>{
 const persistent=await persistentDevice(),key=persistent.device.encryption.privateKey;
 const service=await notificationService();
 const app=await harness(persistent,'',{standalone:true,pushEndpoint:'https://push.example/api',pushFetch:service.fetch});
 await waitUntil(()=>!app.el('push-enable').disabled,'push button available');
 assert.deepEqual(app.pushCounts(),{permission:0,subscribe:0,unsubscribe:0});
 const enable=app.event('push-enable');
 assert.equal(app.pushCounts().permission,1,'Permission starts synchronously in click');
 await enable;
 assert.equal(app.pushCounts().subscribe,1);assert.equal(app.el('push-test').hidden,false);
 assert.equal(persistent.device.encryption.privateKey,key);
 const registered=service.requests.find(r=>r.envelope?.op==='register');
 assert.ok(registered);assert.equal(registered.envelope.data.senders.length,1);
 assert.ok(!service.requests.some(r=>r.envelope?.op==='test'),'Enabling never sends a notification itself');
 await app.event('push-test');assert.equal(service.requests.filter(r=>r.envelope?.op==='test').length,1);
 await app.event('push-disable');assert.equal(app.el('push-test').hidden,true);assert.equal(app.pushCounts().unsubscribe,1);
});

test('ordinary browser launch never asks for notification permission or subscribes',async()=>{
 const service=await notificationService();
 const app=await harness(await persistentDevice(),'',{pushEndpoint:'https://push.example/api',pushFetch:service.fetch});
 await app.event('push-enable');assert.equal(app.pushCounts().permission,0);assert.equal(app.pushCounts().subscribe,0);
 assert.match(app.el('push-status').textContent,/синий значок/);
 assert.equal(service.requests.length,0);
});

test('notification denial and failed subscription leave decryption keys and main features intact',async t=>{
 for(const options of [{permissionResult:'denied'},{rejectSubscribe:true}])await t.test(JSON.stringify(options),async()=>{
  const persistent=await persistentDevice(),key=persistent.device.signing.privateKey,service=await notificationService();
  const app=await harness(persistent,'',{standalone:true,pushEndpoint:'https://push.example/api',pushFetch:service.fetch,...options});
  await app.event('push-enable');assert.equal(app.el('push-test').hidden,true);
  assert.equal(persistent.device.signing.privateKey,key);assert.equal(app.el('open').disabled,false);
  assert.ok(!service.requests.some(r=>r.envelope?.op==='register'));
 });
});

test('refresh retains consent: an existing but server-disabled subscription is not silently enabled',async()=>{
 const service=await notificationService({enabled:false});
 const app=await harness(await persistentDevice(),'',{standalone:true,pushEndpoint:'https://push.example/api',pushFetch:service.fetch,notificationPermission:'granted',pushSubscription:true});
 await waitUntil(()=>service.requests.some(r=>r.envelope?.op==='status'),'server status checked');
 await waitUntil(()=>/выключены/.test(app.el('push-status').textContent),'disabled state shown');
 assert.equal(app.pushCounts().permission,0);assert.equal(app.pushCounts().subscribe,0);
 assert.ok(!service.requests.some(r=>r.envelope?.op==='register'));
});

test('enabled startup refreshes verified senders without requesting permission; adding and removing contacts updates consent', async () => {
  const persistent = await persistentDevice(), colleague = await persistentDevice();
  const selfID = (await exchange.deviceIdentity(persistent.device)).id;
  const card = await exchange.exportPublicCard(colleague.device, 'Коллега');
  const contact = await exchange.importPublicCard(card);
  const service = await notificationService({enabled:true});
  const app = await harness(persistent, '', {standalone:true, pushEndpoint:'https://push.example/api', pushFetch:service.fetch, notificationPermission:'granted', pushSubscription:true});
  const registrations = () => service.requests.filter(request => request.envelope?.op === 'register');
  await waitUntil(() => !app.el('push-test').hidden && !app.el('push-test').disabled, 'existing subscription refreshed');
  assert.deepEqual(app.pushCounts(), {permission:0, subscribe:0, unsubscribe:0});
  assert.deepEqual(registrations().at(-1).envelope.data.senders, [selfID]);
  await addCard(app, card);
  await waitUntil(() => registrations().length === 2 && !app.el('push-test').disabled, 'added contact registered');
  assert.deepEqual(registrations().at(-1).envelope.data.senders, [selfID, contact.id].sort());
  await app.el('contacts-list').querySelectorAll('button')[0].fire('click');
  await waitUntil(() => registrations().length === 3 && !app.el('push-test').disabled, 'removed contact revoked');
  assert.deepEqual(registrations().at(-1).envelope.data.senders, [selfID]);
  await app.event('push-disable');
  await addCard(app, card);
  assert.equal(registrations().length, 3, 'Contact edits never reactivate notifications after disabling');
});

test('a contact saved while notification enablement is in flight refreshes the final consent list', async () => {
  const persistent = await persistentDevice(), colleague = await persistentDevice();
  const card = await exchange.exportPublicCard(colleague.device, 'Коллега');
  const contact = await exchange.importPublicCard(card);
  const service = await notificationService();
  let enter, release, held = false;
  const started = new Promise(resolve => { enter = resolve; });
  const wait = new Promise(resolve => { release = resolve; });
  const fetcher = async (url, options) => {
    const response = await service.fetch(url, options);
    if (JSON.parse(options.body).envelope?.op === 'register' && !held) { held = true; enter(); await wait; }
    return response;
  };
  const app = await harness(persistent, '', {standalone:true, pushEndpoint:'https://push.example/api', pushFetch:fetcher});
  const enabling = app.event('push-enable');
  await started;
  await addCard(app, card);
  release(); await enabling;
  const registrations = service.requests.filter(request => request.envelope?.op === 'register');
  assert.equal(registrations.length, 2);
  assert.ok(!registrations[0].envelope.data.senders.includes(contact.id));
  assert.ok(registrations[1].envelope.data.senders.includes(contact.id));
});

test('composition notifies only the created short-link capability; push failure leaves the selected recipient link copyable', async t => {
  for (const failNotify of [false, true]) await t.test(failNotify ? 'push unavailable' : 'push accepted', async () => {
    const sender = await persistentDevice(), recipient = await persistentDevice();
    const recipientCard = await exchange.exportPublicCard(recipient.device, 'Получатель');
    const contact = await exchange.importPublicCard(recipientCard);
    const broker = await shortlinkBroker(sender.device), service = await notificationService({failNotify});
    const fetcher = async (url, options) => {
      if (JSON.parse(options.body).envelope?.op === 'notify') assert.equal(broker.rows.size, 1, 'Short link is stored before notification');
      return service.fetch(url, options);
    };
    const app = await harness(sender, '', {...broker.options, pushEndpoint:'https://push.example/api', pushFetch:fetcher});
    await addCard(app, recipientCard);
    const url = await composeShortMessage(app, contact.id, 'orit');
    const requests = service.requests.filter(request => request.envelope?.op === 'notify');
    assert.equal(requests.length, 1);
    assert.deepEqual(requests[0].envelope.data, {id:new URL(url).hash.slice(3)}, 'Caller cannot override recipient or add plaintext to notification');
    assert.ok(!JSON.stringify(requests).includes('Тестов'));
    assert.match(app.el('notice').textContent, failNotify ? /не подтверждено/ : /Сервис принял уведомление/);
    await app.event('copy-composed');
    assert.equal(app.clipboard(), 'Новый пациент ОРИТ\n' + url);
    const client = new shortlinks.ShortLinkClient(broker.options.shortlinkEndpoint, {fetch:broker.options.shortlinkFetch});
    const token = await client.resolve(url, origin + appPath);
    const senderContact = {...await exchange.importPublicCard(await exchange.exportPublicCard(sender.device, 'Отправитель')), verified:true};
    assert.equal((await exchange.openSurname(recipient.device, token, [senderContact])).surname, 'Тестов');
    await assert.rejects(exchange.openSurname(sender.device, token, [senderContact]), /получател|браузер/);
  });
});
