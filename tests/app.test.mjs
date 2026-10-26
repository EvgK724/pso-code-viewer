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
import * as team from '../docs/team.mjs';
import * as direct from '../docs/direct.mjs';
import * as messages from '../docs/messages.mjs';
import * as photos from '../docs/photos.mjs';
import * as recipientTrust from '../docs/recipient-trust.mjs';
import * as deviceUnlock from '../docs/device-unlock.mjs';
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
  return {device:await cryptography.makeDevice(), contacts:new Map(), name:'',pending:new Map(),pins:new Map()};
}

async function harness(persistent, initialHash = '', {
  richClipboard = false, rejectRich = false, rejectText = false,
  readText = '', rejectRead = false, deferRead = false, standalone = false, legacyStandalone = false, initialHidden = false,
  nativeCopy = undefined, nativeShare = undefined, shortlinkEndpoint = '', shortlinkFetch = undefined,
  directEndpoint = '', directFetch = undefined,
  deviceAuthEndpoint = '', deviceAuthFetch = undefined,
  teamEndpoint = '', teamFetch = undefined, pushEndpoint = '', pushFetch = undefined, notificationPermission = 'default', pushSubscription = null, permissionResult = 'granted', rejectSubscribe = false, rejectUnsubscribe = false
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
    navigator:{clipboard:clipboardAPI, standalone:legacyStandalone,...(nativeShare?{share:nativeShare}:{}),...(pushEndpoint?{serviceWorker:{register:async()=>registration,ready:Promise.resolve(registration)}}:{})},
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
  class InjectedDirectClient extends direct.DirectClient {constructor(endpoint){super(endpoint,{fetch:directFetch});}}
  const pinStorage={getItem:key=>persistent.pins.get(key)||null,setItem:(key,value)=>persistent.pins.set(key,value)};
  class InjectedTeamClient extends team.TeamClient {constructor(endpoint){super(endpoint,{fetch:teamFetch});}}
  class InjectedDeviceUnlockClient extends deviceUnlock.DeviceUnlockClient {constructor(endpoint){super(endpoint,{fetch:deviceAuthFetch});}}
  const exportsFor = {
    './crypto.mjs':cryptography, './exchange.mjs':exchange, './storage.mjs':storage, './sharing.mjs':sharing,
    './shortlinks.mjs':{...shortlinks, ShortLinkClient:InjectedShortLinkClient},
    './shortlink-config.mjs':{SHORTLINK_ENDPOINT:shortlinkEndpoint,PUSH_ENDPOINT:pushEndpoint,TEAM_ENDPOINT:teamEndpoint,DIRECT_ENDPOINT:directEndpoint,DEVICE_AUTH_ENDPOINT:deviceAuthEndpoint},
    './push.mjs':{...push,PushClient:InjectedPushClient},
    './team.mjs':{...team,TeamClient:InjectedTeamClient},
    './direct.mjs':{...direct,DirectClient:InjectedDirectClient,savePending:async data=>persistent.pending.set(data.id,data),loadPending:async()=>[...persistent.pending.values()],removePending:async id=>persistent.pending.delete(id)},
    './messages.mjs':messages,'./photos.mjs':photos,'./device-unlock.mjs':{...deviceUnlock,DeviceUnlockClient:InjectedDeviceUnlockClient},
    './recipient-trust.mjs':{...recipientTrust,loadOrganizerCard:options=>recipientTrust.loadOrganizerCard({...options,storage:pinStorage}),pinOrganizerCard:(card,options)=>recipientTrust.pinOrganizerCard(card,{...options,storage:pinStorage})},
    './updates.mjs':{installAppUpdates(){return {ready:Promise.resolve(registration),check:async()=>{}};}}
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

async function teamFixture(stores,roles,{pushResult='unavailable',resolveStatus=0}={}){
  const records=new Map(),invitations=new Map(),requests=[],members=[];
  for(let i=0;i<stores.length;i++){const card=await exchange.exportPublicCard(stores[i].device,'Врач '+i),c=await exchange.importPublicCard(card);members.push({id:c.id,name:'Врач '+i,role:roles[i],card});}
  let pending=[];
  const fetcher=async(url,options)=>{
    const e=JSON.parse(options.body).envelope;requests.push(e);const own=await exchange.importPublicCard(e.card),m=members.find(m=>m.id===own.id);
    const response=(v,status=200)=>new Response(JSON.stringify(v),{status,headers:{'Content-Type':'application/json'}});
    if(e.op==='status')return response(m?{state:'active',name:m.name,role:m.role}:{state:'unregistered',name:null,role:null});
    if(e.op==='directory')return response({members});
    if(e.op==='pending')return response({members:pending});
    if(e.op==='claim'){pending.push({id:own.id,name:'Заявка',role:'neurologist',card:e.card});return response({state:'pending'});}
    if(e.op==='approve'){const entry=pending.find(v=>v.id===e.data.deviceId);if(entry){members.push(entry);pending=pending.filter(v=>v!==entry);}return response({state:'active'});}
    if(e.op==='invite'){
      const invitation={id:e.data.id,expires:Date.now()+60000,...(e.data.organizerCard?{organizerCard:e.data.organizerCard}:{})};
      invitations.set(e.data.id,invitation);return response({id:invitation.id,expires:invitation.expires});
    }
    if(e.op==='invite_info'){
      const invitation=invitations.get(e.data.id);
      return invitation?.organizerCard?response(invitation):response({error:'request_rejected'},404);
    }
    if(e.op==='create'){records.set(e.data.id,{...e.data,sender:m});return response({id:e.data.id,expires:e.data.expires,push:pushResult});}
    if(e.op==='resolve'){
      if(resolveStatus)return response({error:'request_rejected'},resolveStatus);
      const r=records.get(e.data.id);if(!r)return response({error:'request_rejected'},404);
      const entry=r.entries.find(e=>e.recipientId===own.id);if(!entry)return response({error:'request_rejected'},403);
      return response({token:entry.token,expires:r.expires,senderCard:r.sender.card,senderName:r.sender.name});
    }
    return response({error:'request_rejected'},403);
  };
  return {members,records,invitations,requests,setPending(value){pending=value;},options:{teamEndpoint:'https://team.example/api',teamFetch:fetcher,shortlinkEndpoint:'https://legacy.example/api',shortlinkFetch:async()=>new Response('{}',{status:404,headers:{'Content-Type':'application/json'}})}};
}

test('team UI exposes manual review only to neurologists/admin and never offers self/individual recipients',async()=>{
 const stores=await Promise.all(Array.from({length:4},()=>persistentDevice()));const service=await teamFixture(stores,['neurologist','cardiologist','intensivist','bot']);
 for(let i=0;i<stores.length;i++){
  const app=await harness(stores[i],'',service.options);
  assert.equal(app.el('show-write').hidden,i!==0);
  assert.deepEqual(app.el('recipient').options.map(o=>o.value),['','cardiology','orit']);
  if(i!==0){app.el('recipient').value='orit';app.el('compose-surname').value='Тестов';await app.event('compose-form','submit');assert.equal(app.el('compose-output').hidden,true);}
 }
 assert.equal(service.requests.filter(e=>e.op==='create').length,0);
});

test('one review link opens only each approved group recipient; unknown writer cards never persist locally',async()=>{
 const stores=await Promise.all(Array.from({length:4},()=>persistentDevice()));const service=await teamFixture(stores,['neurologist','intensivist','intensivist','cardiologist'],{pushResult:'partial'});
 const a=await harness(stores[0],'',service.options);a.el('recipient').value='orit';a.el('compose-surname').value='Тестов';a.el('compose-orit').checked=true;
 await a.event('compose-form','submit');await a.idle();const url=a.el('output-link').value;assert.ok(url, a.el('notice').textContent);await a.event('copy-composed');assert.equal(a.clipboard(),'Проверочная история\n'+url);
 const creation=service.requests.find(e=>e.op==='create');assert.equal(creation.data.kind,'review');assert.deepEqual(creation.data.entries.map(e=>e.recipientId).sort(),service.members.slice(1,3).map(m=>m.id).sort());assert.ok(!JSON.stringify(creation).includes('Тестов'));assert.match(a.el('notice').textContent,/Скопированы/);
 for(let i=1;i<4;i++){
  const b=await harness(stores[i],'',service.options);b.el('token').value=url;await b.event('open-form','submit');await b.idle();
  if(i<3){assert.equal(b.el('surname').textContent,'Тестов');assert.equal(b.el('department').textContent,'ОРИТ');}else{assert.equal(b.el('result').hidden,true);assert.match(b.el('notice').textContent,/доступа/);}
  assert.equal(stores[i].contacts.size,0,'Directory trust is memory-only; it does not replace legacy contact storage');
 }
});

test('team resolve403 never falls back to legacy broker while404 still opens existing encrypted links',async()=>{
 const sender=await persistentDevice(),recipient=await persistentDevice();const senderCard=await exchange.exportPublicCard(sender.device,'Отправитель'),senderContact=await exchange.importPublicCard(senderCard);recipient.contacts.set(senderContact.id,{id:senderContact.id,card:senderCard,verified:true});
 const rec={...await exchange.importPublicCard(await exchange.exportPublicCard(recipient.device,'Получатель')),verified:true};const broker=await shortlinkBroker(sender.device);const client=new shortlinks.ShortLinkClient(broker.options.shortlinkEndpoint,{fetch:broker.options.shortlinkFetch});const link=await client.create(sender.device,await exchange.sealSurname(sender.device,rec,'Тестов'),1440,origin+appPath);
 for(const status of [403,404]){
  const service=await teamFixture([recipient],['cardiologist'],{resolveStatus:status});let legacyCalls=0;
  const app=await harness(recipient,'',{...service.options,...broker.options,shortlinkFetch:async(...args)=>{legacyCalls++;return broker.options.shortlinkFetch(...args);}});
  app.el('token').value=link;await app.event('open-form','submit');await app.idle();assert.equal(legacyCalls,status===404?1:0);assert.equal(app.el('result').hidden,status!==404);
 }
});

test('activation never submits on opening invitation or in ordinary browser; explicit installed action requests review',async()=>{
 const store=await persistentDevice(),service=await teamFixture([],[]),id=team.randomTeamID();
 const browser=await harness(store,'#join='+id,service.options);await waitUntil(()=>!browser.el('join-panel').hidden,'join visible');assert.equal(service.requests.filter(e=>e.op==='claim').length,0);assert.equal(browser.el('team-claim').disabled,true);await browser.event('team-claim');assert.equal(service.requests.filter(e=>e.op==='claim').length,0);
 const app=await harness(store,'#join='+id,{...service.options,standalone:true});await waitUntil(()=>!app.el('join-panel').hidden,'join visible installed');assert.equal(app.el('team-claim').disabled,false);await app.event('team-claim');assert.equal(service.requests.filter(e=>e.op==='claim').length,1);assert.equal(app.el('show-write').hidden,true,'A claim alone never grants a sender role');
});

async function invitationFixture(){
 const organizer=await persistentDevice(),store=await persistentDevice(),service=await teamFixture([],[]);
 const card=await exchange.exportPublicCard(organizer.device,'Тестовый организатор');
 const id=team.randomTeamID(),url=await recipientTrust.trustedInvitationURL(origin+appPath,id,card);
 const options={...service.options,directEndpoint:'https://direct.example/api',directFetch:async()=>{throw new Error('No direct call expected before enrollment');}};
 return {store,service,card,id,url,options};
}

async function shortInvitationFixture(){
 const s=await invitationFixture();
 const url=await recipientTrust.shortTrustedInvitationURL(origin+appPath,s.id,s.card);
 s.service.invitations.set(s.id,{id:s.id,expires:Date.now()+60000,organizerCard:s.card});
 return {...s,url};
}

test('short invitation loads its public card without claiming or pinning and survives browser reload',async()=>{
 const s=await shortInvitationFixture(),hash=new URL(s.url).hash;
 assert.match(hash,/^#i=[A-Za-z0-9_-]{64}$/);
 const browser=await harness(s.store,hash,s.options);
 await waitUntil(()=>!browser.el('join-panel').hidden,'short invitation visible');
 assert.equal(browser.el('join-link').value,s.url);assert.equal(browser.location.hash,hash);
 assert.equal(browser.el('organizer-trust').hidden,false);assert.equal(browser.el('team-claim').disabled,true);
 const lookups=s.service.requests.filter(r=>r.op==='invite_info');
 assert.equal(lookups.length,1);assert.deepEqual(lookups[0].data,{id:s.id});
 assert.equal(s.store.pins.size,0);assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
 const reloaded=await harness(s.store,browser.location.hash,s.options);
 await waitUntil(()=>!reloaded.el('join-panel').hidden,'short invitation restored');
 assert.equal(reloaded.el('join-link').value,s.url);assert.equal(reloaded.location.hash,hash);
 assert.equal(s.service.requests.filter(r=>r.op==='invite_info').length,2);
 assert.equal(s.store.pins.size,0);assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
});

test('pasted short invitation requires explicit organizer confirmation and installed-device claim',async()=>{
 const s=await shortInvitationFixture(),app=await harness(s.store,'',{...s.options,standalone:true,readText:s.url});
 await app.event('paste-open');await app.idle();
 assert.equal(app.el('join-link').value,s.url);assert.equal(app.el('join-panel').hidden,false);
 assert.equal(s.service.requests.filter(r=>r.op==='invite_info').length,1);
 assert.equal(s.store.pins.size,0);assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
 await app.event('team-claim');assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
 app.el('organizer-confirm').checked=true;await app.event('organizer-confirm','change');
 await app.event('organizer-save');await app.idle();assert.equal(s.store.pins.size,1);
 await app.event('team-claim');
 assert.equal(s.service.requests.filter(r=>r.op==='claim').length,1);
 assert.equal(s.service.requests.find(r=>r.op==='claim').data.id,s.id);
 assert.equal(app.el('join-panel').hidden,true);
});

test('short invitation rejects a substituted public card without pinning or submitting a claim',async()=>{
 const s=await shortInvitationFixture(),other=await persistentDevice();
 const substituted=await exchange.exportPublicCard(other.device,'Другой организатор');
 s.service.invitations.set(s.id,{id:s.id,expires:Date.now()+60000,organizerCard:substituted});
 const app=await harness(s.store,'',{...s.options,standalone:true,readText:s.url});
 await app.event('paste-open');await app.idle();
 assert.equal(s.service.requests.filter(r=>r.op==='invite_info').length,1);
 assert.equal(app.el('join-panel').hidden,true);assert.equal(app.el('organizer-trust').hidden,true);
 assert.equal(app.el('team-claim').disabled,true);assert.match(app.el('notice').textContent,/ключ|карточк|приглашени/i);
 await app.event('team-claim');
 assert.equal(s.store.pins.size,0);assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
});

test('a short invitation cannot replace a confirmed organizer with another root key',async()=>{
 const s=await shortInvitationFixture(),other=await persistentDevice();
 const app=await harness(s.store,'',{...s.options,standalone:true,readText:s.url});
 await app.event('paste-open');await app.idle();
 app.el('organizer-confirm').checked=true;await app.event('organizer-confirm','change');
 await app.event('organizer-save');await app.idle();
 const storedPin=[...s.store.pins.entries()];assert.equal(storedPin.length,1);
 const otherCard=await exchange.exportPublicCard(other.device,'Другой организатор'),otherID=team.randomTeamID();
 const otherURL=await recipientTrust.shortTrustedInvitationURL(origin+appPath,otherID,otherCard);
 s.service.invitations.set(otherID,{id:otherID,expires:Date.now()+60000,organizerCard:otherCard});
 app.setReadText(otherURL);await app.event('paste-open');await app.idle();
 assert.equal(app.el('join-panel').hidden,true);assert.equal(app.el('team-claim').disabled,true);
 assert.match(app.el('notice').textContent,/Ключ организатора.*не совпадает.*сохранённым/);
 await app.event('team-claim');
 assert.deepEqual([...s.store.pins.entries()],storedPin);
 assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
 const reloaded=await harness(s.store,new URL(otherURL).hash,{...s.options,standalone:true});
 await waitUntil(()=>/Ключ организатора.*не совпадает.*сохранённым/.test(reloaded.el('notice').textContent),'saved pin checked after reload');
 assert.equal(reloaded.el('join-panel').hidden,true);assert.equal(reloaded.el('team-claim').disabled,true);
 await reloaded.event('team-claim');
 assert.deepEqual([...s.store.pins.entries()],storedPin);
 assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
});

test('a delayed short-invitation response cannot replace a newer incoming invitation',async()=>{
 const s=await shortInvitationFixture(),other=await persistentDevice();
 const nextCard=await exchange.exportPublicCard(other.device,'Следующий организатор'),nextID=team.randomTeamID();
 const nextURL=await recipientTrust.shortTrustedInvitationURL(origin+appPath,nextID,nextCard);
 s.service.invitations.set(nextID,{id:nextID,expires:Date.now()+60000,organizerCard:nextCard});
 let release,started=false,finished=false;
 const gate=new Promise(resolve=>release=resolve);
 const app=await harness(s.store,'',{...s.options,standalone:true,teamFetch:async(url,options)=>{
  const e=JSON.parse(options.body).envelope;
  if(e.op==='invite_info'&&e.data.id===s.id){started=true;await gate;const response=await s.options.teamFetch(url,options);finished=true;return response;}
  return s.options.teamFetch(url,options);
 }});
 await app.hashchange(new URL(s.url).hash);await waitUntil(()=>started,'first lookup started');
 await app.hashchange(new URL(nextURL).hash);
 release();await waitUntil(()=>finished,'old lookup finished');
 await waitUntil(()=>app.el('join-link').value===nextURL&&!app.el('join-panel').hidden,'new invitation displayed');
 assert.equal(app.location.hash,new URL(nextURL).hash);
 const next=await exchange.importPublicCard(nextCard);assert.equal(app.el('organizer-code').textContent,next.fingerprint);
 assert.equal(s.store.pins.size,0);assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
 assert.deepEqual(s.service.requests.filter(r=>r.op==='invite_info').map(r=>r.data.id).sort(),[s.id,nextID].sort());
});

test('compact invitation opens and survives reload without enrolling or trusting a device automatically',async()=>{
 const s=await invitationFixture(),hash=new URL(s.url).hash;
 const browser=await harness(s.store,hash,s.options);
 await waitUntil(()=>!browser.el('join-panel').hidden,'compact invitation visible');
 assert.equal(browser.location.hash,hash,'Public invitation remains available after refresh');
 assert.equal(browser.el('organizer-trust').hidden,false);
 assert.equal(browser.el('join-link').value,s.url);
 assert.equal(browser.el('team-claim').disabled,true,'Ordinary browser cannot silently bind a different device store');
 assert.equal(s.store.pins.size,0);assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
 const reloaded=await harness(s.store,browser.location.hash,s.options);
 await waitUntil(()=>!reloaded.el('join-panel').hidden,'invitation restored from address on reload');
 assert.equal(reloaded.el('join-link').value,s.url);assert.equal(reloaded.location.hash,hash);
 assert.equal(s.store.pins.size,0);assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
});

test('compact invitation paste is recognized, requires trust confirmation and clears address only after successful claim',async()=>{
 const s=await invitationFixture(),hash=new URL(s.url).hash;
 const app=await harness(s.store,'',{...s.options,standalone:true,readText:s.url});
 await app.event('paste-open');await app.idle();
 assert.equal(app.el('join-panel').hidden,false);assert.equal(app.el('organizer-trust').hidden,false);
 assert.equal(s.store.pins.size,0);assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
 app.el('join-link').value='';
 await app.hashchange(hash);await waitUntil(()=>app.el('join-link').value===s.url,'incoming invitation parsed');
 assert.equal(app.location.hash,hash);
 await app.event('team-claim');assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
 app.el('organizer-confirm').checked=true;await app.event('organizer-confirm','change');
 await app.event('organizer-save');await app.idle();
 assert.equal(s.store.pins.size,1);assert.equal(app.location.hash,hash);
 await app.event('team-claim');
 assert.equal(s.service.requests.filter(r=>r.op==='claim').length,1);
 assert.equal(s.service.requests.find(r=>r.op==='claim').data.id,s.id);
 assert.equal(app.location.hash,'');assert.equal(app.el('join-panel').hidden,true);
});

test('truncated legacy organizer-card invitation reports the actual error without claiming or pinning',async()=>{
 const s=await invitationFixture(),broken=origin+appPath+'#join='+s.id+'&organizer=PSO-CARD1';
 const app=await harness(s.store,new URL(broken).hash,{...s.options,standalone:true});
 await waitUntil(()=>/Ссылка приглашения обрезана/.test(app.el('notice').textContent),'specific incomplete invitation message');
 assert.equal(app.el('join-panel').hidden,true);assert.equal(app.el('organizer-trust').hidden,true);
 assert.equal(s.store.pins.size,0);assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
 app.el('token').value=broken;await app.event('open-form','submit');await app.idle();
 assert.match(app.el('notice').textContent,/Ссылка приглашения обрезана/);
 assert.equal(s.store.pins.size,0);assert.equal(s.service.requests.filter(r=>r.op==='claim').length,0);
});

test('retaining invitation hashes does not retain patient-message hashes on startup or hash change',async()=>{
 const store=await persistentDevice(),id=team.randomTeamID();
 const app=await harness(store,'#m='+id);
 assert.equal(app.location.hash,'');
 await app.hashchange('#pso=PSO1.invalid');assert.equal(app.location.hash,'');
});

test('invite sharing sends only the full URL from the click gesture; cancel never falls back to clipboard',async()=>{
 const s=await directFixture(['admin']),payloads=[];
 let cancel=false;
 const app=await harness(s.stores[0],'',{...s.options,standalone:true,nativeShare(payload){
  payloads.push(JSON.parse(JSON.stringify(payload)));
  if(cancel){const error=new Error('Share dismissed');error.name='AbortError';return Promise.reject(error);}
  return Promise.resolve();
 }});
 app.el('invite-name').value='Тестовый кардиолог';app.el('invite-role').value='cardiologist';
 await app.event('invite-form','submit');
 const url=app.el('invite-link').value;assert.match(new URL(url).hash,/^#i=[A-Za-z0-9_-]{64}$/);
 const first=app.event('share-invite');
 assert.deepEqual(payloads,[{url}],'Native share must run during the button gesture, with no additional text/card');
 await first;assert.deepEqual(app.clipboardAttempts(),{rich:0,plain:0});
 cancel=true;await app.event('share-invite');
 assert.deepEqual(payloads,[{url},{url}]);assert.deepEqual(app.clipboardAttempts(),{rich:0,plain:0});
});

test('without native sharing the invitation copy fallback retains the complete URL',async()=>{
 const s=await directFixture(['admin']),app=await harness(s.stores[0],'',{...s.options,standalone:true});
 app.el('invite-name').value='Тестовый кардиолог';app.el('invite-role').value='cardiologist';
 await app.event('invite-form','submit');const url=app.el('invite-link').value;assert.match(new URL(url).hash,/^#i=[A-Za-z0-9_-]{64}$/);
 await app.event('share-invite');assert.equal(app.clipboard(),url);
 assert.deepEqual(app.clipboardAttempts(),{rich:0,plain:1});
});

test('admin approval requires explicit fingerprint checkbox even after ordinary busy updates',async()=>{
 const admin=await persistentDevice(),applicant=await persistentDevice(),service=await teamFixture([admin],['admin']);const card=await exchange.exportPublicCard(applicant.device,'Врач'),contact=await exchange.importPublicCard(card);service.setPending([{id:contact.id,name:'Врач',role:'neurologist',card}]);
 const app=await harness(admin,'',service.options);await waitUntil(()=>app.el('team-pending').querySelectorAll('button').length===1,'pending rendered');
 const approve=app.el('team-pending').querySelectorAll('button')[0],check=app.el('team-pending').querySelectorAll('input')[0];
 await app.event('recipient','change');assert.equal(approve.disabled,true);await approve.fire('click');assert.equal(service.requests.filter(e=>e.op==='approve').length,0);
 check.checked=true;await check.fire('change');assert.equal(approve.disabled,false);await approve.fire('click');assert.equal(service.requests.filter(e=>e.op==='approve').length,1);
});

test('team create network failure clears stale output without producing any plaintext or legacy fallback',async()=>{
 const stores=await Promise.all([persistentDevice(),persistentDevice()]),service=await teamFixture(stores,['neurologist','cardiologist']);let fail=false,legacyCalls=0;
 const app=await harness(stores[0],'',{...service.options,teamFetch:async(url,options)=>{if(fail&&JSON.parse(options.body).envelope.op==='create')throw new TypeError('Offline');return service.options.teamFetch(url,options);},shortlinkFetch:async()=>{legacyCalls++;throw new Error('No legacy writes');}});
 app.el('recipient').value='cardiology';app.el('compose-surname').value='Тестов';await app.event('compose-form','submit');assert.ok(app.el('output-link').value);
 fail=true;app.el('compose-surname').value='Другой';await app.event('compose-form','submit');await app.idle();
 assert.equal(app.el('compose-output').hidden,true);assert.equal(app.el('output-link').value,'');assert.equal(app.el('output-message').value,'');assert.equal(app.el('output-preview').href,'#');assert.equal(app.el('compose-surname').value,'');assert.equal(app.el('copy-composed').disabled,true);assert.equal(legacyCalls,0);assert.equal(service.records.size,1);assert.ok(!JSON.stringify(service.requests).includes('Тестов'));assert.ok(!JSON.stringify(service.requests).includes('Другой'));
});

test('team notification consent includes approved sender roles but no other group recipient',async()=>{
 const stores=await Promise.all(Array.from({length:5},()=>persistentDevice())),service=await teamFixture(stores,['admin','neurologist','bot','cardiologist','intensivist']),push=await notificationService({enabled:true});
 const app=await harness(stores[3],'',{...service.options,standalone:true,pushEndpoint:'https://push.example/api',pushFetch:push.fetch,notificationPermission:'granted',pushSubscription:true});
 await waitUntil(()=>!app.el('push-test').hidden&&!app.el('push-test').disabled,'team notification consent ready');
 const registered=push.requests.filter(r=>r.envelope?.op==='register').at(-1);assert.ok(registered);
 assert.deepEqual(registered.envelope.data.senders,service.members.slice(0,4).map(m=>m.id).sort());assert.equal(stores[3].contacts.size,0);
 assert.deepEqual(app.pushCounts(),{permission:0,subscribe:0,unsubscribe:0});
});

async function directFixture(roles=['admin','neurologist','cardiologist']){
 const stores=await Promise.all(roles.map(()=>persistentDevice()));
 const base=await teamFixture(stores,roles);const members=base.members.map(member=>({...member})),root=members[0];
 for(const member of members)member.approvalProof=await recipientTrust.makeRecipientGrant(stores[0].device,member);
 for(const store of stores)await recipientTrust.pinOrganizerCard(root.card,{confirmed:true,storage:{getItem:k=>store.pins.get(k)||null,setItem:(k,v)=>store.pins.set(k,v)}});
 const records=new Map(),requests=[];let failAfterCreate=false,openTransform=x=>x,openGate=null;
 const respond=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});
 const fetcher=async(url,options)=>{
  const envelope=JSON.parse(options.body).envelope,{signature,...unsigned}=envelope;requests.push(envelope);
  const author=await exchange.importPublicCard(envelope.card),member=members.find(x=>x.id===author.id);
  assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},author.signingPublicKey,Buffer.from(signature,'base64url'),new TextEncoder().encode('PSO-TEAM-v1\0'+JSON.stringify(unsigned))),true);
  if(envelope.op==='directory')return respond({members:members.filter(m=>!m.state||m.state==='active')});
  if(envelope.op==='admin_members')return respond({members:members.map(m=>({state:'active',...m}))});
  if(envelope.op==='admin_certify'){
   const target=members.find(m=>m.id===envelope.data.id);await recipientTrust.verifyRecipientGrant({...target,approvalProof:envelope.data.approvalProof},root.card);
   target.approvalProof=envelope.data.approvalProof;return respond({state:'active'});
  }
  if(envelope.op==='admin_update'){
   const target=members.find(m=>m.id===envelope.data.id);if(envelope.data.state==='active')await recipientTrust.verifyRecipientGrant({...target,...envelope.data},root.card);
   Object.assign(target,envelope.data);return respond({state:target.state});
  }
  if(envelope.op==='admin_replace'){
   const previous=members.find(m=>m.id===envelope.data.oldId),next=members.find(m=>m.id===envelope.data.newId);
   assert.equal(next.state,'pending');const updated={...next,name:previous.name,role:previous.role,approvalProof:envelope.data.approvalProof};await recipientTrust.verifyRecipientGrant(updated,root.card);
   Object.assign(next,updated,{state:'active'});previous.state='revoked';return respond({state:'active'});
  }
  if(envelope.op==='create'){
   if(!records.has(envelope.data.id))records.set(envelope.data.id,{...envelope.data,sender:member,opened:new Set()});
   else assert.equal(JSON.stringify(envelope.data),JSON.stringify((({sender,opened,...data})=>data)(records.get(envelope.data.id))),'retry retains exact encrypted envelope');
   if(failAfterCreate)throw new TypeError('response lost');
   return respond({id:envelope.data.id,expires:envelope.data.expires,push:'accepted'});
  }
  if(envelope.op==='inbox'||envelope.op==='outbox'){
   const own=member.id;const items=[...records.values()].filter(r=>envelope.op==='outbox'?r.sender.id===own:r.entries.some(e=>e.recipientId===own)).map(r=>({id:r.id,group:r.group,kind:r.kind,issued:r.issued,expires:r.expires,senderId:r.sender.id,senderName:r.sender.name,openedAt:r.opened.has(own)?r.issued+1:null,recipientCount:r.entries.length,openedCount:r.opened.size}));
   return respond({items,next:null});
  }
  if(envelope.op==='open'){
   if(openGate)await openGate;
   const r=records.get(envelope.data.id);if(!r)return respond({error:'not_found'},404);
   const entry=r.entries.find(e=>e.recipientId===member.id);if(!entry)return respond({error:'forbidden'},403);
   return respond(openTransform({token:entry.token,payload:r.payload||null,senderCard:r.sender.card,senderName:r.sender.name,senderRole:r.sender.role,senderApprovalProof:r.sender.approvalProof,meta:{id:r.id,group:r.group,kind:r.kind,issued:r.issued,expires:r.expires}}));
  }
  if(envelope.op==='ack'){records.get(envelope.data.id).opened.add(member.id);return respond({openedAt:Date.now()});}
  return respond({error:'unsupported'},400);
 };
 return {stores,members,records,requests,setFailure(v){failAfterCreate=v;},transform(fn){openTransform=fn;},gate(p){openGate=p;},options:{...base.options,directEndpoint:'https://direct.example/api',directFetch:fetcher}};
}
async function directSend(app,{surname='Иванов',comment='Проверить историю',group='cardiology'}={}){
 await app.event('show-write');app.el('recipient').value=group;await app.event('recipient','change');
 app.el('compose-surname').value=surname;app.el('compose-comment').value=comment;
 await app.event('compose-form','submit');await app.idle();
}

test('direct review is encrypted before network/persistence, opens from inbox, acknowledges only verified display and clears on hide',async()=>{
 const s=await directFixture(),writer=await harness(s.stores[1],'',s.options);
 await directSend(writer);assert.equal(s.records.size,1,writer.el('notice').textContent);assert.equal(s.stores[1].pending.size,0);
 const record=[...s.records.values()][0],sent=s.requests.find(r=>r.op==='create');
 assert.equal(record.kind,'review');assert.deepEqual(record.entries.map(e=>e.recipientId),[s.members[2].id]);
 assert.ok(!JSON.stringify(sent).includes('Иванов'));assert.ok(!JSON.stringify(sent).includes('Проверить историю'));assert.equal(writer.el('compose-surname').value,'');assert.equal(writer.el('compose-comment').value,'');
 const reader=await harness(s.stores[2],'',s.options);await waitUntil(()=>reader.el('inbox-list').querySelectorAll('button').length===1,'direct inbox');
 assert.ok(!reader.el('inbox-list').querySelectorAll('p').some(p=>p.textContent.includes('Иванов')));
 await reader.el('inbox-list').querySelectorAll('button')[0].fire('click');await reader.idle();
 assert.equal(reader.el('surname').textContent,'Иванов');assert.equal(reader.el('result-comment').textContent,'Проверить историю');
 await waitUntil(()=>record.opened.has(s.members[2].id),'successful display acknowledgement');
 await reader.hide();assert.equal(reader.el('result').hidden,true);assert.equal(reader.el('surname').textContent,'');assert.equal(reader.el('result-comment').textContent,'');await reader.show();assert.equal(reader.el('result').hidden,true);
 await writer.event('show-read');await writer.event('box-outbox');await waitUntil(()=>writer.el('inbox-list').querySelectorAll('p').some(p=>p.textContent.includes('Открыли: 1')),'outgoing receipt');
 assert.match(writer.el('inbox-status').textContent,/не выполненную консультацию/);
});

test('lost send response retries the same durable encrypted message without duplicates after app restart',async()=>{
 const s=await directFixture(),writer=await harness(s.stores[1],'',s.options);s.setFailure(true);await directSend(writer,{surname:'Петров'});
 assert.equal(s.records.size,1);assert.equal(s.stores[1].pending.size,1);const queued=[...s.stores[1].pending.values()][0];assert.ok(!JSON.stringify(queued).includes('Петров'));
 const restarted=await harness(s.stores[1],'',s.options);await waitUntil(()=>!restarted.el('retry-pending').hidden,'persistent retry button');s.setFailure(false);await restarted.event('retry-pending');
 await waitUntil(()=>s.stores[1].pending.size===0,'pending delivered');assert.equal(s.records.size,1);assert.equal(s.requests.filter(r=>r.op==='create').length,2);assert.equal(s.requests.filter(r=>r.op==='create')[1].data.id,queued.id);
});

test('direct opening fails closed for invalid sender grant, signed-role mismatch and metadata substitution, without acknowledgement',async t=>{
 const s=await directFixture(),writer=await harness(s.stores[1],'',s.options);await directSend(writer);const record=[...s.records.values()][0];
 for(const [name,transform] of [
  ['grant removed',r=>({...r,senderApprovalProof:null})],
  ['neurologist presented as bot',r=>({...r,meta:{...r.meta,kind:'admission'}})],
  ['time changed',r=>({...r,meta:{...r.meta,issued:r.meta.issued-1}})],
  ['group changed',r=>({...r,meta:{...r.meta,group:'orit'}})]
 ])await t.test(name,async()=>{
  s.transform(transform);const reader=await harness(s.stores[2],'',s.options);await reader.hashchange('#m='+record.id);await reader.idle();
  assert.equal(reader.el('result').hidden,true);assert.equal(reader.el('surname').textContent,'');assert.equal(s.requests.filter(r=>r.op==='ack').length,0);assert.equal(reader.el('notice').attributes.get('role'),'alert');
 });
});

test('a delayed direct response cannot reveal or acknowledge after backgrounding',async()=>{
 const s=await directFixture(),writer=await harness(s.stores[1],'',s.options);await directSend(writer);const record=[...s.records.values()][0];
 let release;s.gate(new Promise(resolve=>release=resolve));const reader=await harness(s.stores[2],'',s.options);const operation=reader.hashchange('#m='+record.id);
 await waitUntil(()=>s.requests.some(r=>r.op==='open'),'open requested');await reader.hide();release();await operation;await reader.idle();
 assert.equal(reader.el('surname').textContent,'');assert.equal(reader.el('result-comment').textContent,'');assert.equal(reader.el('result').hidden,true);assert.equal(s.requests.filter(r=>r.op==='ack').length,0);
});

test('a missing pinned organizer never trusts a server-supplied directory',async()=>{
 const s=await directFixture(),writer=await harness(s.stores[1],'',s.options);s.stores[1].pins.clear();const fresh=await harness(s.stores[1],'',s.options);await directSend(fresh);
 assert.equal(s.requests.filter(r=>r.op==='create').length,0);assert.match(fresh.el('notice').textContent,/ключ организатора/);
});

test('direct photo is shown via local blob URL and revoked with all plaintext at the 30-second deadline',async()=>{
 const s=await directFixture(),issued=Date.now(),id=direct.newMessageID(),meta={id,group:'cardiology',kind:'review',issued,expires:issued+60000};
 const data=(await readFile(new URL('./fixtures/review.jpg',import.meta.url))).toString('base64url'),photo={mime:'image/jpeg',data,width:3,height:2};
 const recipient={...await exchange.importPublicCard(s.members[2].card),verified:true};
 const sealed=await messages.sealMessage(s.stores[1].device,[recipient],{surname:'Сидоров',comment:'Комментарий на фото',photo},meta);
 s.records.set(id,{...meta,...sealed,sender:s.members[1],opened:new Set()});
 const reader=await harness(s.stores[2],'',s.options);await reader.hashchange('#m='+id);await reader.idle();
 assert.equal(reader.el('surname').textContent,'Сидоров');assert.equal(reader.el('result-photo').hidden,false);const url=reader.el('result-photo').src;assert.match(url,/^blob:/);
 assert.equal((await (await fetch(url)).arrayBuffer()).byteLength,Buffer.from(data,'base64url').byteLength);
 reader.advance(30001);assert.equal(reader.el('surname').textContent,'');assert.equal(reader.el('result-comment').textContent,'');assert.equal(reader.el('result-photo').hidden,true);await assert.rejects(fetch(url));
 assert.ok(!JSON.stringify(s.requests).includes('Сидоров'));assert.ok(!JSON.stringify(s.requests).includes(photo.data));
});

test('bot PSO1 admission opens in direct inbox only with matching authenticated timestamps',async()=>{
 const s=await directFixture(['admin','bot','cardiologist']);
 const recipient={...await exchange.importPublicCard(s.members[2].card),verified:true},sender={...await exchange.importPublicCard(s.members[1].card),verified:true};
 const token=await exchange.sealSurname(s.stores[1].device,recipient,'Петров',{department:'ОРИТ',ttlMinutes:60});
 const opened=await exchange.openSurname(s.stores[2].device,token,[sender]),id=direct.newMessageID();
 const record={id,group:'cardiology',kind:'admission',issued:opened.issued,expires:opened.expires,entries:[{recipientId:recipient.id,token}],sender:s.members[1],opened:new Set()};s.records.set(id,record);
 const reader=await harness(s.stores[2],'',s.options);await reader.hashchange('#m='+id);await reader.idle();assert.equal(reader.el('surname').textContent,'Петров');assert.equal(reader.el('department').textContent,'ОРИТ');
 await waitUntil(()=>record.opened.size===1,'bot admission ack');await reader.hide();await reader.show();record.opened.clear();s.transform(r=>({...r,meta:{...r.meta,issued:r.meta.issued-1}}));await reader.hashchange('#m='+id);await reader.idle();assert.equal(reader.el('result').hidden,true);assert.equal(record.opened.size,0);
});

test('administrator phone replacement requires fingerprint confirmation and signs the new key for the old role',async()=>{
 const s=await directFixture(['admin','cardiologist','neurologist']);s.members[2].state='pending';
 const admin=await harness(s.stores[0],'',s.options);await waitUntil(()=>admin.el('team-pending').querySelectorAll('button').length===1,'replacement approval');
 const pending=admin.el('team-pending'),button=pending.querySelectorAll('button')[0],checkbox=pending.querySelectorAll('input')[0],selection=pending.querySelectorAll('select')[0];selection.value=s.members[1].id;
 await button.fire('click');assert.equal(s.requests.filter(r=>r.op==='admin_replace').length,0);checkbox.checked=true;await checkbox.fire('change');await button.fire('click');
 const request=s.requests.find(r=>r.op==='admin_replace');assert.ok(request);assert.equal(request.data.oldId,s.members[1].id);assert.equal(request.data.newId,s.members[2].id);
 assert.equal(request.data.approvalProof.grant.subjectId,s.members[2].id);assert.equal(request.data.approvalProof.grant.role,'cardiologist');assert.equal(s.members[1].state,'revoked');assert.equal(s.members[2].state,'active');
 assert.match(admin.el('notice').textContent,/прежний отключён/);
});

async function adminUiFixture({withPush=false}={}){
 const service=await directFixture(),faults={status:0,directory:0,approve:0},events=[];
 service.members[2].state='pending';
 let approvalGate=null,failRefreshAfterApprove=false;
 const response=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});
 const options={...service.options,standalone:true,
  teamFetch:async(url,init)=>{
   const {envelope:e}=JSON.parse(init.body);events.push('team:'+e.op);
   if(e.op==='approve'){
    if(approvalGate)await approvalGate;
    if(failRefreshAfterApprove)faults.status=503;
   }
   if(faults[e.op])return response({error:'request_rejected'},faults[e.op]);
   if(e.op==='approve')service.members.find(m=>m.id===e.data.deviceId).state='active';
   return service.options.teamFetch(url,init);
  },
  directFetch:async(url,init)=>{events.push('direct:'+JSON.parse(init.body).envelope.op);return service.options.directFetch(url,init);},
  deviceAuthEndpoint:'https://auth.example/api',deviceAuthFetch:async(url,init)=>{events.push('auth:'+JSON.parse(init.body).envelope.op);return response({enabled:false});}
 };
 if(withPush){
  const notifications=await notificationService({enabled:true});
  Object.assign(options,{pushEndpoint:'https://push.example/api',notificationPermission:'granted',pushSubscription:true,pushFetch:async(url,init)=>{
   const body=JSON.parse(init.body);events.push('push:'+(body.op||body.envelope.op));return notifications.fetch(url,init);
  }});
 }
 return {...service,options,faults,events,gateApproval(value){approvalGate=value;},failRefreshAfterApprove(value){failRefreshAfterApprove=value;}};
}

test('transient status or directory errors preserve only the displayed admin identity and block stale actions',async()=>{
 const s=await adminUiFixture(),app=await harness(s.stores[0],'',s.options);
 const pending=app.el('team-pending'),approve=pending.querySelectorAll('button')[0],check=pending.querySelectorAll('input')[0];
 const key=s.stores[0].device;
 s.faults.directory=503;await app.event('team-refresh');
 assert.equal(app.el('team-admin').hidden,false);
 assert.match(app.el('team-state').textContent,/Врач 0 · Администратор/);
 assert.match(app.el('team-state').textContent,/Не удалось обновить список команды.*HTTP 503.*Действия недоступны/);
 assert.equal(app.el('invite-create').disabled,true);assert.equal(app.el('show-write').hidden,true);
 check.checked=true;await check.fire('change');assert.equal(approve.disabled,true);
 const before=s.events.length;await approve.fire('click');app.el('invite-name').value='Другой';app.el('invite-role').value='neurologist';await app.event('invite-form','submit');
 await app.hashchange('#m='+direct.newMessageID());await app.idle();
 assert.equal(s.events.length,before,'Offline identity grants neither management mutations nor message opening');
 assert.equal(app.el('result').hidden,true);assert.equal(s.stores[0].device,key);
 s.faults.directory=0;s.faults.status=503;await app.event('team-refresh');
 assert.equal(app.el('team-admin').hidden,false);assert.match(app.el('team-state').textContent,/Администратор.*HTTP 503/);
 s.faults.status=0;await app.event('team-refresh');await app.idle();
 assert.equal(app.el('team-admin').hidden,false);assert.equal(app.el('invite-create').disabled,false);assert.equal(app.el('show-write').hidden,false);
 assert.equal(app.el('team-state').textContent,'Врач 0 · Администратор');
});

test('an explicit authorization rejection or revoked status clears the retained admin identity',async()=>{
 for(const failure of ['status403','directory403','revoked']){
  const s=await adminUiFixture();let revoked=false;
  const teamFetch=s.options.teamFetch;
  const app=await harness(s.stores[0],'',{...s.options,teamFetch:async(url,init)=>{
   if(revoked&&JSON.parse(init.body).envelope.op==='status')return new Response(JSON.stringify({state:'revoked',role:'admin',name:'Врач 0'}),{headers:{'Content-Type':'application/json'}});
   return teamFetch(url,init);
  }});
  if(failure==='revoked')revoked=true;else s.faults[failure==='status403'?'status':'directory']=403;
  await app.event('team-refresh');assert.equal(app.el('team-admin').hidden,true,failure);
  assert.equal(app.el('show-write').hidden,true);assert.equal(app.el('invite-create').disabled,true);
  assert.match(app.el('team-state').textContent,/Доступ этого телефона отключён/);
  assert.doesNotMatch(app.el('team-state').textContent,/Администратор/);
 }
});

test('approval progress blocks duplicate clicks and periodic work; HTTP stage survives failed refresh and recovery',async()=>{
 const s=await adminUiFixture(),app=await harness(s.stores[0],'',s.options);
 const pending=app.el('team-pending'),approve=pending.querySelectorAll('button')[0],check=pending.querySelectorAll('input')[0];
 check.checked=true;await check.fire('change');
 let release;s.gateApproval(new Promise(resolve=>release=resolve));s.faults.approve=503;s.failRefreshAfterApprove(true);
 const start=s.events.length,operation=approve.fire('click');
 await waitUntil(()=>s.events.slice(start).includes('team:approve'),'approval request started');
 assert.equal(approve.disabled,true);assert.equal(approve.textContent,'Подтверждаем…');assert.match(app.el('notice').textContent,/Подтверждение телефона/);
 await approve.fire('click');app.advance(60000);await app.show();await app.event('device-unlock-enable');
 assert.deepEqual(s.events.slice(start),['team:approve'],'No background inbox/auth work or second approval is started');
 release();await operation;
 assert.match(app.el('notice').textContent,/Подтверждение телефона:.*HTTP 503/);
 assert.equal(app.el('team-admin').hidden,false);assert.equal(approve.disabled,true);assert.equal(s.members[2].state,'pending');
 s.gateApproval(null);s.failRefreshAfterApprove(false);s.faults.status=0;s.faults.approve=0;
 await app.event('team-refresh');
 const next=app.el('team-pending').querySelectorAll('button')[0],nextCheck=app.el('team-pending').querySelectorAll('input')[0];nextCheck.checked=true;await nextCheck.fire('change');await next.fire('click');
 assert.equal(s.members[2].state,'active');assert.equal(app.el('team-pending').querySelectorAll('button').length,0);
 assert.equal(s.requests.filter(e=>e.op==='admin_certify').length,1);assert.match(app.el('notice').textContent,/Подключение подтверждено/);
});

test('initialization avoids duplicate inbox/auth checks and post-refresh background work runs in order',async()=>{
 const s=await adminUiFixture({withPush:true}),app=await harness(s.stores[0],'',s.options);await app.pushIdle();
 assert.equal(s.events.filter(e=>e==='direct:inbox').length,1);
 assert.equal(s.events.filter(e=>e==='auth:status').length,1);
 assert.equal(s.events.filter(e=>e==='push:register').length,1);
 const start=s.events.length;await app.event('team-refresh');
 assert.deepEqual(s.events.slice(start),['team:status','team:directory','direct:admin_members','direct:inbox','auth:status','push:register']);
});

test('a notification arriving during team refresh waits and opens exactly once after membership is confirmed',async()=>{
 const s=await directFixture(),writer=await harness(s.stores[1],'',s.options);
 await directSend(writer);const record=[...s.records.values()][0];
 let gate=null,entered=false;
 const reader=await harness(s.stores[2],'',{...s.options,teamFetch:async(url,init)=>{
  if(gate&&JSON.parse(init.body).envelope.op==='status'){entered=true;await gate;}
  return s.options.teamFetch(url,init);
 }});
 let release;gate=new Promise(resolve=>release=resolve);
 const refresh=reader.event('team-refresh');await waitUntil(()=>entered,'refresh waiting on status');
 await reader.hashchange('#m='+record.id);await reader.hashchange('#m='+record.id);
 assert.equal(s.requests.filter(e=>e.op==='open').length,0,'The pending notification cannot open with membership refresh in flight');
 assert.equal(reader.el('result').hidden,true);
 release();await refresh;await reader.idle();
 await waitUntil(()=>reader.el('surname').textContent==='Иванов','deferred notification displayed');
 await waitUntil(()=>s.requests.filter(e=>e.op==='ack').length===1,'deferred notification acknowledged');
 assert.equal(s.requests.filter(e=>e.op==='open').length,1);
 await reader.hide();await reader.show();await reader.idle();
 assert.equal(s.requests.filter(e=>e.op==='open').length,1,'A completed notification is not queued again');
});

test('a queued notification survives a failed team refresh and opens only after a later successful refresh',async()=>{
 const s=await directFixture(),writer=await harness(s.stores[1],'',s.options);
 await directSend(writer);const record=[...s.records.values()][0];
 let gate=null,entered=false,failStatus=false;
 const reader=await harness(s.stores[2],'',{...s.options,teamFetch:async(url,init)=>{
  if(JSON.parse(init.body).envelope.op==='status'){
   if(gate){entered=true;await gate;}
   if(failStatus)return new Response(JSON.stringify({error:'request_rejected'}),{status:503,headers:{'Content-Type':'application/json'}});
  }
  return s.options.teamFetch(url,init);
 }});
 let release;gate=new Promise(resolve=>release=resolve);failStatus=true;
 const refresh=reader.event('team-refresh');await waitUntil(()=>entered,'failing refresh waiting on status');
 await reader.hashchange('#m='+record.id);release();await refresh;await reader.idle();
 assert.match(reader.el('team-state').textContent,/Действия недоступны/);
 assert.equal(s.requests.filter(e=>e.op==='open').length,0);assert.equal(reader.el('result').hidden,true);
 await reader.show();await reader.idle();assert.equal(s.requests.filter(e=>e.op==='open').length,0);
 gate=null;failStatus=false;await reader.event('team-refresh');await reader.idle();
 await waitUntil(()=>reader.el('surname').textContent==='Иванов','notification retained through outage');
 await waitUntil(()=>s.requests.filter(e=>e.op==='ack').length===1,'retained notification acknowledged');
 assert.equal(s.requests.filter(e=>e.op==='open').length,1);
});
