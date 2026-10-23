import {makeDevice} from './crypto.mjs';
import {importPublicCard} from './exchange.mjs';

// GitHub project sites can share an origin. Scope our stores to this app path.
// This avoids collisions; it is not a security boundary between same-origin apps.
const storageScope = encodeURIComponent(new URL('./', import.meta.url).pathname);

function openDB(name, version, upgrade) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name + '-' + storageScope, version);
    request.onupgradeneeded = () => upgrade(request.result);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('Хранилище недоступно. Откройте просмотрщик в обычном режиме браузера.'));
    request.onblocked = () => reject(new Error('Закройте другие вкладки просмотрщика и откройте его снова.'));
  });
}

function transaction(db, storeName, mode, action) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, mode);
    let value;
    const request = action(tx.objectStore(storeName));
    request.onsuccess = () => { value = request.result; };
    tx.oncomplete = () => { db.close(); resolve(value); };
    tx.onerror = tx.onabort = () => { db.close(); reject(new Error('Не удалось сохранить или прочитать данные просмотрщика.')); };
  });
}

function validateDevice(device) {
  if (device?.version !== 1 || typeof device.id !== 'string') throw new Error('Ключ устройства повреждён. Не удаляйте приложение; обратитесь к настройке устройства.');
  for (const [pairName, algorithm, usage] of [['encryption','RSA-OAEP','decrypt'],['signing','ECDSA','sign']]) {
    const pair = device[pairName];
    if (pair?.privateKey?.type !== 'private' || pair.privateKey.extractable !== false || pair.privateKey.algorithm.name !== algorithm || !pair.privateKey.usages.includes(usage) || pair.publicKey?.type !== 'public') {
      throw new Error('Ключ устройства повреждён. Автоматическая замена ключа не выполнена.');
    }
  }
  return device;
}

export async function readDevice() {
  // Preserve this installation’s schema and key. Updates on the same origin/path never rotate keys.
  const db = await openDB('pso-viewer-demo-v1', 1, database => database.createObjectStore('keys'));
  const existing = await new Promise((resolve, reject) => {
    const request = db.transaction('keys').objectStore('keys').get('device');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('Не удалось прочитать ключ устройства.'));
  });
  if (existing) { db.close(); return validateDevice(existing); }
  const candidate = await makeDevice();
  const chosen = await new Promise((resolve, reject) => {
    const tx = db.transaction('keys', 'readwrite');
    const store = tx.objectStore('keys');
    let value = candidate;
    const request = store.get('device');
    request.onsuccess = () => { if (request.result) value = request.result; else store.put(candidate, 'device'); };
    tx.oncomplete = () => resolve(value);
    tx.onerror = tx.onabort = () => reject(new Error('Не удалось сохранить ключ на этом устройстве.'));
  });
  db.close();
  return validateDevice(chosen);
}

function contactsDB() {
  return openDB('pso-viewer-contacts-v1', 1, database => {
    database.createObjectStore('contacts', {keyPath:'id'});
    database.createObjectStore('settings');
  });
}

export async function loadContacts() {
  const entries = await transaction(await contactsDB(), 'contacts', 'readonly', store => store.getAll());
  const contacts = [];
  for (const entry of entries) {
    if (entry.verified !== true || !Number.isSafeInteger(entry.verifiedAt)) throw new Error('Запись контакта повреждена. Проверьте контакты врачей.');
    const contact = await importPublicCard(entry.card);
    if (contact.id !== entry.id) throw new Error('Ключ сохранённого контакта изменился. Необходима повторная проверка.');
    contacts.push({...contact, verified:true});
  }
  return contacts.sort((a,b) => a.name.localeCompare(b.name, 'ru'));
}

export async function saveContact(contact) {
  if (contact.verified !== true) throw new Error('Сначала сверьте отпечаток ключа с коллегой.');
  const parsed = await importPublicCard(contact.card);
  if (parsed.id !== contact.id) throw new Error('Карточка контакта изменилась.');
  await transaction(await contactsDB(), 'contacts', 'readwrite', store => store.put({id:parsed.id, card:parsed.card, verified:true, verifiedAt:Date.now()}));
}

export async function deleteContact(id) {
  await transaction(await contactsDB(), 'contacts', 'readwrite', store => store.delete(id));
}

export async function getMyName() {
  return (await transaction(await contactsDB(), 'settings', 'readonly', store => store.get('name'))) || '';
}

export async function setMyName(name) {
  await transaction(await contactsDB(), 'settings', 'readwrite', store => store.put(name, 'name'));
}
