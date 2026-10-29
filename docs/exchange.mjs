// Local recipient-specific encryption. Public cards do not establish identity:
// callers must mark a contact verified only after an independent fingerprint check.
const DOMAIN = 'PSO-SURNAME-LINK-v1';
const CARD_DOMAIN = 'PSO-CONTACT-v1';
const PREFIX = 'PSO1';
const CARD_PREFIX = 'PSO-CARD1.';
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', {fatal:true});
const MAX_TTL = 1440 * 60000;
const CONTROL = /[\p{Cc}\p{Cf}]/u;

function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64(value, expected, max = 5000) {
  if (typeof value !== 'string' || !value || value.length > max || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Некорректный формат кода.');
  const base = value.replace(/-/g,'+').replace(/_/g,'/');
  const result = Uint8Array.from(atob(base + '='.repeat((4-base.length%4)%4)), c=>c.charCodeAt(0));
  if (b64(result) !== value || (expected && result.length !== expected)) throw new Error('Некорректный формат кода.');
  return result;
}
function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;
}
function label(value) {
  if (typeof value !== 'string' || CONTROL.test(value)) throw new Error('В имени контакта не должно быть управляющих символов или переносов строк.');
  const text = value.normalize('NFC').trim();
  if (!text || [...text].length > 60) throw new Error('Имя контакта должно содержать от 1 до 60 символов.');
  return text;
}
function surnameValue(value) {
  if (typeof value !== 'string' || CONTROL.test(value)) throw new Error('Введите только фамилию, без переносов строк и управляющих символов.');
  const name = value.normalize('NFC').trim().replace(/ +/g,' ').replace(/[\u2010\u2011]/g,'-');
  const shape = /^[\p{L}][\p{L}\p{M}]*(?:[ '\u2019\u02BC-][\p{L}][\p{L}\p{M}]*)*$/u;
  if (!name || [...name].length > 80 || !shape.test(name) || [...name].some(c=>/\p{L}/u.test(c) && !/[\p{Script=Latin}\p{Script=Cyrillic}]/u.test(c))) {
    throw new Error('Фамилия: до 80 букв кириллицы или латиницы; допустимы пробел, дефис и апостроф.');
  }
  return name;
}
function validatePublicKeys(encryption, signing) {
  const rsa = encryption?.algorithm, ec = signing?.algorithm;
  if (encryption?.type !== 'public' || rsa?.name !== 'RSA-OAEP' || rsa.modulusLength !== 3072 || rsa.hash?.name !== 'SHA-256' || !encryption.usages.includes('encrypt') || !rsa.publicExponent || Array.from(rsa.publicExponent).join(',') !== '1,0,1') throw new Error('Открытый ключ шифрования должен быть RSA-OAEP 3072/SHA-256.');
  if (signing?.type !== 'public' || ec?.name !== 'ECDSA' || ec.namedCurve !== 'P-256' || !signing.usages.includes('verify')) throw new Error('Открытый ключ подписи должен быть ECDSA P-256.');
}
async function publicIdentity(encryption, signing) {
  validatePublicKeys(encryption, signing);
  const e = b64(await crypto.subtle.exportKey('spki', encryption));
  const s = b64(await crypto.subtle.exportKey('spki', signing));
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(CARD_DOMAIN + '\0' + e + '\0' + s)));
  const hex = Array.from(digest, n=>n.toString(16).padStart(2,'0')).join('').toUpperCase();
  return {id:b64(digest), fingerprint:hex.match(/.{4}/g).join(' '), e, s};
}
export async function deviceIdentity(device) {
  const {id,fingerprint} = await publicIdentity(device?.encryption?.publicKey, device?.signing?.publicKey);
  return {id,fingerprint};
}
export async function exportPublicCard(device, name) {
  const n = label(name);
  const {e,s} = await publicIdentity(device?.encryption?.publicKey, device?.signing?.publicKey);
  return CARD_PREFIX + b64(enc.encode(JSON.stringify({v:1,n,e,s})));
}
export async function importPublicCard(card) {
  if (typeof card !== 'string' || card.length > 5000) throw new Error('Карточка контакта слишком длинная или имеет неверный формат.');
  const input = card.trim();
  if (!input.startsWith(CARD_PREFIX)) throw new Error('Вставьте открытую карточку контакта ПСО.');
  let data, encryptionPublicKey, signingPublicKey;
  try {
    const json = dec.decode(unb64(input.slice(CARD_PREFIX.length)));
    data = JSON.parse(json);
    if (JSON.stringify(data) !== json || !exact(data,'e,n,s,v') || data.v !== 1 || label(data.n) !== data.n) throw new Error('schema');
    const encryptionBytes = unb64(data.e,0,1000), signingBytes = unb64(data.s,0,300);
    encryptionPublicKey = await crypto.subtle.importKey('spki', encryptionBytes, {name:'RSA-OAEP', hash:'SHA-256'}, true, ['encrypt']);
    signingPublicKey = await crypto.subtle.importKey('spki', signingBytes, {name:'ECDSA', namedCurve:'P-256'}, true, ['verify']);
    validatePublicKeys(encryptionPublicKey, signingPublicKey);
    const identity = await publicIdentity(encryptionPublicKey, signingPublicKey);
    if (identity.e !== data.e || identity.s !== data.s) throw new Error('canonical keys');
    return {id:identity.id,name:data.n,fingerprint:identity.fingerprint,encryptionPublicKey,signingPublicKey,card:input};
  } catch { throw new Error('Карточка повреждена или содержит неподдерживаемые открытые ключи.'); }
}
function signedBytes(recipient, sender, ciphertext) {
  return enc.encode(DOMAIN + '\0' + PREFIX + '.' + recipient + '.' + sender + '.' + ciphertext);
}
async function verifiedContact(contact) {
  if (contact?.verified !== true) throw new Error('Сначала добавьте контакт и подтвердите его отпечаток.');
  const identity = await publicIdentity(contact.encryptionPublicKey, contact.signingPublicKey);
  if (contact.id !== identity.id || (contact.fingerprint && contact.fingerprint !== identity.fingerprint)) throw new Error('Ключи контакта изменились. Повторно сверьте отпечаток.');
  return identity;
}
export async function sealSurname(device, recipient, surname, {department='',ttlMinutes=1440}={}) {
  const name = surnameValue(surname);
  if (!['','ПСО','ОРИТ'].includes(department)) throw new Error('Неизвестное отделение.');
  if (!Number.isSafeInteger(ttlMinutes) || ttlMinutes < 1 || ttlMinutes > 1440) throw new Error('Срок ссылки должен быть от 1 до 1440 минут.');
  const recipientIdentity = await verifiedContact(recipient);
  const senderIdentity = await deviceIdentity(device);
  const issued = Date.now();
  const payload = {n:name,d:department,j:b64(crypto.getRandomValues(new Uint8Array(12))),i:issued,x:issued+ttlMinutes*60000};
  const bytes = enc.encode(JSON.stringify(payload));
  if (bytes.length > 318) throw new Error('Фамилия превышает допустимый размер зашифрованной записи.');
  let encrypted;
  try { encrypted = await crypto.subtle.encrypt({name:'RSA-OAEP',label:enc.encode(DOMAIN)},recipient.encryptionPublicKey,bytes); }
  finally { bytes.fill(0); }
  const c = b64(encrypted);
  const signature = await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},device.signing.privateKey,signedBytes(recipientIdentity.id,senderIdentity.id,c));
  return [PREFIX,recipientIdentity.id,senderIdentity.id,c,b64(signature)].join('.');
}
export async function openSurname(device, token, contactsArray, now=Date.now()) {
  if (typeof token !== 'string' || token.length > 900 || !Number.isSafeInteger(now)) throw new Error('Некорректный код ссылки.');
  const parts = token.split('.');
  if (parts.length !== 5 || parts[0] !== PREFIX) throw new Error('Неизвестный формат ссылки.');
  const [,recipientID,senderID,c,s] = parts;
  let ciphertext, signature;
  try { unb64(recipientID,32); unb64(senderID,32); ciphertext=unb64(c,384); signature=unb64(s,64); }
  catch { throw new Error('Код повреждён или скопирован не полностью.'); }
  const ownIdentity = await deviceIdentity(device);
  if (recipientID !== ownIdentity.id) throw new Error('Ссылка предназначена другому получателю или другому браузеру. Откройте её в подключённом просмотрщике.');
  let senderKey, senderName;
  if (senderID === ownIdentity.id) { senderKey=device.signing.publicKey; senderName='Вы'; }
  else {
    const contact = Array.isArray(contactsArray) ? contactsArray.find(c=>c?.id===senderID && c.verified===true) : null;
    if (!contact) throw new Error('Отправитель не подтверждён. Добавьте его открытую карточку и сверьте отпечаток.');
    await verifiedContact(contact);
    senderKey=contact.signingPublicKey;
    senderName=label(contact.name);
  }
  let data;
  try {
    if (!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},senderKey,signature,signedBytes(recipientID,senderID,c))) throw new Error('signature');
    const plaintext = await crypto.subtle.decrypt({name:'RSA-OAEP',label:enc.encode(DOMAIN)},device.encryption.privateKey,ciphertext);
    try { data=JSON.parse(dec.decode(plaintext)); } finally { new Uint8Array(plaintext).fill(0); }
  } catch { throw new Error('Не удалось проверить подпись или расшифровать ссылку.'); }
  const bound=exact(data,'d,g,i,j,n,x');
  if ((!bound&&!exact(data,'d,i,j,n,x')) || (bound&&!['cardiology','orit'].includes(data.g)) || !['','ПСО','ОРИТ'].includes(data.d) || surnameValue(data.n)!==data.n) throw new Error('Зашифрованная запись имеет неверный формат.');
  try { unb64(data.j,bound?16:12); } catch { throw new Error('Зашифрованная запись имеет неверный формат.'); }
  if (!Number.isSafeInteger(data.i) || data.i<=0 || !Number.isSafeInteger(data.x) || data.x <= data.i || data.x-data.i > (bound?2*MAX_TTL:MAX_TTL) || data.x-data.i < 60000 || data.i > now+30000 || data.x <= now) throw new Error('Срок ссылки истёк или время её создания некорректно.');
  return {surname:data.n,department:data.d,code:'ПСО-'+data.j,senderName,issued:data.i,expires:data.x,...(bound?{messageId:data.j,group:data.g}:{})};
}
