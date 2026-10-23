// Demonstration only: real patient payloads are deliberately rejected.
const DOMAIN = 'PSO-VIEWER-DEMO-v1';
const PREFIX = 'PSO-DEMO1.';
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', {fatal: true});
const MAX_AGE = 10 * 60 * 1000;

export function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unbase64url(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > 2000) throw new Error('Некорректный код.');
  const s = value.replace(/-/g, '+').replace(/_/g, '/');
  const out = Uint8Array.from(atob(s + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
  if (base64url(out) !== value || (length && out.length !== length)) throw new Error('Некорректный код.');
  return out;
}
export async function makeDevice() {
  const encryption = await crypto.subtle.generateKey({name:'RSA-OAEP', modulusLength:3072, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256'}, false, ['encrypt','decrypt']);
  const signing = await crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, false, ['sign','verify']);
  const spki = await crypto.subtle.exportKey('spki', encryption.publicKey);
  const id = base64url(await crypto.subtle.digest('SHA-256', spki));
  return {version:1, id, encryption, signing};
}
export function demoPayload(device, time = Date.now()) {
  return {demo:true, code:'ПРИМЕР-01', surname:'Иванов', department:'ОРИТ', device:device.id, issued:time, expires:time + MAX_AGE};
}
function signedBytes(k, c) { return enc.encode(DOMAIN + '\u0000' + k + '\u0000' + c); }
export async function sealDemo(device, payload = demoPayload(device)) {
  const bytes = enc.encode(JSON.stringify(payload));
  if (bytes.length > 318) throw new Error('Тестовый пакет превышает допустимый размер.');
  const encrypted = await crypto.subtle.encrypt({name:'RSA-OAEP', label:enc.encode(DOMAIN)}, device.encryption.publicKey, bytes);
  const c = base64url(encrypted);
  const signature = await crypto.subtle.sign({name:'ECDSA', hash:'SHA-256'}, device.signing.privateKey, signedBytes(device.id, c));
  return PREFIX + base64url(enc.encode(JSON.stringify({v:1, k:device.id, c, s:base64url(signature)})));
}
export async function openDemo(device, token, time = Date.now()) {
  if (typeof token !== 'string' || !token.startsWith(PREFIX) || token.length > 1800) throw new Error('Это не код тестового просмотрщика.');
  let p;
  try { p = JSON.parse(dec.decode(unbase64url(token.slice(PREFIX.length)))); }
  catch { throw new Error('Код повреждён или скопирован не полностью.'); }
  if (!p || Object.keys(p).sort().join(',') !== 'c,k,s,v' || p.v !== 1 || typeof p.k !== 'string') throw new Error('Неизвестный формат кода.');
  if (p.k !== device.id) throw new Error('Этот код создан для другого браузера или приложения. Откройте его там, где создавали пример, либо вставьте ссылку в подключённый просмотрщик.');
  let data;
  try {
    const ciphertext = unbase64url(p.c, 384);
    const sig = unbase64url(p.s, 64);
    if (!(await crypto.subtle.verify({name:'ECDSA', hash:'SHA-256'}, device.signing.publicKey, sig, signedBytes(p.k, p.c)))) throw new Error('signature');
    const plaintext = await crypto.subtle.decrypt({name:'RSA-OAEP', label:enc.encode(DOMAIN)}, device.encryption.privateKey, ciphertext);
    try { data = JSON.parse(dec.decode(plaintext)); } finally { new Uint8Array(plaintext).fill(0); }
  } catch { throw new Error('Не удалось проверить или расшифровать код.'); }
  // Hard gate: this hosted prototype never displays real patient content.
  if (!data || Object.keys(data).sort().join(',') !== 'code,demo,department,device,expires,issued,surname' || data.demo !== true || data.surname !== 'Иванов' || data.department !== 'ОРИТ' || data.code !== 'ПРИМЕР-01' || data.device !== device.id) {
    throw new Error('Прототип принимает только вымышленный пример «Иванов». Рабочие данные не подключены.');
  }
  if (!Number.isSafeInteger(data.issued) || !Number.isSafeInteger(data.expires) || data.expires <= data.issued || data.expires - data.issued > MAX_AGE || data.issued > time + 30000 || data.expires <= time) throw new Error('Срок тестового кода истёк. Создайте новый пример.');
  return data;
}
export function tokenFromInput(input, baseURL) {
  const value = String(input).trim();
  if (value.length > 2500) throw new Error('Слишком длинный код.');
  if (value.startsWith(PREFIX)) return value;
  let url;
  try { url = new URL(value); } catch { throw new Error('Вставьте тестовый код или полную ссылку на просмотрщик.'); }
  const base = new URL('./', baseURL);
  if (url.origin !== base.origin || ![base.pathname, base.pathname + 'index.html'].includes(url.pathname) || url.username || url.password || url.search || !url.hash.startsWith('#pso=')) throw new Error('Эта ссылка не относится к данному просмотрщику.');
  return decodeURIComponent(url.hash.slice(5));
}
export function linkForToken(token, baseURL) {
  const url = new URL('./', baseURL);
  if (!['https:', 'http:'].includes(url.protocol)) throw new Error('Нужен адрес просмотрщика по HTTPS.');
  url.hash = 'pso=' + encodeURIComponent(token);
  return url.href;
}
