// A short link contains only a random lookup capability. The existing PSO1
// ciphertext and signatures remain unchanged; this module never takes a surname.
const DOMAIN = 'PSO-SHORT-LINK-v1\0';
const MAX_TTL = 86400000;
const enc = new TextEncoder();
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function bytes(value, size) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > 1000) throw new Error('Некорректная ссылка.');
  const plain = value.replace(/-/g,'+').replace(/_/g,'/');
  const result = Uint8Array.from(atob(plain + '='.repeat((4-plain.length%4)%4)), c => c.charCodeAt(0));
  if (result.length !== size || b64(result) !== value) throw new Error('Некорректная ссылка.');
  return result;
}
function tokenParts(token) {
  if (typeof token !== 'string' || token.length > 900) throw new Error('Некорректная зашифрованная запись.');
  const parts = token.split('.');
  if (parts.length !== 5 || parts[0] !== 'PSO1') throw new Error('Некорректная зашифрованная запись.');
  [32,32,384,64].forEach((size,index) => bytes(parts[index+1],size));
  return parts;
}
function baseURL(base) {
  const url = new URL('./', base);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Нужна HTTPS-ссылка просмотрщика.');
  return url;
}
export function shortLinkFor(id, base) {
  bytes(id,16);
  const url = baseURL(base); url.hash = 'r=' + id;
  return url.href;
}
export function shortIDFromInput(input, base) {
  let url;
  let value = String(input).trim();
  const lines = value.split(/\r?\n/);
  if (lines.length === 2 && ['Новый пациент','Новый пациент ОРИТ','Проверочная история'].includes(lines[0])) value = lines[1];
  try { url = new URL(value); } catch { return null; }
  if (!url.hash.startsWith('#r=')) return null;
  const expected = baseURL(base);
  if (url.origin !== expected.origin || url.username || url.password || url.search ||
      ![expected.pathname,expected.pathname+'index.html'].includes(url.pathname)) throw new Error('Эта ссылка не относится к данному просмотрщику.');
  const id = url.hash.slice(3); bytes(id,16); return id;
}
function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;
}
export async function createEnvelope(device, token, ttlMinutes, now=Date.now()) {
  tokenParts(token);
  if (!Number.isSafeInteger(ttlMinutes) || ttlMinutes < 1 || ttlMinutes > 1440 || !Number.isSafeInteger(now)) throw new Error('Некорректный срок ссылки.');
  const id = b64(crypto.getRandomValues(new Uint8Array(16)));
  const unsigned = {v:1,id,token,issued:now,expires:now+ttlMinutes*60000};
  // The broker also verifies the sender and the original PSO1 signature.
  const signature = b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},device.signing.privateKey,enc.encode(DOMAIN+JSON.stringify(unsigned))));
  return {...unsigned,signature};
}
export class ShortLinkClient {
  constructor(endpoint, {fetch:fetcher=globalThis.fetch, timeout=12000, now=Date.now}={}) {
    const url = new URL(endpoint);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) throw new Error('Некорректный адрес сервиса коротких ссылок.');
    this.endpoint = url.href; this.fetcher = fetcher; this.timeout = timeout; this.now = now;
  }
  async request(body) {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(),this.timeout);
    try {
      const response = await this.fetcher(this.endpoint, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',redirect:'error',signal:controller.signal});
      if (response.status === 403) throw new Error(body.op === 'create' ? 'Этот телефон ещё не подключён к созданию коротких ссылок. Передайте администратору свою открытую карточку.' : 'Сервис отклонил запрос. Откройте обновлённую версию просмотрщика.');
      if (response.status === 404) throw new Error('Ссылка не найдена или срок её действия истёк.');
      if (response.status === 429) throw new Error('Лимит создания ссылок достигнут. Попробуйте позже.');
      if (!response.ok || !response.headers.get('content-type')?.startsWith('application/json')) throw new Error('Сервис коротких ссылок недоступен. Попробуйте позже.');
      const reader = response.body?.getReader();
      if (!reader) throw new Error('Некорректный ответ сервиса коротких ссылок.');
      let length=0, text=''; const decoder=new TextDecoder('utf-8',{fatal:true});
      try {
        for (;;) {
          const {done,value}=await reader.read(); if (done) break;
          length+=value.byteLength;
          if (length>4096) { await reader.cancel(); throw new Error('Некорректный ответ сервиса коротких ссылок.'); }
          text+=decoder.decode(value,{stream:true});
        }
        text+=decoder.decode(); return JSON.parse(text);
      } finally { reader.releaseLock(); }
    } catch(error) {
      if (error.name === 'AbortError' || error instanceof TypeError || error instanceof SyntaxError) throw new Error('Не удалось связаться с сервисом коротких ссылок. Проверьте интернет и повторите.');
      throw error;
    } finally { clearTimeout(timer); }
  }
  async create(device, token, ttlMinutes, base) {
    const envelope = await createEnvelope(device,token,ttlMinutes,this.now());
    const result = await this.request({op:'create',envelope});
    if (!exact(result,'expires,id') || result.id !== envelope.id || result.expires !== envelope.expires || result.expires <= this.now()) throw new Error('Сервис не подтвердил создание ссылки. Попробуйте ещё раз.');
    return shortLinkFor(result.id,base);
  }
  async resolve(input, base) {
    const id = shortIDFromInput(input,base);
    if (!id) throw new Error('Вставьте короткую ссылку целиком.');
    const result = await this.request({op:'resolve',id});
    if (!exact(result,'expires,token') || !Number.isSafeInteger(result.expires) || result.expires<=this.now() || result.expires>this.now()+MAX_TTL+30000) throw new Error('Ссылка не найдена или срок её действия истёк.');
    tokenParts(result.token); return result.token;
  }
}
