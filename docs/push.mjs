// Device-authenticated notification requests. No patient plaintext or private key
// is sent here. The public card uses a fixed label instead of the doctor's name.
import {exportPublicCard, deviceIdentity} from './exchange.mjs';
import {runApiRequest} from './api-queue.mjs';
const DOMAIN = 'PSO-PUSH-v1\0';
const enc = new TextEncoder();
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;
}
export function pushKeyBytes(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{87}$/.test(value)) throw new Error('Сервис уведомлений вернул неверный ключ.');
  const bytes = Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')+'='), c=>c.charCodeAt(0));
  if (bytes.length !== 65 || bytes[0] !== 4 || b64(bytes) !== value) throw new Error('Сервис уведомлений вернул неверный ключ.');
  return bytes;
}
export async function pushEnvelope(device, op, data, now=Date.now()) {
  if (!['register','unregister','status','test','notify'].includes(op) || !Number.isSafeInteger(now)) throw new Error('Неверный запрос уведомлений.');
  const card = await exportPublicCard(device,'Устройство');
  const unsigned = {v:1,op,issued:now,nonce:b64(crypto.getRandomValues(new Uint8Array(16))),card,data};
  const signature = b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},device.signing.privateKey,enc.encode(DOMAIN+JSON.stringify(unsigned))));
  return {...unsigned,signature};
}
export class PushClient {
  constructor(endpoint, {fetch:fetcher=globalThis.fetch.bind(globalThis),timeout=12000,now=Date.now}={}) {
    const url = new URL(endpoint);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) throw new Error('Неверный адрес сервиса уведомлений.');
    this.endpoint=url.href; this.fetcher=fetcher; this.timeout=timeout; this.now=now;
  }
  async request(body) {
    return runApiRequest(async()=>this.requestOnce(typeof body==='function'?await body():body));
  }
  async requestOnce(body) {
    const controller=new AbortController(), timer=setTimeout(()=>controller.abort(),this.timeout);
    try {
      const response=await this.fetcher(this.endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',redirect:'error',signal:controller.signal});
      if (response.status===429) throw new Error('Слишком много запросов уведомлений. Повторите позже.');
      if (response.status===403) throw new Error('Сервис не подтвердил запрос уведомлений. Откройте обновлённый просмотрщик.');
      if (!response.ok || !response.headers.get('content-type')?.startsWith('application/json')) throw new Error('Сервис уведомлений недоступен.');
      const reader=response.body?.getReader();
      if (!reader) throw new Error('Не удалось проверить ответ сервиса уведомлений.');
      let length=0,text=''; const decoder=new TextDecoder('utf-8',{fatal:true});
      try {
        for (;;) {
          const {done,value}=await reader.read(); if(done)break;
          length+=value.byteLength;
          if(length>2048){await reader.cancel();throw new Error('Не удалось проверить ответ сервиса уведомлений.');}
          text+=decoder.decode(value,{stream:true});
        }
        text+=decoder.decode(); return JSON.parse(text);
      } finally {reader.releaseLock();}
    } catch(error) {
      if(error.name==='AbortError'||error instanceof TypeError||error instanceof SyntaxError)throw new Error('Не удалось связаться с сервисом уведомлений. Проверьте интернет.');
      throw error;
    } finally {clearTimeout(timer);}
  }
  async config() {
    const result=await this.request({op:'config'});
    if(!exact(result,'publicKey,v')||result.v!==1)throw new Error('Не удалось проверить настройки уведомлений.');
    pushKeyBytes(result.publicKey); return result.publicKey;
  }
  async signed(device,op,data={}) {
    const snapshot=JSON.parse(JSON.stringify(data));
    const result=await this.request(async()=>({envelope:await pushEnvelope(device,op,snapshot,this.now())}));
    const statuses=['register','unregister','status'].includes(op)?['enabled','disabled']:['accepted','unavailable','already','failed','gone'];
    if(!exact(result,'status')||!statuses.includes(result.status))throw new Error('Сервис не подтвердил уведомление.');
    return result.status;
  }
  async register(device,subscription,contacts=[]) {
    const own=(await deviceIdentity(device)).id;
    const senders=[...new Set([own,...contacts.filter(c=>c?.verified===true).map(c=>c.id)])].sort();
    if(senders.length>100)throw new Error('Слишком много контактов для уведомлений.');
    return this.signed(device,'register',{subscription:typeof subscription.toJSON==='function'?subscription.toJSON():subscription,senders});
  }
  unregister(device){return this.signed(device,'unregister');}
  status(device){return this.signed(device,'status');}
  test(device){return this.signed(device,'test');}
  notify(device,id){
    if(typeof id!=='string'||!/^[A-Za-z0-9_-]{21}[AQgw]$/.test(id))throw new Error('Не удалось проверить короткую ссылку для уведомления.');
    return this.signed(device,'notify',{id});
  }
}
