// Optional WebAuthn verification. Unlock tokens exist only in this page's memory.
// The server, not a visual overlay, checks the token before returning ciphertext.
import {exportPublicCard,deviceIdentity} from './exchange.mjs';
import {runApiRequest} from './api-queue.mjs';
const DOMAIN='PSO-TEAM-v1\0', enc=new TextEncoder();
const OPS=['status','enroll_begin','enroll_finish','unlock_begin','unlock_finish','reset'];
const b64=x=>btoa(String.fromCharCode(...new Uint8Array(x))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function bytes(s){if(typeof s!=='string'||!/^[A-Za-z0-9_-]+$/.test(s)||s.length>131072)throw new Error('Некорректный ответ защиты.');const t=s.replace(/-/g,'+').replace(/_/g,'/');return Uint8Array.from(atob(t+'='.repeat((4-t.length%4)%4)),c=>c.charCodeAt(0));}
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===k;
export async function deviceAuthEnvelope(device,op,data={},issued=Date.now()){
  if(!OPS.includes(op))throw new Error('Неизвестное действие защиты.');
  const value={v:1,op,issued,nonce:b64(crypto.getRandomValues(new Uint8Array(16))),card:await exportPublicCard(device,'Устройство'),data};
  return {...value,signature:b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},device.signing.privateKey,enc.encode(DOMAIN+JSON.stringify(value))))};
}
function serializeCredential(credential,registration){
  if(!credential||credential.type!=='public-key')throw new Error('Подтверждение отменено.');
  const r=credential.response;
  const response=registration?{clientDataJSON:b64(r.clientDataJSON),attestationObject:b64(r.attestationObject),transports:typeof r.getTransports==='function'?r.getTransports():[]}:
    {clientDataJSON:b64(r.clientDataJSON),authenticatorData:b64(r.authenticatorData),signature:b64(r.signature),userHandle:r.userHandle?b64(r.userHandle):undefined};
  return {id:credential.id,rawId:b64(credential.rawId),type:'public-key',response,clientExtensionResults:credential.getClientExtensionResults?.()||{},authenticatorAttachment:credential.authenticatorAttachment||undefined};
}
export class DeviceUnlockClient{
  constructor(endpoint,{fetch:fetcher=globalThis.fetch?.bind(globalThis),credentials=globalThis.navigator?.credentials,now=Date.now,timeout=15000}={}){
    const u=new URL(endpoint);if(u.protocol!=='https:'||u.username||u.password||u.hash||u.search)throw new Error('Неверный адрес защиты.');
    this.endpoint=u.href;this.fetcher=fetcher;this.credentials=credentials;this.now=now;this.timeout=timeout;this.session=null;this.epoch=0;this.prompt=null;
  }
  clear(){this.session=null;this.epoch++;this.prompt?.abort();this.prompt=null;}
  active(epoch){if(epoch!==this.epoch)throw new Error('Подтверждение прервано. Откройте запись снова.');}
  async request(device,op,data={}){
    const snapshot=JSON.parse(JSON.stringify(data));
    return runApiRequest(()=>this.requestOnce(device,op,snapshot));
  }
  async requestOnce(device,op,data){
    const envelope=await deviceAuthEnvelope(device,op,data,this.now());const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),this.timeout);
    try{
      const r=await this.fetcher(this.endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({envelope}),credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',signal:abort.signal});
      if(!r.ok){const e=new Error(({403:'Доступ к этому телефону закрыт.',409:'Защита уже подключена или запрос устарел. Повторите действие.',428:'Подтвердите вход на телефоне.',429:'Слишком много запросов. Повторите позже.'})[r.status]||'Сервис защиты недоступен. Повторите позже.');e.status=r.status;throw e;}
      if(!r.headers.get('content-type')?.startsWith('application/json'))throw new Error('Неверный ответ защиты.');
      const reader=r.body?.getReader();if(!reader)throw new Error('Ответ защиты не получен.');let count=0,text='';const decoder=new TextDecoder('utf-8',{fatal:true});
      try{for(;;){const {done,value}=await reader.read();if(done)break;count+=value.byteLength;if(count>131072){await reader.cancel();throw new Error('Ответ защиты слишком большой.');}text+=decoder.decode(value,{stream:true});}text+=decoder.decode();return JSON.parse(text);}finally{reader.releaseLock();}
    }catch(e){if(e.name==='AbortError'||e instanceof TypeError)throw new Error('Нет связи с сервисом защиты.');throw e;}finally{clearTimeout(timer);}
  }
  async status(device){const r=await this.request(device,'status');if(!exact(r,'enabled')||typeof r.enabled!=='boolean')throw new Error('Состояние защиты не подтверждено.');return r;}
  async remember(device,r,epoch){if(!exact(r,'expires,token')||typeof r.token!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(r.token)||!Number.isSafeInteger(r.expires)||r.expires<=this.now()||r.expires>this.now()+630000)throw new Error('Подтверждение входа не принято.');const id=(await deviceIdentity(device)).id;this.active(epoch);this.session={deviceId:id,token:r.token,expires:r.expires};return r.token;}
  async enroll(device){
    if(!this.credentials?.create)throw new Error('На этом устройстве подтверждение Face ID / кодом недоступно.');
    this.clear();const epoch=this.epoch;this.prompt=new AbortController();
    const r=await this.request(device,'enroll_begin');this.active(epoch);if(!exact(r,'options')||!r.options)throw new Error('Не удалось подготовить защиту.');
    const o=r.options,publicKey={...o,challenge:bytes(o.challenge),user:{...o.user,id:bytes(o.user.id)},excludeCredentials:(o.excludeCredentials||[]).map(c=>({...c,id:bytes(c.id)}))};
    let credential;try{credential=await this.credentials.create({publicKey,signal:this.prompt.signal});}catch{throw new Error('Подключение защиты отменено или недоступно на телефоне.');}this.active(epoch);
    return this.remember(device,await this.request(device,'enroll_finish',{credential:serializeCredential(credential,true)}),epoch);
  }
  async ensure(device){
    if(this.session?.deviceId===(await deviceIdentity(device)).id&&this.session.expires>this.now()+1000)return this.session.token;
    this.clear();const epoch=this.epoch;const state=await this.status(device);this.active(epoch);if(!state.enabled)return '';
    if(!this.credentials?.get)throw new Error('Откройте запись на телефоне с подключённой защитой.');
    const r=await this.request(device,'unlock_begin');this.active(epoch);if(!exact(r,'options')||!r.options)throw new Error('Не удалось подготовить вход.');this.prompt=new AbortController();
    const o=r.options,publicKey={...o,challenge:bytes(o.challenge),allowCredentials:(o.allowCredentials||[]).map(c=>({...c,id:bytes(c.id)}))};
    let credential;try{credential=await this.credentials.get({publicKey,signal:this.prompt.signal});}catch{throw new Error('Вход не подтверждён. Попробуйте Face ID или код телефона.');}this.active(epoch);
    return this.remember(device,await this.request(device,'unlock_finish',{credential:serializeCredential(credential,false)}),epoch);
  }
  async reset(device,targetId){const token=await this.ensure(device),r=await this.request(device,'reset',{targetId,unlockToken:token});if(!exact(r,'reset')||r.reset!==true)throw new Error('Сброс защиты не подтверждён.');if(targetId===(await deviceIdentity(device)).id)this.clear();return r;}
}
