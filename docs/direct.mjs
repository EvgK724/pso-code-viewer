// Direct delivery: signed requests, recipient-only inbox, encrypted local retries.
import {exportPublicCard, importPublicCard} from './exchange.mjs';
import {validateMessagePayload,inspectMessageToken} from './messages.mjs';
const DOMAIN='PSO-TEAM-v1\0', enc=new TextEncoder();
const ID=/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/, LINK=/^[A-Za-z0-9_-]{21}[AQgw]$/;
const OPS=['create','inbox','outbox','open','ack','retry','admin_members','admin_update','admin_replace','directory','admin_certify'];
const ROLES=['admin','neurologist','intensivist','cardiologist','bot'];
const b64=x=>btoa(String.fromCharCode(...new Uint8Array(x))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===k;
const label=v=>typeof v==='string'&&v.trim()===v&&v.length>0&&[...v].length<=60&&!/[\p{Cc}\p{Cf}]/u.test(v);
export function newMessageID(){return b64(crypto.getRandomValues(new Uint8Array(16)));}
export function directIDFromInput(input,base){
  let u;try{u=new URL(String(input).trim(),base);}catch{return null;}
  const own=new URL('./',base),id=u.hash.startsWith('#m=')?u.hash.slice(3):'';
  return u.origin===own.origin&&[own.pathname,own.pathname+'index.html'].includes(u.pathname)&&!u.search&&!u.username&&!u.password&&LINK.test(id)?id:null;
}
export async function directEnvelope(device,op,data,issued=Date.now()){
  if(!OPS.includes(op)||!Number.isSafeInteger(issued))throw new Error('Неизвестная операция сообщений.');
  const card=await exportPublicCard(device,'Устройство'), unsigned={v:1,op,issued,nonce:newMessageID(),card,data};
  const signature=b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},device.signing.privateKey,enc.encode(DOMAIN+JSON.stringify(unsigned))));
  return {...unsigned,signature};
}
export class DirectError extends Error {constructor(message,status,code=''){super(message);this.status=status;this.code=code;}}
export class DirectClient {
  constructor(endpoint,{fetch:fetcher=globalThis.fetch.bind(globalThis),now=Date.now,timeout=25000}={}){
    const u=new URL(endpoint);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw new Error('Неверный адрес сообщений.');
    this.endpoint=u.href;this.fetcher=fetcher;this.now=now;this.timeout=timeout;
  }
  async request(device,op,data={}){
    const envelope=await directEnvelope(device,op,data,this.now()),controller=new AbortController(),timer=setTimeout(()=>controller.abort(),this.timeout);
    try{
      const headers={'Content-Type':'application/json'};
      const r=await this.fetcher(this.endpoint,{method:'POST',headers,body:JSON.stringify({envelope}),credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',signal:controller.signal});
      if(!r.ok){let code='';try{const t=await r.text();if(t.length<2048)code=JSON.parse(t).error||'';}catch{}
        const messages={401:'Подтвердите доступ на этом телефоне.',428:'Подтвердите Face ID или код телефона.',403:'Доступ отключён или действие недоступно для вашей роли.',404:'Сообщение недоступно или срок его хранения истёк.',409:'Состав получателей изменился. Обновите команду и подготовьте сообщение заново.',413:'Фото слишком большое. Выберите снимок меньшего размера.',429:'Слишком много запросов. Повторите позже.'};
        throw new DirectError(messages[r.status]||'Нет подтверждения сервиса. Повторите действие позже.',r.status,code);
      }
      if(!r.headers.get('content-type')?.startsWith('application/json'))throw new Error('Неверный ответ сервиса.');
      const reader=r.body?.getReader();if(!reader)throw new Error('Нет ответа сервиса.');
      let total=0,text='';const decoder=new TextDecoder('utf-8',{fatal:true});
      try{for(;;){const{done,value}=await reader.read();if(done)break;total+=value.byteLength;if(total>3000000){await reader.cancel();throw new Error('Ответ слишком большой.');}text+=decoder.decode(value,{stream:true});}text+=decoder.decode();return JSON.parse(text);}finally{reader.releaseLock();}
    }catch(e){if(e.name==='AbortError'||e instanceof TypeError||e instanceof SyntaxError)throw new DirectError('Нет связи с сервисом. Повторите после подключения.',0);throw e;}finally{clearTimeout(timer);}
  }
  async list(device,box='inbox',cursor=null){
    if(!['inbox','outbox'].includes(box))throw new Error('Неизвестный список.');
    const r=await this.request(device,box,{cursor});
    if(!exact(r,'items,next')||!Array.isArray(r.items)||r.items.length>100||!(r.next===null||exact(r.next,'id,issued')&&LINK.test(r.next.id)&&Number.isSafeInteger(r.next.issued)))throw new Error('Не удалось проверить список сообщений.');
    const ids=new Set();for(const m of r.items){if(!exact(m,'expires,group,id,issued,kind,openedAt,openedCount,recipientCount,senderId,senderName')||!LINK.test(m.id)||ids.has(m.id)||!ID.test(m.senderId)||!label(m.senderName)||!['cardiology','orit'].includes(m.group)||!['admission','review'].includes(m.kind)||!Number.isSafeInteger(m.issued)||!Number.isSafeInteger(m.expires)||m.expires<=m.issued||!(m.openedAt===null||Number.isSafeInteger(m.openedAt))||!Number.isInteger(m.recipientCount)||m.recipientCount<0||m.recipientCount>25||!Number.isInteger(m.openedCount)||m.openedCount<0||m.openedCount>m.recipientCount)throw new Error('Не удалось проверить сообщение.');ids.add(m.id);}
    return r;
  }
  async open(device,id,{unlockToken=''}={}){
    if(!LINK.test(id))throw new Error('Неверный код сообщения.');
    const r=await this.request(device,'open',unlockToken?{id,unlockToken}:{id});
    if(!exact(r,'meta,payload,senderApprovalProof,senderCard,senderName,senderRole,token')||!exact(r.meta,'expires,group,id,issued,kind')||r.meta.id!==id||!label(r.senderName)||!ROLES.includes(r.senderRole)||typeof r.token!=='string'||r.token.length>1600||!Number.isSafeInteger(r.meta.issued)||r.meta.issued<=0||r.meta.issued>this.now()+30000||!Number.isSafeInteger(r.meta.expires)||r.meta.expires<=this.now()||r.meta.expires<=r.meta.issued||r.meta.expires-r.meta.issued>86400000||!['admission','review'].includes(r.meta.kind)||!['cardiology','orit'].includes(r.meta.group))throw new Error('Не удалось проверить сообщение.');
    const sender=await importPublicCard(r.senderCard);if(r.token.split('.')[2]!==sender.id)throw new Error('Подпись отправителя не соответствует записи.');
    return {...r,sender:{...sender,name:r.senderName,verified:true}};
  }
  async create(device,data){const r=await this.request(device,'create',data);if(!exact(r,'expires,id,push')||r.id!==data.id||r.expires!==data.expires||!['accepted','partial','queued'].includes(r.push))throw new Error('Сервис не подтвердил сохранение. Повторите отправку из очереди.');return r;}
  async ack(device,id){const r=await this.request(device,'ack',{id});if(!exact(r,'openedAt')||!Number.isSafeInteger(r.openedAt))throw new Error('Не подтверждено открытие.');return r;}
  async retry(device){return this.request(device,'retry',{});}
  async members(device){const r=await this.request(device,'admin_members',{});if(!exact(r,'members')||!Array.isArray(r.members)||r.members.length>500)throw new Error('Не удалось получить команду.');
    const list=[];for(const m of r.members){if(!ID.test(m.id)||!label(m.name)||!ROLES.includes(m.role)||!['active','pending','revoked'].includes(m.state)||typeof m.card!=='string')throw new Error('Не удалось проверить участника.');const card=await importPublicCard(m.card);if(card.id!==m.id)throw new Error('Ключ участника изменился.');list.push({...card,...m,verified:m.state==='active'});}return list;}
  async update(device,member){const data={id:member.id,name:member.name,role:member.role,state:member.state};if(member.approvalProof)data.approvalProof=member.approvalProof;return this.request(device,'admin_update',data);}
  async replace(device,oldId,newId,approvalProof){return this.request(device,'admin_replace',{oldId,newId,approvalProof});}
  async directory(device){const r=await this.request(device,'directory',{});if(!exact(r,'members')||!Array.isArray(r.members)||r.members.length>100)throw new Error('Не удалось проверить состав команды.');return r.members;}
  async certify(device,id,approvalProof){return this.request(device,'admin_certify',{id,approvalProof});}
}

// Only encrypted bodies and delivery metadata are persisted; never names/photos.
const DB='pso-direct-retries-'+encodeURIComponent(new URL('./',import.meta.url).pathname);
function db(){return new Promise((resolve,reject)=>{const r=indexedDB.open(DB,1);r.onupgradeneeded=()=>r.result.createObjectStore('outbox',{keyPath:'id'});r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(new Error('Не удалось сохранить зашифрованную очередь на телефоне.'));});}
async function transaction(mode,action){const database=await db();try{return await new Promise((resolve,reject)=>{const t=database.transaction('outbox',mode),r=action(t.objectStore('outbox'));let result;r.onsuccess=()=>{result=r.result;};t.oncomplete=()=>resolve(result);t.onerror=()=>reject(new Error('Не удалось обновить зашифрованную очередь.'));t.onabort=t.onerror;});}finally{database.close();}}
export function validatePending(data,now=Date.now()){
  if(!exact(data,'entries,expires,group,id,issued,kind,payload')||!LINK.test(data?.id)||!Array.isArray(data.entries)||!data.entries.length||data.entries.length>25)throw new Error('В очередь допускаются только зашифрованные сообщения.');
  const payload=validateMessagePayload(data.payload,now);for(const key of ['id','expires','issued','kind','group'])if(data[key]!==payload[key])throw new Error('Параметры очереди не совпадают с шифром.');
  const seen=new Set();for(const entry of data.entries){if(!exact(entry,'recipientId,token')||seen.has(entry.recipientId)||!ID.test(entry.recipientId)||inspectMessageToken(entry.token).recipientId!==entry.recipientId)throw new Error('Неверный получатель в очереди.');seen.add(entry.recipientId);}
  return data;
}
export async function savePending(data){validatePending(data);await transaction('readwrite',s=>s.put(data));}
export async function loadPending(now=Date.now()){const all=await transaction('readonly',s=>s.getAll());const valid=[];for(const item of all){try{valid.push(validatePending(item,now));}catch{await removePending(item.id);}}return valid;}
export async function removePending(id){await transaction('readwrite',s=>s.delete(id));}
