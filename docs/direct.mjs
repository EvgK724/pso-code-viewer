// Direct delivery: signed requests, recipient-only inbox, encrypted local retries.
import {deviceIdentity,exportPublicCard, importPublicCard} from './exchange.mjs';
import {validateMessagePayload,inspectMessageToken,verifyMessageEnvelope,messageUnbase64url,MAX_MESSAGE_TTL,HISTORY_TTL} from './messages.mjs';
import {verifyRecipientGrant} from './recipient-trust.mjs';
import {runApiRequest,readApiError,apiDiagnosticText,API_REQUEST_TIMEOUT_MS} from './api-queue.mjs';
const DOMAIN='PSO-TEAM-v1\0', enc=new TextEncoder();
const ID=/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/, LINK=/^[A-Za-z0-9_-]{21}[AQgw]$/;
const OPS=['create','inbox','outbox','open','ack','history','history_open','retry','admin_members','admin_update','admin_replace','directory','admin_certify','release_status'];
import {ROLES,GROUPS,isRehabGroup,isReplyKind,isGroupConversationKind,canSendGroup,memberRoles} from './care-routing.mjs';
const b64=x=>btoa(String.fromCharCode(...new Uint8Array(x))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===k;
const optionalExact=(value,required,optional=[])=>value&&typeof value==='object'&&!Array.isArray(value)&&required.split(',').every(key=>Object.hasOwn(value,key))&&Object.keys(value).every(key=>required.split(',').includes(key)||optional.includes(key));
const senderRoles=value=>({role:value.senderRole,...(Object.hasOwn(value,'senderRoles')?{roles:value.senderRoles}:{})});
const label=v=>typeof v==='string'&&v.trim()===v&&v.length>0&&[...v].length<=60&&!/[\p{Cc}\p{Cf}]/u.test(v);
const kindAllowed=(kind,group)=>['admission','review','reply','group_reply','discussion'].includes(kind)&&(!isRehabGroup(group)||!['admission','reply'].includes(kind))&&(kind!=='discussion'||group==='rehab1');
const historyMeta=(m,now)=>m&&LINK.test(m.id)&&GROUPS.includes(m.group)&&kindAllowed(m.kind,m.group)&&Number.isSafeInteger(m.issued)&&m.issued>0&&m.issued<=now+30000&&Number.isSafeInteger(m.expires)&&m.expires>m.issued&&m.expires-m.issued<=MAX_MESSAGE_TTL;
const historyTime=(m,now)=>Number.isSafeInteger(m.createdAt)&&m.createdAt>=m.issued-30000&&m.createdAt<=now+30000&&Number.isSafeInteger(m.archiveUntil)&&m.archiveUntil===m.issued+HISTORY_TTL&&m.archiveUntil>now;
const receiptTime=(value,m,now)=>value===null||(Number.isSafeInteger(value)&&value>=m.createdAt&&value<m.meta.expires&&value<=now+30000);
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
  constructor(endpoint,{fetch:fetcher=globalThis.fetch.bind(globalThis),now=Date.now,timeout=API_REQUEST_TIMEOUT_MS,sleep,random}={}){
    const u=new URL(endpoint);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw new Error('Неверный адрес сообщений.');
    this.endpoint=u.href;this.fetcher=fetcher;this.now=now;this.timeout=timeout;this.sleep=sleep;this.random=random;
  }
  async request(device,op,data={}){
    const snapshot=JSON.parse(JSON.stringify(data));
    return runApiRequest(()=>this.requestOnce(device,op,snapshot),{retry:op==='admin_certify',sleep:this.sleep,random:this.random});
  }
  async requestOnce(device,op,data){
    const envelope=await directEnvelope(device,op,data,this.now()),controller=new AbortController(),timer=setTimeout(()=>controller.abort(),this.timeout);
    try{
      const headers={'Content-Type':'application/json'};
      const r=await this.fetcher(this.endpoint,{method:'POST',headers,body:JSON.stringify({envelope}),credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',signal:controller.signal});
      if(!r.ok){const details=await readApiError(r);
        const messages={400:details.code==='clock_skew'?'Проверьте автоматические дату и время на телефоне и повторите (HTTP 400).':'Запрос отклонён (HTTP 400). Обновите приложение и повторите.',401:'Подтвердите доступ на этом телефоне.',428:'Подтвердите Face ID или код телефона.',403:'Доступ отключён или действие недоступно для вашей роли.',404:'Сообщение недоступно или срок его хранения истёк.',409:'Состав получателей изменился. Обновите команду и подготовьте сообщение заново.',413:'Фото слишком большое. Выберите снимок меньшего размера.',429:'Слишком много запросов. Повторите позже.'};
        const message=details.code==='group_too_large'?'В обсуждении больше 25 устройств. Сообщение не отправлено; организатору нужно проверить состав команды.':details.code==='history_full'?'История сообщений заполнена. Сообщение не отправлено; зашифрованная копия остаётся в очереди.':messages[r.status]||'Нет подтверждения сервиса (HTTP '+r.status+'). Повторите действие позже.';
        throw new DirectError(message+apiDiagnosticText(details),r.status,details.code);
      }
      if(!r.headers.get('content-type')?.startsWith('application/json'))throw new Error('Неверный ответ сервиса.');
      const reader=r.body?.getReader();if(!reader)throw new Error('Нет ответа сервиса.');
      let total=0,text='';const decoder=new TextDecoder('utf-8',{fatal:true});
      try{for(;;){const{done,value}=await reader.read();if(done)break;total+=value.byteLength;if(total>3000000){await reader.cancel();throw new Error('Ответ слишком большой.');}text+=decoder.decode(value,{stream:true});}text+=decoder.decode();return JSON.parse(text);}finally{reader.releaseLock();}
    }catch(e){if(e.name==='AbortError'||e instanceof TypeError||e instanceof SyntaxError){const error=new DirectError('Нет связи с сервисом. Повторите после подключения.',0);error.networkFailure=e.name==='AbortError'||e instanceof TypeError;throw error;}throw e;}finally{clearTimeout(timer);}
  }
  async list(device,box='inbox',cursor=null){
    if(!['inbox','outbox'].includes(box))throw new Error('Неизвестный список.');
    const r=await this.request(device,box,{cursor,includeConversations:true});
    if(!exact(r,'items,next')||!Array.isArray(r.items)||r.items.length>100||!(r.next===null||exact(r.next,'id,issued')&&LINK.test(r.next.id)&&Number.isSafeInteger(r.next.issued)))throw new Error('Не удалось проверить список сообщений.');
    const ids=new Set();for(const m of r.items){if(!exact(m,'expires,group,id,issued,kind,openedAt,openedCount,recipientCount,senderId,senderName')||!LINK.test(m.id)||ids.has(m.id)||!ID.test(m.senderId)||!label(m.senderName)||!GROUPS.includes(m.group)||!kindAllowed(m.kind,m.group)||!Number.isSafeInteger(m.issued)||!Number.isSafeInteger(m.expires)||m.expires<=m.issued||!(m.openedAt===null||Number.isSafeInteger(m.openedAt))||!Number.isInteger(m.recipientCount)||m.recipientCount<0||m.recipientCount>25||!Number.isInteger(m.openedCount)||m.openedCount<0||m.openedCount>m.recipientCount)throw new Error('Не удалось проверить сообщение.');ids.add(m.id);}
    return r;
  }
  async open(device,id,{unlockToken=''}={}){
    if(!LINK.test(id))throw new Error('Неверный код сообщения.');
    const r=await this.request(device,'open',{id,includeRoles:true,...(unlockToken?{unlockToken}:{})});
    if(!optionalExact(r,'meta,payload,senderApprovalProof,senderCard,senderName,senderRole,token',['senderRoles','senderRoleProofs'])||!exact(r.meta,isReplyKind(r.meta?.kind)?'expires,group,id,issued,kind,replyTo':'expires,group,id,issued,kind')||r.meta.id!==id||!label(r.senderName)||!memberRoles(senderRoles(r)).length||typeof r.token!=='string'||r.token.length>1600||!Number.isSafeInteger(r.meta.issued)||r.meta.issued<=0||r.meta.issued>this.now()+30000||!Number.isSafeInteger(r.meta.expires)||r.meta.expires<=this.now()||r.meta.expires<=r.meta.issued||r.meta.expires-r.meta.issued>MAX_MESSAGE_TTL||!kindAllowed(r.meta.kind,r.meta.group)||(isReplyKind(r.meta.kind)&&(!LINK.test(r.meta.replyTo)||r.meta.replyTo===r.meta.id||!r.payload||!r.token.startsWith('PSO2.')))||!GROUPS.includes(r.meta.group))throw new Error('Не удалось проверить сообщение.');
    if(!canSendGroup(senderRoles(r),r.meta.group,r.meta.kind)||((isRehabGroup(r.meta.group)||isGroupConversationKind(r.meta.kind))&&(!r.payload||!r.token.startsWith('PSO2.'))))throw new Error('Роль отправителя или формат сообщения не соответствуют направлению.');
    const sender=await importPublicCard(r.senderCard);if(r.token.split('.')[2]!==sender.id)throw new Error('Подпись отправителя не соответствует записи.');
    return {...r,sender:{...sender,name:r.senderName,verified:true}};
  }
  async history(device,cursor=null,{source='own'}={}){
    if(!['own','bot'].includes(source))throw new Error('Неизвестный раздел истории.');
    const r=await this.request(device,'history',{cursor,...(source==='bot'?{source}:{})}),now=this.now();
    if(!exact(r,'items,next')||!Array.isArray(r.items)||r.items.length>50||!(r.next===null||exact(r.next,'id,issued')&&LINK.test(r.next.id)&&Number.isSafeInteger(r.next.issued)&&r.next.issued>0))throw new Error('Не удалось проверить историю сообщений.');
    const seen=new Set();
    for(const m of r.items){
      if(!exact(m,'archiveUntil,createdAt,expires,group,hasContent,id,issued,kind,openedCount,recipientCount')||!historyMeta(m,now)||!historyTime(m,now)||seen.has(m.id)||typeof m.hasContent!=='boolean'||!Number.isInteger(m.recipientCount)||m.recipientCount<1||m.recipientCount>25||!Number.isInteger(m.openedCount)||m.openedCount<0||m.openedCount>m.recipientCount||(source==='bot'&&(m.kind!=='admission'||!['cardiology','orit'].includes(m.group))))throw new Error('Не удалось проверить запись истории.');
      seen.add(m.id);
    }
    return r;
  }
  async botHistory(device,cursor=null){return this.history(device,cursor,{source:'bot'});}
  async historyOpen(device,id,{unlockToken=''}={}){
    if(!LINK.test(id))throw new Error('Неверный код сообщения.');
    const r=await this.request(device,'history_open',{id,includeRoles:true,...(unlockToken?{unlockToken}:{})}),now=this.now();
    if(!optionalExact(r,'archiveUntil,createdAt,meta,organizerToken,payload,recipients,senderApprovalProof,senderCard,senderName,senderRole,senderToken',['senderRoles','senderRoleProofs'])||!exact(r.meta,isReplyKind(r.meta?.kind)?'expires,group,id,issued,kind,replyTo':'expires,group,id,issued,kind')||r.meta.id!==id||!historyMeta(r.meta,now)||!historyTime({...r,...r.meta},now)||!label(r.senderName)||!memberRoles(senderRoles(r)).length||!Array.isArray(r.recipients)||r.recipients.length<1||r.recipients.length>25||(isReplyKind(r.meta.kind)&&(!LINK.test(r.meta.replyTo)||r.meta.replyTo===id)))throw new Error('Не удалось проверить запись истории.');
    const own=await deviceIdentity(device),sender=await importPublicCard(r.senderCard);
    let verifiedSender={...sender,name:r.senderName,verified:true};
    const seen=new Set();
    for(const recipient of r.recipients){
      if(!optionalExact(recipient,'id,name,openedAt,pushAcceptedAt,pushState,role',['roles'])||!ID.test(recipient.id)||seen.has(recipient.id)||!label(recipient.name)||!memberRoles(recipient).length||!['queued','sending','accepted','gone','failed'].includes(recipient.pushState)||!receiptTime(recipient.openedAt,r,now)||!receiptTime(recipient.pushAcceptedAt,r,now)||(recipient.pushState==='accepted')!==(recipient.pushAcceptedAt!==null))throw new Error('Не удалось проверить подтверждение получателя.');
      seen.add(recipient.id);
    }
    if(r.organizerToken!==null){
      if(r.senderRole!=='bot'||r.meta.kind!=='admission'||!['cardiology','orit'].includes(r.meta.group)||r.payload!==null||r.senderToken!==null||typeof r.organizerToken!=='string'||r.organizerToken.length>1000)throw new Error('Неверный архив бота.');
      verifiedSender=await verifyRecipientGrant({id:sender.id,name:r.senderName,role:'bot',card:r.senderCard,approvalProof:r.senderApprovalProof},await exportPublicCard(device,'Организатор'),r.meta.issued);
      const parts=r.organizerToken.split('.');
      if(parts.length!==5||parts[0]!=='PSO1'||parts[1]!==own.id||parts[2]!==sender.id)throw new Error('Архив бота предназначен другому организатору.');
      messageUnbase64url(parts[3],384,512);const signature=messageUnbase64url(parts[4],64,86);
      if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},sender.signingPublicKey,signature,enc.encode('PSO-SURNAME-LINK-v1\0'+parts.slice(0,4).join('.'))))throw new Error('Подпись бота не подтверждена.');
    }else{
      if(sender.id!==own.id||r.senderApprovalProof!==null)throw new Error('История принадлежит другому отправителю.');
      if(r.payload===null||r.senderToken===null){if(r.payload!==null||r.senderToken!==null)throw new Error('История зашифрована не полностью.');}
      else{
        const token=inspectMessageToken(r.senderToken);
        if(token.senderId!==own.id||token.recipientId!==own.id)throw new Error('Архив предназначен другому устройству.');
        const payload=validateMessagePayload(r.payload,r.meta.issued);
        for(const key of ['id','group','kind','issued','expires','replyTo'])if(payload[key]!==r.meta[key])throw new Error('Параметры истории не совпадают с шифром.');
        await verifyMessageEnvelope(r.senderToken,payload,sender,r.meta.issued);
      }
    }
    return {...r,sender:verifiedSender};
  }
  async create(device,data){const r=await this.request(device,'create',data);if(!exact(r,'expires,id,push')||r.id!==data.id||r.expires!==data.expires||!['accepted','partial','queued'].includes(r.push))throw new Error('Сервис не подтвердил сохранение. Повторите отправку из очереди.');return r;}
  async ack(device,id){const r=await this.request(device,'ack',{id});if(!exact(r,'openedAt')||!Number.isSafeInteger(r.openedAt))throw new Error('Не подтверждено открытие.');return r;}
  async retry(device){return this.request(device,'retry',{});}
  async members(device){const r=await this.request(device,'admin_members',{includeRehab:true,includeRoles:true});if(!exact(r,'members')||!Array.isArray(r.members)||r.members.length>500)throw new Error('Не удалось получить команду.');
    const list=[];for(const m of r.members){if(!ID.test(m.id)||!label(m.name)||!memberRoles(m).length||Object.hasOwn(m,'pendingRole')&&(m.state!=='active'||!memberRoles([...memberRoles(m),m.pendingRole]).length)||!['active','pending','revoked'].includes(m.state)||typeof m.card!=='string')throw new Error('Не удалось проверить участника.');const card=await importPublicCard(m.card);if(card.id!==m.id)throw new Error('Ключ участника изменился.');list.push({...card,...m,verified:m.state==='active'});}return list;}
  async update(device,member){const data={id:member.id,name:member.name,role:member.role,state:member.state};if(member.approvalProof)data.approvalProof=member.approvalProof;if(member.roles)data.roles=member.roles;if(member.roleProofs)data.roleProofs=member.roleProofs;return this.request(device,'admin_update',data);}
  async replace(device,oldId,newId,approvalProof,roleProofs){return this.request(device,'admin_replace',{oldId,newId,approvalProof,...(roleProofs?{roleProofs}:{})});}
  async directory(device){const r=await this.request(device,'directory',{includeRehab:true,includeRoles:true});if(!exact(r,'members')||!Array.isArray(r.members)||r.members.length>100)throw new Error('Не удалось проверить состав команды.');return r.members;}
  async certify(device,id,approvalProof){return this.request(device,'admin_certify',{id,approvalProof});}
}

// Only encrypted bodies and delivery metadata are persisted; never names/photos.
const DB='pso-direct-retries-'+encodeURIComponent(new URL('./',import.meta.url).pathname);
function db(){return new Promise((resolve,reject)=>{const r=indexedDB.open(DB,1);r.onupgradeneeded=()=>r.result.createObjectStore('outbox',{keyPath:'id'});r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(new Error('Не удалось сохранить зашифрованную очередь на телефоне.'));});}
async function transaction(mode,action){const database=await db();try{return await new Promise((resolve,reject)=>{const t=database.transaction('outbox',mode),r=action(t.objectStore('outbox'));let result;r.onsuccess=()=>{result=r.result;};t.oncomplete=()=>resolve(result);t.onerror=()=>reject(new Error('Не удалось обновить зашифрованную очередь.'));t.onabort=t.onerror;});}finally{database.close();}}
export function validatePending(data,now=Date.now()){
  const fields=(isReplyKind(data?.kind)?'entries,expires,group,id,issued,kind,payload,replyTo':'entries,expires,group,id,issued,kind,payload')+(Object.hasOwn(data||{},'senderToken')?',senderToken':'');
  if(!exact(data,fields)||!LINK.test(data?.id)||!Array.isArray(data.entries)||!data.entries.length||data.entries.length>25)throw new Error('В очередь допускаются только зашифрованные сообщения.');
  const payload=validateMessagePayload(data.payload,now);for(const key of ['id','expires','issued','kind','group','replyTo'])if(data[key]!==payload[key])throw new Error('Параметры очереди не совпадают с шифром.');
  let senderId,payloadHash;const seen=new Set();for(const entry of data.entries){
    if(!exact(entry,'recipientId,token')||seen.has(entry.recipientId)||!ID.test(entry.recipientId))throw new Error('Неверный получатель в очереди.');
    const token=inspectMessageToken(entry.token);if(token.recipientId!==entry.recipientId||(senderId&&token.senderId!==senderId)||(payloadHash&&token.payloadHash!==payloadHash))throw new Error('Неверная подпись получателя в очереди.');
    senderId=token.senderId;payloadHash=token.payloadHash;seen.add(entry.recipientId);
  }
  if(Object.hasOwn(data,'senderToken')){const token=inspectMessageToken(data.senderToken);if(token.recipientId!==senderId||token.senderId!==senderId||token.payloadHash!==payloadHash)throw new Error('Неверная зашифрованная копия отправителя.');}
  return data;
}
export async function savePending(data){validatePending(data);await transaction('readwrite',s=>s.put(data));}
export async function loadPending(now=Date.now()){const all=await transaction('readonly',s=>s.getAll());const valid=[];for(const item of all){try{valid.push(validatePending(item,now));}catch{await removePending(item.id);}}return valid;}
export async function removePending(id){await transaction('readwrite',s=>s.delete(id));}
