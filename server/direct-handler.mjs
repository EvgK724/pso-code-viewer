// Direct, device-authenticated encrypted inbox; never receives patient plaintext.
import {importPublicCard} from '../docs/exchange.mjs';
import {verifyRecipientGrant} from '../docs/recipient-trust.mjs';
import {verifyMessageEnvelope} from '../docs/messages.mjs';
import {createVapidKeys,sendWebPush} from './web-push.mjs';
export const MAX_DIRECT_BODY_BYTES=2100000;
const DOMAIN='PSO-TEAM-v1\0',OLD_TOKEN_DOMAIN='PSO-SURNAME-LINK-v1\0';
const TTL=86400000,ROLES=['admin','neurologist','cardiologist','intensivist','bot'];
const OPS=['create','inbox','outbox','open','ack','retry','admin_members','admin_update','admin_replace','directory','admin_certify'];
const enc=new TextEncoder();
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===k;
const b64=v=>btoa(String.fromCharCode(...new Uint8Array(v))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
class Rejected extends Error{constructor(status=400,code='request_rejected'){super('Request rejected');this.status=status;this.code=code;}}
function bytes(v,len){
 if(typeof v!=='string'||v.length!==Math.ceil(len*4/3)||!/^[A-Za-z0-9_-]+$/.test(v))throw new Rejected();
 let r;try{const s=v.replace(/-/g,'+').replace(/_/g,'/');r=Uint8Array.from(atob(s+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));}catch{throw new Rejected();}
 if(r.length!==len||b64(r)!==v)throw new Rejected();return r;
}
function text(v){if(typeof v!=='string'||!v||v!==v.normalize('NFC').trim()||[...v].length>60||/[\p{Cc}\p{Cf}]/u.test(v))throw new Rejected();return v;}
function validMeta(v,at){
 if(!Number.isSafeInteger(v.issued)||v.issued<=0||v.issued>at+30000||!Number.isSafeInteger(v.expires)||v.expires<=at||v.expires<=v.issued||v.expires-v.issued>TTL||!['cardiology','orit'].includes(v.group)||!['admission','review'].includes(v.kind))throw new Rejected();bytes(v.id,16);
}
function failure(result){
 const state=typeof result==='string'?result:result?.status;
 if(state==='limited')throw new Rejected(429);
 if(state==='denied')throw new Rejected(403);
 if(state==='missing')throw new Rejected(404);
 if(['conflict','replay','roster_changed'].includes(state))throw new Rejected(409,state==='conflict'?'id_conflict':state);
 if(state==='invalid')throw new Rejected();
 throw new Error('Storage unavailable');
}
function result(r){if(r?.status)failure(r);return r;}
async function bodyJSON(request){
 if(!/^application\/json(?:\s*;|$)/i.test(request.headers.get('content-type')||''))throw new Rejected(415);
 const length=request.headers.get('content-length');if(length&&(!/^\d+$/.test(length)||Number(length)>MAX_DIRECT_BODY_BYTES))throw new Rejected(413);
 if(!request.body)throw new Rejected();const reader=request.body.getReader(),decoder=new TextDecoder('utf-8',{fatal:true});let size=0,value='';
 try{for(;;){const {done,value:chunk}=await reader.read();if(done)break;size+=chunk.byteLength;if(size>MAX_DIRECT_BODY_BYTES){await reader.cancel().catch(()=>{});throw new Rejected(413);}value+=decoder.decode(chunk,{stream:true});}value+=decoder.decode();return JSON.parse(value);}catch(e){if(e instanceof Rejected)throw e;throw new Rejected();}finally{reader.releaseLock();}
}
async function validateToken(token,payload,sender,recipient,crypto,at){
 if(typeof token!=='string'||token.length>1000)throw new Rejected();
 if(payload!==null){
  if(!token.startsWith('PSO2.'))throw new Rejected();
  try{await verifyMessageEnvelope(token,payload,sender,at);}catch{throw new Rejected(403);}
  const p=token.split('.');if(p[1]!==recipient||p[2]!==sender.id)throw new Rejected(403);return;
 }
 const p=token.split('.');if(p.length!==5||p[0]!=='PSO1')throw new Rejected();
 bytes(p[1],32);bytes(p[2],32);bytes(p[3],384);const signature=bytes(p[4],64);
 if(p[1]!==recipient||p[2]!==sender.id||!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},sender.signingPublicKey,signature,enc.encode(OLD_TOKEN_DOMAIN+p.slice(0,4).join('.'))))throw new Rejected(403);
}
export function createDirectHandler({store,allowedOrigin,crypto=globalThis.crypto,now=Date.now,send=sendWebPush}){
 const origin=new URL(allowedOrigin);if(origin.protocol!=='https:'||origin.origin!==allowedOrigin)throw new Error('One HTTPS origin required');
 for(const op of ['accept','create','list','open','members','update','replace','pushClaim','pushFinish','keys','unlockCheck','directory','certify'])if(typeof store?.[op]!=='function')throw new Error('Direct store missing '+op);
 let cachedKeys;
 async function keys(){if(!cachedKeys)cachedKeys=(async()=>{const k=await store.keys(null)||await store.keys(await createVapidKeys({crypto}));bytes(k?.publicKey,65);if(!k?.privateKey)throw new Error('Push unavailable');return k;})().catch(e=>{cachedKeys=null;throw e;});return cachedKeys;}
 function response(status,value,cors=true){
  const h={'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','Vary':'Origin'};
  if(cors)h['Access-Control-Allow-Origin']=allowedOrigin;
  if(status===204)Object.assign(h,{'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Content-Type','Access-Control-Max-Age':'600'});else h['Content-Type']='application/json; charset=utf-8';
  return new Response(status===204?null:JSON.stringify(value),{status,headers:h});
 }
 async function notify(actor,id,at){
  let targets;
  try{const claimed=result(await store.pushClaim(actor,id));targets=claimed?.targets;if(!Array.isArray(targets)||targets.length>20)throw new Error('Bad claims');}
  catch{return {accepted:0,queued:1};}
  let accepted=0,queued=0;
  // Bound concurrency / duration. Every outcome completes a lease; ambiguous
  // network failures retry later with same notification tag/id, not new records.
  for(let offset=0;offset<targets.length;offset+=5){
   await Promise.all(targets.slice(offset,offset+5).map(async t=>{
    let state='failed';
    try{
     bytes(t.id,16);bytes(t.recipientId,32);if(id&&t.id!==id)throw new Error('Unexpected message');
     if(!Number.isSafeInteger(t.lease)||t.lease<1||!Number.isSafeInteger(t.expires)||t.expires<=at||t.expires>at+TTL)throw new Error('Expired notification');
     const r=await send(t.subscription,await keys(),{v:2,id:t.id,expires:t.expires},{crypto,now:at,ttl:Math.max(0,Math.floor((t.expires-at)/1000))});
     if(['accepted','gone'].includes(r?.status))state=r.status;
    }catch{/* No provider details or subscription endpoints in logs/responses. */}
    try{await store.pushFinish(t.id,t.recipientId,t.lease,state);}catch{/* Lease timeout recovers the attempt. */}
    if(state==='accepted')accepted++;else queued++;
   }));
  }
  return {accepted,queued};
 }
 return async function handle(request){
  if(request.headers.get('origin')!==allowedOrigin)return response(403,{error:'request_rejected'},false);
  try{
   const url=new URL(request.url);if(url.search||url.hash||url.username||url.password)throw new Rejected();
   if(request.method==='OPTIONS'){const h=(request.headers.get('access-control-request-headers')||'').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean);if(request.headers.get('access-control-request-method')!=='POST'||h.some(x=>x!=='content-type'))throw new Rejected(403);return response(204,null);}
   if(request.method!=='POST')throw new Rejected(405);
   const body=await bodyJSON(request),at=now();if(!Number.isSafeInteger(at))throw new Error('Clock unavailable');
   if(!exact(body,'envelope')||!exact(body.envelope,'card,data,issued,nonce,op,signature,v'))throw new Rejected();
   const e=body.envelope;
   if(e.v!==1||!OPS.includes(e.op)||!Number.isSafeInteger(e.issued)||e.issued<at-60000||e.issued>at+30000)throw new Rejected();
   bytes(e.nonce,16);const signature=bytes(e.signature,64);let sender;try{sender=await importPublicCard(e.card);}catch{throw new Rejected();}
   const unsigned={v:1,op:e.op,issued:e.issued,nonce:e.nonce,card:e.card,data:e.data};
   if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},sender.signingPublicKey,signature,enc.encode(DOMAIN+JSON.stringify(unsigned))))throw new Rejected(403);
   const data=e.data;let normalized;
   if(['retry','admin_members','directory'].includes(e.op)){if(!exact(data,''))throw new Rejected();}
   else if(['inbox','outbox'].includes(e.op)){
    if(!exact(data,'')&&!exact(data,'cursor'))throw new Rejected();
    if(data.cursor!=null){if(!exact(data.cursor,'id,issued')||!Number.isSafeInteger(data.cursor.issued)||data.cursor.issued<=0)throw new Rejected();bytes(data.cursor.id,16);}
   }else if(e.op==='open'){
    if(!exact(data,'id')&&!exact(data,'id,unlockToken'))throw new Rejected();bytes(data.id,16);if('unlockToken'in data)bytes(data.unlockToken,32);
   }else if(e.op==='ack'){if(!exact(data,'id'))throw new Rejected();bytes(data.id,16);}
   else if(e.op==='admin_certify'){
    if(!exact(data,'approvalProof,id'))throw new Rejected();bytes(data.id,32);
   }else if(e.op==='admin_update'){
    if((!exact(data,'id,name,role,state')&&!exact(data,'approvalProof,id,name,role,state'))||!ROLES.includes(data.role)||data.role==='admin'||!['active','revoked'].includes(data.state))throw new Rejected();bytes(data.id,32);text(data.name);
   }else if(e.op==='admin_replace'){
    if(!exact(data,'approvalProof,newId,oldId'))throw new Rejected();bytes(data.oldId,32);bytes(data.newId,32);if(data.oldId===data.newId)throw new Rejected();
   }else{
    if(!exact(data,'entries,expires,group,id,issued,kind')&&!exact(data,'entries,expires,group,id,issued,kind,payload'))throw new Rejected();
    validMeta(data,at);if(!Array.isArray(data.entries)||data.entries.length<1||data.entries.length>25)throw new Rejected();
    if('payload'in data){if(!data.payload||data.payload.id!==data.id||data.payload.group!==data.group||data.payload.kind!==data.kind||data.payload.issued!==data.issued||data.payload.expires!==data.expires)throw new Rejected();}
   }
   const spki=b64(await crypto.subtle.exportKey('spki',sender.signingPublicKey));
   const ok=await store.accept(sender.id,e.nonce,e.op,e.issued,e.card,spki);if(ok!=='ok')failure(ok);
   if(e.op==='create'){
    const directory=result(await store.directory(sender.id));if(!Array.isArray(directory?.members))throw new Error('Missing directory');
    const actor=directory.members.find(m=>m.id===sender.id);if(!actor)throw new Rejected(403);
    const admins=directory.members.filter(m=>m.role==='admin');
    async function approved(member){if(member.role==='admin'&&member.id===sender.id)return;const issuer=admins.find(a=>a.id===member.approvalProof?.grant?.issuerId);if(!issuer)throw new Rejected(403);try{await verifyRecipientGrant(member,issuer.card,at);}catch{throw new Rejected(403);}}
    await approved(actor);
    const seen=new Set(),entries=[];
    for(const entry of data.entries){if(!exact(entry,'recipientId,token'))throw new Rejected();bytes(entry.recipientId,32);if(seen.has(entry.recipientId))throw new Rejected();seen.add(entry.recipientId);const member=directory.members.find(m=>m.id===entry.recipientId);if(!member)throw new Rejected(403);await approved(member);await validateToken(entry.token,data.payload??null,sender,entry.recipientId,crypto,at);entries.push({recipientId:entry.recipientId,token:entry.token});}
    entries.sort((a,b)=>a.recipientId<b.recipientId?-1:a.recipientId>b.recipientId?1:0);
    normalized={id:data.id,group:data.group,kind:data.kind,issued:data.issued,expires:data.expires,entries};if(data.payload)normalized.payload=data.payload;
    const hash=[...new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(JSON.stringify(normalized))))].map(x=>x.toString(16).padStart(2,'0')).join('');
    const created=await store.create(sender.id,hash,normalized);if(!['created','exists'].includes(created))failure(created);
    const delivery=await notify(sender.id,data.id,at);
    const push=delivery.accepted===entries.length?'accepted':delivery.accepted>0?'partial':'queued';
    return response(200,{id:data.id,expires:data.expires,push});
   }
   if(e.op==='inbox'||e.op==='outbox'){
    const r=result(await store.list(sender.id,e.op==='outbox',data.cursor??null));if(!exact(r,'items,next')||!Array.isArray(r.items)||r.items.length>50)throw new Error('Invalid inbox response');
    for(const item of r.items){if(!exact(item,'expires,group,id,issued,kind,openedAt,openedCount,recipientCount,senderId,senderName'))throw new Error('Invalid inbox item');validMeta(item,at);bytes(item.senderId,32);text(item.senderName);if(!Number.isSafeInteger(item.recipientCount)||item.recipientCount<1||item.recipientCount>25||!Number.isSafeInteger(item.openedCount)||item.openedCount<0||item.openedCount>item.recipientCount||(item.openedAt!==null&&!Number.isSafeInteger(item.openedAt)))throw new Error('Invalid receipt');}
    if(r.next!==null){if(!exact(r.next,'id,issued')||!Number.isSafeInteger(r.next.issued))throw new Error('Invalid cursor');bytes(r.next.id,16);}return response(200,r);
   }
   if(e.op==='open'){
    if(!await store.unlockCheck(sender.id,data.unlockToken||''))throw new Rejected(428,'unlock_required');
    const r=result(await store.open(sender.id,data.id,false));if(!exact(r,'meta,payload,senderApprovalProof,senderCard,senderName,senderRole,token')||!exact(r.meta,'expires,group,id,issued,kind')||r.meta.id!==data.id)throw new Error('Invalid message');validMeta(r.meta,at);text(r.senderName);
    let owner;try{owner=await importPublicCard(r.senderCard);}catch{throw new Error('Invalid sender');}await validateToken(r.token,r.payload,owner,sender.id,crypto,at);
    if(r.payload&&(r.payload.id!==r.meta.id||r.payload.group!==r.meta.group||r.payload.kind!==r.meta.kind||r.payload.issued!==r.meta.issued||r.payload.expires!==r.meta.expires))throw new Error('Invalid message binding');
    return response(200,r);
   }
   if(e.op==='ack'){
    const r=result(await store.open(sender.id,data.id,true));if(!exact(r,'openedAt')||!Number.isSafeInteger(r.openedAt))throw new Error('Invalid receipt');return response(200,r);
   }
   if(e.op==='retry')return response(200,await notify(sender.id,null,at));
   if(e.op==='directory'){const r=result(await store.directory(sender.id));if(!exact(r,'members')||!Array.isArray(r.members)||r.members.length>100)throw new Error('Invalid directory');return response(200,r);}
   if(e.op==='admin_members'){
    const r=result(await store.members(sender.id));if(!exact(r,'members')||!Array.isArray(r.members)||r.members.length>500)throw new Error('Invalid members');
    for(const m of r.members){if(!exact(m,'approvalProof,approvedAt,card,createdAt,id,name,revokedAt,role,state')||!ROLES.includes(m.role)||!['active','pending','revoked'].includes(m.state))throw new Error('Invalid member');bytes(m.id,32);text(m.name);}return response(200,r);
   }
   if(['admin_certify','admin_update','admin_replace'].includes(e.op)){
    const listing=result(await store.members(sender.id));if(!Array.isArray(listing?.members))throw new Error('Missing members');
    const actor=listing.members.find(m=>m.id===sender.id&&m.role==='admin'&&m.state==='active');if(!actor)throw new Rejected(403);
    let target;
    if(e.op==='admin_replace'){const old=listing.members.find(m=>m.id===data.oldId);const next=listing.members.find(m=>m.id===data.newId);if(!old||!next)throw new Rejected(403);target={...next,name:old.name,role:old.role,approvalProof:data.approvalProof};}
    else{target=listing.members.find(m=>m.id===data.id);if(!target)throw new Rejected(403);target={...target,approvalProof:data.approvalProof};if(e.op==='admin_update')Object.assign(target,{name:data.name,role:data.role});}
    if(e.op!=='admin_update'||data.state!=='revoked'){try{await verifyRecipientGrant(target,e.card,at);}catch{throw new Rejected(403);}}
    if(e.op==='admin_certify')return response(200,result(await store.certify(sender.id,data.id,data.approvalProof)));
    if(e.op==='admin_update')return response(200,result(await store.update(sender.id,data.id,data.name,data.role,data.state,data.approvalProof??null)));
    return response(200,result(await store.replace(sender.id,data.oldId,data.newId,data.approvalProof)));
   }
   throw new Rejected();
  }catch(error){return response(error instanceof Rejected?error.status:503,{error:error instanceof Rejected?error.code:'request_rejected'});}
 };
}
