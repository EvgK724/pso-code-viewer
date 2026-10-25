import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {createDirectHandler,MAX_DIRECT_BODY_BYTES} from './direct-handler.mjs';
import {makeDevice,base64url} from '../docs/crypto.mjs';
import {deviceIdentity,exportPublicCard,importPublicCard,sealSurname,openSurname} from '../docs/exchange.mjs';
import {sealMessage,openMessage} from '../docs/messages.mjs';
import {makeRecipientGrant} from '../docs/recipient-trust.mjs';
import {createVapidKeys} from './web-push.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const ORIGIN='https://viewer.example',URL='https://broker.example/pso-direct',NOW=Date.now();
const devices=await Promise.all(Array.from({length:6},()=>makeDevice()));
const [admin,neuro,cardio,icu,bot,replacement]=devices;
const cards=await Promise.all(devices.map(d=>exportPublicCard(d,'Устройство')));
const contacts=await Promise.all(cards.map(async card=>({...await importPublicCard(card),verified:true})));
const roles=['admin','neurologist','cardiologist','intensivist','bot','intensivist'];
const members=await Promise.all(contacts.map(async(c,i)=>{const m={id:c.id,card:cards[i],name:'Врач '+i,role:roles[i]};return {...m,approvalProof:i===0?null:await makeRecipientGrant(admin,m,{now:NOW})};}));
const rid=()=>base64url(crypto.getRandomValues(new Uint8Array(16)));
const vapid=await createVapidKeys();
async function envelope(device,op,data={},issued=NOW){const unsigned={v:1,op,issued,nonce:rid(),card:await exportPublicCard(device,'Устройство'),data};return {...unsigned,signature:base64url(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},device.signing.privateKey,new TextEncoder().encode('PSO-TEAM-v1\0'+JSON.stringify(unsigned))))};}
function req(envelope,{origin=ORIGIN,raw,headers={}}={}){return new Request(URL,{method:'POST',headers:{Origin:origin,'Content-Type':'application/json',...headers},body:raw??JSON.stringify({envelope})});}
function fixture({unlock=true,sendState='accepted'}={}){
 let clock=NOW;const roster=new Map(members.map((m,i)=>[m.id,{...m,state:i===5?'pending':'active',createdAt:NOW,approvedAt:i===5?null:NOW,revokedAt:null}]));const messages=new Map(),nonces=new Set(),pushes=[],leases=new Map(),audit=[];
 const active=id=>roster.get(id)?.state==='active';
 const store={
  async accept(id,nonce){if(!active(id))return'denied';if(nonces.has(id+nonce))return'replay';nonces.add(id+nonce);return'ok';},
  async directory(id){if(!active(id))return{status:'denied'};return{members:[...roster.values()].filter(m=>m.state==='active').map(({id,name,role,card,approvalProof})=>({id,name,role,card,approvalProof}))};},
  async create(sender,hash,data){const m=roster.get(sender);if(!active(sender)||(data.kind==='admission'?m.role!=='bot':!['admin','neurologist'].includes(m.role)))return'denied';const old=messages.get(data.id);if(old)return old.hash===hash?'exists':'conflict';const expected=[...roster.values()].filter(m=>m.state==='active'&&m.role===(data.group==='cardiology'?'cardiologist':'intensivist')).map(m=>m.id).sort();if(JSON.stringify(data.entries.map(e=>e.recipientId).sort())!==JSON.stringify(expected))return'roster_changed';messages.set(data.id,{...data,payload:data.payload??null,sender,hash,acks:new Map()});return'created';},
  async list(id,outbox,cursor){const mine=[...messages.values()].filter(m=>m.expires>clock&&(outbox?m.sender===id:m.entries.some(e=>e.recipientId===id)));return{items:mine.map(m=>({id:m.id,group:m.group,kind:m.kind,issued:m.issued,expires:m.expires,senderId:m.sender,senderName:roster.get(m.sender).name,openedAt:m.acks.get(id)||null,recipientCount:m.entries.length,openedCount:m.acks.size})),next:null};},
  async open(id,key,ack){const m=messages.get(key);if(!m||m.expires<=clock)return{status:'missing'};const e=m.entries.find(e=>e.recipientId===id);if(!active(id)||!e)return{status:'denied'};if(ack){if(!m.acks.has(id))m.acks.set(id,clock);return{openedAt:m.acks.get(id)};}const s=roster.get(m.sender);audit.push({id,key});return{token:e.token,payload:m.payload,senderCard:s.card,senderName:s.name,senderRole:s.role,senderApprovalProof:s.approvalProof,meta:{id:m.id,group:m.group,kind:m.kind,issued:m.issued,expires:m.expires}};},
  async members(id){if(roster.get(id)?.role!=='admin'||!active(id))return{status:'denied'};return{members:[...roster.values()]};},
  async update(actor,id,name,role,state,proof){if(roster.get(actor)?.role!=='admin'||id===actor||roster.get(id)?.state!=='active')return{status:'denied'};Object.assign(roster.get(id),{name,role,state,approvalProof:proof});return{state};},
  async replace(actor,oldId,newId,proof){if(roster.get(actor)?.role!=='admin'||roster.get(newId)?.state!=='pending')return{status:'denied'};const old=roster.get(oldId);old.state='revoked';Object.assign(roster.get(newId),{name:old.name,role:old.role,state:'active',approvalProof:proof});return{state:'active'};},
  async certify(actor,id,proof){if(roster.get(actor)?.role!=='admin')return{status:'denied'};roster.get(id).approvalProof=proof;return{state:'active'};},
  async pushClaim(actor,key){const targets=[];for(const m of messages.values()){if(key&&m.id!==key)continue;for(const e of m.entries){const key=m.id+e.recipientId;const old=leases.get(key);if(!active(e.recipientId)||old?.status==='accepted'||old?.status==='sending')continue;const lease=(old?.lease||0)+1;leases.set(key,{lease,status:'sending'});targets.push({id:m.id,recipientId:e.recipientId,expires:m.expires,subscription:{synthetic:true},lease});}}return{targets};},
  async pushFinish(id,recipient,lease,status){const key=id+recipient;if(leases.get(key)?.lease===lease)leases.set(key,{lease,status});},
  async keys(){return vapid;},async unlockCheck(){return unlock;}
 };
 const handler=createDirectHandler({store,allowedOrigin:ORIGIN,now:()=>clock,send:async(s,k,p)=>{pushes.push(p);return{status:sendState};}});
 return{store,handler,roster,messages,pushes,leases,audit,setTime:t=>clock=t,async op(device,op,data={},options){return handler(req(await envelope(device,op,data,clock),options));}};
}
async function legacy(sender=bot,group='cardiology'){const index=group==='cardiology'?2:3;return{id:rid(),group,kind:sender===bot?'admission':'review',issued:NOW,expires:NOW+3600000,entries:[{recipientId:contacts[index].id,token:await sealSurname(sender,contacts[index],'Вымышленный',{department:group==='cardiology'?'ПСО':'ОРИТ',ttlMinutes:60,now:NOW})}]};}

test('legacy bot arrives in direct inbox, opens only for target, acknowledges separately from delivery',async()=>{
 const f=fixture(),d=await legacy();assert.equal((await f.op(bot,'create',d)).status,200);assert.equal(f.pushes.length,1);assert.deepEqual(f.pushes[0],{v:2,id:d.id,expires:d.expires});
 assert.equal(JSON.stringify(f.pushes).includes('Вымышленный'),false);
 const inbox=await(await f.op(cardio,'inbox')).json();assert.equal(inbox.items[0].id,d.id);assert.equal(inbox.items[0].openedAt,null);
 assert.equal((await f.op(icu,'open',{id:d.id})).status,403);
 const opened=await(await f.op(cardio,'open',{id:d.id})).json();assert.equal(opened.payload,null);assert.equal((await openSurname(cardio,opened.token,[contacts[4]],NOW)).surname,'Вымышленный');
 assert.equal((await f.op(cardio,'ack',{id:d.id})).status,200);assert.equal((await(await f.op(bot,'outbox')).json()).items[0].openedCount,1);
 assert.equal((await f.op(bot,'create',d)).status,200);assert.equal(f.messages.size,1);assert.equal(f.pushes.length,1);
});
test('hybrid photo/comment cannot be changed or opened by other devices',async()=>{
 const f=fixture(),meta={id:rid(),group:'orit',kind:'review',issued:NOW,expires:NOW+3600000};
 const encrypted=await sealMessage(neuro,[contacts[3]],{surname:'Пример',department:'ОРИТ',comment:'Проверка',photo:null},meta);const d={...meta,...encrypted};assert.equal((await f.op(neuro,'create',d)).status,200);
 const opened=await(await f.op(icu,'open',{id:d.id})).json();assert.equal((await openMessage(icu,opened.token,opened.payload,[contacts[1]],NOW)).comment,'Проверка');
 const tamper=structuredClone(d);tamper.id=rid();assert.equal((await f.op(neuro,'create',tamper)).status,400);
 const tamper2=structuredClone(d);tamper2.payload.ciphertext=tamper2.payload.ciphertext.replace(/^./,tamper2.payload.ciphertext[0]==='A'?'B':'A');assert.equal((await f.op(neuro,'create',tamper2)).status,403);
});
test('roles and signed recipient certifications block unauthorized senders and key substitutions',async()=>{
 const f=fixture(),d=await legacy(neuro);d.kind='admission';assert.equal((await f.op(neuro,'create',d)).status,403);
 f.roster.get(contacts[2].id).approvalProof=null;assert.equal((await f.op(bot,'create',await legacy())).status,403);assert.equal(f.messages.size,0);
});
test('revocation and expiry apply at each retrieval; enabled FaceID has server gate',async()=>{
 const f=fixture(),d=await legacy();await f.op(bot,'create',d);f.roster.get(contacts[2].id).state='revoked';assert.equal((await f.op(cardio,'open',{id:d.id})).status,403);
 f.roster.get(contacts[2].id).state='active';f.setTime(d.expires+1);assert.equal((await f.op(cardio,'open',{id:d.id})).status,404);
 const locked=fixture({unlock:false});const d2=await legacy();await locked.op(bot,'create',d2);const r=await locked.op(cardio,'open',{id:d2.id});assert.equal(r.status,428);assert.equal((await r.json()).error,'unlock_required');assert.equal(locked.audit.length,0);
});
test('failed notification keeps inbox and retries original id, never creates duplicate record',async()=>{
 const f=fixture({sendState:'failed'}),d=await legacy();const r=await(await f.op(bot,'create',d)).json();assert.equal(r.push,'queued');assert.equal(f.messages.size,1);
 const result=await(await f.op(bot,'retry')).json();assert.equal(result.queued,1);assert.equal(f.pushes.length,2);assert.equal(f.pushes[1].id,d.id);assert.equal(f.messages.size,1);
});
test('organizer signs replacement phone; replacement never decrypts old ciphertext',async()=>{
 const f=fixture(),d=await legacy(neuro,'orit');await f.op(neuro,'create',d);
 const target={...members[5],name:members[3].name,role:members[3].role};const proof=await makeRecipientGrant(admin,target,{now:NOW});
 const r=await f.op(admin,'admin_replace',{oldId:members[3].id,newId:members[5].id,approvalProof:proof});assert.equal(r.status,200);
 assert.equal((await f.op(icu,'open',{id:d.id})).status,403);assert.equal((await f.op(replacement,'open',{id:d.id})).status,403);
});
test('admin update requires signature for new role/name; normal doctors cannot manage staff',async()=>{
 const f=fixture();const data={id:members[3].id,name:'Новое имя',role:'intensivist',state:'active'};
 assert.equal((await f.op(admin,'admin_update',data)).status,403);
 data.approvalProof=await makeRecipientGrant(admin,{...members[3],name:data.name},{now:NOW});assert.equal((await f.op(neuro,'admin_update',data)).status,403);assert.equal((await f.op(admin,'admin_update',data)).status,200);
});
test('unauthenticated requests, replay, origin, body limits, private errors fail closed',async()=>{
 const f=fixture(),e=await envelope(bot,'retry');const bad={...e,op:'admin_members'};assert.equal((await f.handler(req(bad))).status,403);
 assert.equal((await f.handler(req(e,{origin:'https://wrong.example'}))).status,403);assert.equal((await f.handler(req(e))).status,200);assert.equal((await f.handler(req(e))).status,409);
 assert.equal((await f.handler(req(e,{raw:'x'.repeat(MAX_DIRECT_BODY_BYTES+1)}))).status,413);
 f.store.list=async()=>{throw Error('sensitive DB detail');};const r=await f.op(cardio,'inbox');assert.equal(r.status,503);assert.equal((await r.text()).includes('sensitive'),false);
});
