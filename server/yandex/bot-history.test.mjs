import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {createMemoryDatabase} from './test-db.mjs';
import {createDirectStore} from './direct-store.mjs';
import {createDirectHandler} from '../direct-handler.mjs';
import {makeDevice} from '../../docs/crypto.mjs';
import {exportPublicCard,importPublicCard,sealSurname,openSurname} from '../../docs/exchange.mjs';
import {makeRecipientGrant} from '../../docs/recipient-trust.mjs';
import {sealMessage,openBotArchivedMessage} from '../../docs/messages.mjs';
import {DirectClient,directEnvelope,newMessageID} from '../../docs/direct.mjs';
import {sealBoundBotToken} from '../../tests/helpers/bot-token.mjs';

if(!globalThis.crypto)globalThis.crypto=webcrypto;
const DAY=86400000,origin='https://viewer.example',endpoint=origin+'/direct',surname='Вымыслов';
const roles={admin:'admin',otheradmin:'admin',neurologist:'neurologist',cardiologist:'cardiologist',intensivist:'intensivist',intensivist2:'intensivist',bot:'bot',otherbot:'bot'};
const people=Object.fromEntries(await Promise.all(Object.entries(roles).map(async([key,role])=>{
  const device=await makeDevice(),card=await importPublicCard(await exportPublicCard(device,'Synthetic '+key));
  return[key,{device,contact:{...card,role,verified:true},role}];
})));
const dev=key=>people[key].device,id=key=>people[key].contact.id;

async function fixture({botGrantTTL=365*DAY}={}){
  let clock=Date.now(),unlocked=true;const now=()=>clock,db=createMemoryDatabase({now}),store=createDirectStore(db,{now});
  for(const [key,{device,contact,role}] of Object.entries(people)){
    const issuer=key==='otherbot'?'otheradmin':'admin';
    const proof=role==='admin'?null:await makeRecipientGrant(dev(issuer),contact,{now:now(),ttlMs:role==='bot'?botGrantTTL:365*DAY});
    await db.seed('member:'+contact.id,{device_id:contact.id,name:contact.name,role,state:'active',card:contact.card,
      signing_spki:Buffer.from(await crypto.subtle.exportKey('spki',device.signing.publicKey)).toString('base64url'),
      approval_proof:proof,created_at:now(),approved_at:now(),revoked_at:null});
  }
  async function root(key){await db.seed('config:organizer',{device_id:id(key),card:people[key].contact.card});}
  await root('admin');
  const sent=[],handler=createDirectHandler({store:{...store,
    keys:async()=>({publicKey:Buffer.alloc(65,1).toString('base64url'),privateKey:{}}),
    unlockCheck:async(actor,token)=>unlocked||token==='A'.repeat(43)},allowedOrigin:origin,now,
    send:async(subscription,keys,payload,options)=>{sent.push({subscription,payload,now:options.now});return {status:'accepted'};}});
  const client=new DirectClient(endpoint,{now,fetch:async(url,options)=>handler(new Request(url,{...options,headers:{...options.headers,Origin:origin}}))});
  async function op(sender,data,operation='create'){
    const envelope=await directEnvelope(dev(sender),operation,data,now());
    return handler(new Request(endpoint,{method:'POST',headers:{'Content-Type':'application/json',Origin:origin},body:JSON.stringify({envelope})}));
  }
  async function message({sender='bot',organizer='admin',group='cardiology',meta={}}={}){
    const m={id:newMessageID(),group,kind:'admission',issued:now(),expires:now()+2*DAY,...meta};
    const targets=m.group==='orit'?['intensivist','intensivist2']:['cardiologist'];
    const entries=await Promise.all(targets.map(async key=>({recipientId:id(key),token:await sealBoundBotToken(dev(sender),people[key].contact,m,{surname})})));
    const organizerToken=await sealBoundBotToken(dev(sender),people[organizer].contact,m,{surname});
    return {...m,entries,organizerId:id(organizer),organizerToken};
  }
  async function manual(){
    const m={id:newMessageID(),group:'cardiology',kind:'review',issued:now(),expires:now()+2*DAY};
    return {...m,...await sealMessage(dev('admin'),[people.cardiologist.contact],{surname,comment:'Вымышленный пример'},m,{archive:true})};
  }
  async function change(key,patch){const k='member:'+id(key);await db.seed(k,{...db.dump().get(k),...patch});}
  async function subscription(key){await db.seed('pushsub:'+id(key),{refreshed_at:now(),endpoint_hash:'1'.repeat(64),subscription:{endpoint:'https://push.example/'+key}});}
  const archivePlain=(actor,record)=>openBotArchivedMessage(dev(actor),record.organizerToken,record.meta,
    {...record.sender,role:record.senderRole,approvalProof:record.senderApprovalProof,verified:true},now());
  return {now,db,store,client,op,message,manual,change,subscription,root,archivePlain,sent,
    advance:ms=>clock+=ms,setNow:at=>clock=at,lock:()=>unlocked=false};
}

test('bot sends bound 48-hour recipient messages and an organizer-only copy retained for exactly 90 days',async()=>{
  const f=await fixture({botGrantTTL:DAY}),message=await f.message({group:'orit'});
  assert.equal((await f.op('bot',message)).status,200);
  const page=await f.client.botHistory(dev('admin'));
  assert.equal(page.items.length,1);assert.equal(page.items[0].id,message.id);assert.equal(page.items[0].hasContent,true);
  assert.equal(page.items[0].recipientCount,2);assert.equal(page.items[0].archiveUntil,message.issued+90*DAY);
  assert.deepEqual((await f.client.history(dev('admin'))).items,[]);
  assert.deepEqual((await f.client.list(dev('admin'))).items,[]);
  f.setNow(message.expires-1);
  for(const key of ['intensivist','intensivist2']){
    const live=await f.client.open(dev(key),message.id);
    const value=await openSurname(dev(key),live.token,[people.bot.contact],f.now());
    assert.equal(value.surname,surname);assert.equal(value.messageId,message.id);assert.equal(value.group,'orit');
    assert.equal(value.expires,message.expires);
  }
  f.setNow(message.expires);
  for(const key of ['intensivist','intensivist2']){
    assert.deepEqual((await f.client.list(dev(key))).items,[]);
    await assert.rejects(f.client.open(dev(key),message.id),e=>e.status===404);
    await assert.rejects(f.client.ack(dev(key),message.id),e=>e.status===404);
    await assert.rejects(openSurname(dev(key),message.entries.find(e=>e.recipientId===id(key)).token,[people.bot.contact],f.now()));
  }
  f.setNow(message.issued+90*DAY-1);
  const archive=await f.client.historyOpen(dev('admin'),message.id);
  assert.equal(archive.senderRole,'bot');assert.equal(archive.payload,null);assert.equal(archive.senderToken,null);
  assert.equal(archive.organizerToken,message.organizerToken);
  assert.equal((await f.archivePlain('admin',archive)).surname,surname);
  assert.ok(!JSON.stringify([...f.db.dump()]).includes(surname));
  f.setNow(message.issued+90*DAY);
  assert.deepEqual((await f.client.botHistory(dev('admin'))).items,[]);
  await assert.rejects(f.client.historyOpen(dev('admin'),message.id),e=>e.status===404);
  await assert.rejects(f.archivePlain('admin',archive));
});

test('manual and bot sources remain separate and a later organizer cannot inherit the original archive',async()=>{
  const f=await fixture(),bot=await f.message(),manual=await f.manual();
  assert.equal((await f.op('bot',bot)).status,200);assert.equal((await f.op('admin',manual)).status,200);
  await f.root('otheradmin');
  const other=await f.message({sender:'otherbot',organizer:'otheradmin'});
  assert.equal((await f.op('otherbot',other)).status,200);
  assert.deepEqual((await f.client.history(dev('admin'))).items.map(m=>m.id),[manual.id]);
  assert.deepEqual((await f.client.botHistory(dev('admin'))).items.map(m=>m.id),[bot.id]);
  assert.deepEqual((await f.client.botHistory(dev('otheradmin'))).items.map(m=>m.id),[other.id]);
  assert.equal((await f.archivePlain('admin',await f.client.historyOpen(dev('admin'),bot.id))).surname,surname);
  await assert.rejects(f.client.historyOpen(dev('otheradmin'),bot.id),e=>e.status===403);
  await assert.rejects(f.client.historyOpen(dev('admin'),other.id),e=>e.status===403);
  const manualArchive=await f.client.historyOpen(dev('admin'),manual.id);
  assert.equal(manualArchive.organizerToken,null);assert.equal(manualArchive.senderApprovalProof,null);
  for(const key of ['bot','otherbot','neurologist','cardiologist']){
    await assert.rejects(f.client.botHistory(dev(key)),e=>e.status===403);
    await assert.rejects(f.client.historyOpen(dev(key),bot.id),e=>e.status===403);
  }
});

test('bot archive requires the pinned active organizer, matching bot grant issuer and signed recipient-bound token',async()=>{
  const f=await fixture(),message=await f.message(),other=await f.message({organizer:'otheradmin'});
  const parts=message.organizerToken.split('.'),signature=Buffer.from(parts.at(-1),'base64url');signature[0]^=1;parts[parts.length-1]=signature.toString('base64url');
  const {organizerId,...missingId}=message,{organizerToken,...missingToken}=message;
  const foreignToken=await sealBoundBotToken(dev('neurologist'),people.admin.contact,message,{surname});
  const invalid=[other,missingId,missingToken,{...message,organizerId:id('otheradmin')},
    {...message,organizerToken:message.entries[0].token},{...message,organizerToken:foreignToken},{...message,organizerToken:parts.join('.')},
    {...message,organizerToken:'PSO1.invalid'}];
  for(const value of invalid){
    const response=await f.op('bot',value);assert.ok(response.status>=400&&response.status<500);
    assert.deepEqual((await f.client.botHistory(dev('admin'))).items,[]);
  }
  const human=await f.message({sender:'neurologist'});
  assert.equal((await f.op('neurologist',human)).status,403);
  await f.root('otheradmin');assert.equal((await f.op('bot',message)).status,403);
  await f.db.transaction(tx=>tx.delete('config:organizer'));assert.equal((await f.op('bot',message)).status,403);
  await f.root('admin');await f.change('admin',{state:'revoked'});
  assert.equal((await f.op('bot',message)).status,403);
  const deliveryKeys=[...f.db.dump().keys()].filter(key=>/^direct(?:msg:|entry:|in:|out:|archive:|history:|bothistory:|quota:|push:)/.test(key));
  assert.deepEqual(deliveryKeys,[]);
});

test('organizer archive content requires unlock and current administrator access',async()=>{
  const f=await fixture(),message=await f.message();assert.equal((await f.op('bot',message)).status,200);
  f.lock();assert.equal((await f.client.botHistory(dev('admin'))).items.length,1);
  await assert.rejects(f.client.historyOpen(dev('admin'),message.id),e=>e.status===428);
  assert.equal((await f.client.historyOpen(dev('admin'),message.id,{unlockToken:'A'.repeat(43)})).meta.id,message.id);
  await f.change('admin',{role:'neurologist'});
  await assert.rejects(f.client.botHistory(dev('admin')),e=>e.status===403);
  await assert.rejects(f.client.historyOpen(dev('admin'),message.id,{unlockToken:'A'.repeat(43)}),e=>e.status===403);
  await f.change('admin',{role:'admin',state:'revoked'});
  await assert.rejects(f.client.botHistory(dev('admin')),e=>e.status===403);
  await assert.rejects(f.client.historyOpen(dev('admin'),message.id,{unlockToken:'A'.repeat(43)}),e=>e.status===403);
});

test('new bot archive is atomic when full while legacy bot delivery bypasses the archive budget',async()=>{
  const f=await fixture(),message=await f.message();
  const key='directarchivebucket:'+Math.floor((f.now()+90*DAY)/DAY),quota={bytes:250000000,until:f.now()+91*DAY};
  await f.db.seed(key,quota,quota.until);
  const response=await f.op('bot',message);assert.equal(response.status,429);assert.deepEqual(await response.json(),{error:'history_full'});
  assert.deepEqual((await f.client.list(dev('cardiologist'))).items,[]);
  assert.deepEqual((await f.client.botHistory(dev('admin'))).items,[]);
  const deliveryKeys=[...f.db.dump().keys()].filter(key=>/^direct(?:msg:|entry:|in:|out:|archive:|history:|bothistory:|quota:|push:)/.test(key));
  assert.deepEqual(deliveryKeys,[]);
  const token=await sealSurname(dev('bot'),people.cardiologist.contact,surname);
  const legacy={id:newMessageID(),group:'cardiology',kind:'admission',issued:f.now(),expires:f.now()+DAY,entries:[{recipientId:id('cardiologist'),token}]};
  assert.equal((await f.op('bot',legacy)).status,200);
  const live=await f.client.open(dev('cardiologist'),legacy.id);
  assert.equal((await openSurname(dev('cardiologist'),live.token,[people.bot.contact],f.now())).surname,surname);
  assert.deepEqual((await f.client.botHistory(dev('admin'))).items,[]);
  await assert.rejects(f.client.historyOpen(dev('admin'),legacy.id),e=>e.status===404);
  assert.deepEqual(f.db.dump().get(key),quota);
});

test('bot archive keeps original approvals, participant snapshots and first receipts despite later bot changes',async()=>{
  const f=await fixture({botGrantTTL:DAY});await f.subscription('cardiologist');
  const message=await f.message(),created=f.now();assert.equal((await f.op('bot',message)).status,200);
  assert.equal(f.sent.length,1);f.advance(1000);
  const first=(await f.client.ack(dev('cardiologist'),message.id)).openedAt;
  f.advance(1000);assert.equal((await f.client.ack(dev('cardiologist'),message.id)).openedAt,first);
  const captured=f.db.dump().get('member:'+id('bot')).approval_proof;
  const newProof=await makeRecipientGrant(dev('otheradmin'),people.bot.contact,{now:f.now()});
  await f.change('bot',{name:'Synthetic changed bot',role:'neurologist',approval_proof:newProof,state:'revoked'});
  await f.change('cardiologist',{name:'Synthetic renamed recipient',role:'intensivist'});
  f.setNow(message.expires+1);
  const archive=await f.client.historyOpen(dev('admin'),message.id);
  assert.equal(archive.senderName,people.bot.contact.name);assert.equal(archive.senderRole,'bot');
  assert.deepEqual(archive.senderApprovalProof,captured);
  assert.deepEqual(archive.recipients,[{id:id('cardiologist'),name:people.cardiologist.contact.name,role:'cardiologist',
    openedAt:first,pushState:'accepted',pushAcceptedAt:created}]);
  assert.equal((await f.archivePlain('admin',archive)).surname,surname);
  assert.equal((await f.client.botHistory(dev('admin'))).items[0].openedCount,1);
  const archiveRows=()=>[...f.db.dump()].filter(([key])=>/^direct(?:archive:|push:|entry:)/.test(key)),before=archiveRows();
  await f.client.historyOpen(dev('admin'),message.id);
  assert.deepEqual(archiveRows(),before);assert.equal(f.sent.length,1);
});

test('bot create replay is idempotent and the retained archive blocks ID reuse after recipient expiry',async()=>{
  const f=await fixture();await f.subscription('cardiologist');const message=await f.message();
  assert.equal((await f.op('bot',message)).status,200);assert.equal((await f.op('bot',message)).status,200);
  assert.equal(f.sent.length,1);assert.equal((await f.client.botHistory(dev('admin'))).items.length,1);
  f.setNow(message.expires+1);
  const reused=await f.message({meta:{id:message.id}}),response=await f.op('bot',reused);
  assert.equal(response.status,409);assert.deepEqual(await response.json(),{error:'id_conflict'});
  const archive=await f.client.historyOpen(dev('admin'),message.id);
  assert.equal(archive.meta.issued,message.issued);assert.equal(archive.archiveUntil,message.issued+90*DAY);
  assert.equal(archive.organizerToken,message.organizerToken);assert.equal(f.sent.length,1);
});

test('recertified renamed bot can retry saved content but cannot create a new archive before its current approval',async()=>{
  const f=await fixture(),message=await f.message();assert.equal((await f.op('bot',message)).status,200);
  const original=await f.client.historyOpen(dev('admin'),message.id);
  f.advance(31000);
  const renamed={...people.bot.contact,name:'Synthetic recertified bot'};
  const proof=await makeRecipientGrant(dev('admin'),renamed,{now:f.now()});
  await f.change('bot',{name:renamed.name,approval_proof:proof});
  assert.equal((await f.op('bot',message)).status,200);
  const archive=await f.client.historyOpen(dev('admin'),message.id);
  assert.equal(archive.senderName,original.senderName);assert.deepEqual(archive.senderApprovalProof,original.senderApprovalProof);
  assert.equal(archive.organizerToken,original.organizerToken);
  const backdated=await f.message({meta:{issued:message.issued,expires:message.expires}});
  assert.equal((await f.op('bot',backdated)).status,403);
  assert.equal((await f.client.botHistory(dev('admin'))).items.length,1);
});

test('bot source pagination remains stable after live expiry and rejects unrecognized source flags',async()=>{
  const f=await fixture(),messages=[];
  for(let n=0;n<55;n++){
    const message=await f.message();assert.equal((await f.op('bot',message)).status,200);messages.push(message);f.advance(1);
  }
  f.advance(3*DAY);
  const first=await f.client.botHistory(dev('admin'));assert.equal(first.items.length,50);assert.ok(first.next);
  const second=await f.client.botHistory(dev('admin'),first.next);assert.equal(second.items.length,5);assert.equal(second.next,null);
  const expected=messages.sort((a,b)=>b.issued-a.issued||(a.id<b.id?1:a.id>b.id?-1:0)).map(m=>m.id);
  assert.deepEqual([...first.items,...second.items].map(m=>m.id),expected);
  assert.deepEqual((await f.client.history(dev('admin'))).items,[]);
  assert.deepEqual((await f.client.botHistory(dev('otheradmin'))).items,[]);
  for(const source of ['manual','other',false,null])assert.equal((await f.op('admin',{source},'history')).status,400);
  assert.equal((await f.op('admin',{source:'bot',extra:true},'history')).status,400);
  assert.equal((await f.op('admin',{id:messages[0].id,source:'bot'},'history_open')).status,400);
});
