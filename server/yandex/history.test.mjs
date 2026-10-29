import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto,createHash} from 'node:crypto';
import {createMemoryDatabase} from './test-db.mjs';
import {createDirectStore} from './direct-store.mjs';
import {createDirectHandler} from '../direct-handler.mjs';
import {makeDevice} from '../../docs/crypto.mjs';
import {exportPublicCard,importPublicCard,sealSurname,openSurname} from '../../docs/exchange.mjs';
import {makeRecipientGrant} from '../../docs/recipient-trust.mjs';
import {sealMessage,openMessage,openArchivedMessage} from '../../docs/messages.mjs';
import {DirectClient,directEnvelope,newMessageID} from '../../docs/direct.mjs';

if(!globalThis.crypto)globalThis.crypto=webcrypto;
const DAY=86400000,origin='https://viewer.example',endpoint=origin+'/direct';
const keys=['admin','neurologist','cardiologist','bot','colleague'];
const people=Object.fromEntries(await Promise.all(keys.map(async key=>{
  const role=key==='colleague'?'neurologist':key,device=await makeDevice();
  const card=await importPublicCard(await exportPublicCard(device,'Synthetic '+key));
  return[key,{device,contact:{...card,role,verified:true},role}];
})));
const dev=k=>people[k].device,id=k=>people[k].contact.id;
const surname='Вымыслов',comment='История содержит только вымышленный пример';
const requestHash=data=>createHash('sha256').update(JSON.stringify(data)).digest('hex');

async function fixture({withoutHistory=false}={}){
  let clock=Date.now(),unlocked=true;const now=()=>clock,db=createMemoryDatabase({now}),store=createDirectStore(db,{now});
  for(const {device,contact,role} of Object.values(people)){
    const proof=role==='admin'?null:await makeRecipientGrant(dev('admin'),contact,{now:now()});
    await db.seed('member:'+contact.id,{device_id:contact.id,name:contact.name,role,state:'active',card:contact.card,
      signing_spki:Buffer.from(await crypto.subtle.exportKey('spki',device.signing.publicKey)).toString('base64url'),
      approval_proof:proof,created_at:now(),approved_at:now(),revoked_at:null});
  }
  const sent=[],handlerStore={...store,keys:async()=>({publicKey:Buffer.alloc(65,1).toString('base64url'),privateKey:{}}),
    unlockCheck:async(actor,token)=>unlocked||token==='A'.repeat(43)};
  if(withoutHistory){delete handlerStore.history;delete handlerStore.historyOpen;}
  const handler=createDirectHandler({store:handlerStore,allowedOrigin:origin,now,send:async(subscription,keys,payload,options)=>{
    sent.push({subscription,payload,now:options.now,ttl:options.ttl});return {status:'accepted'};
  }});
  const client=new DirectClient(endpoint,{now,fetch:async(url,options)=>handler(new Request(url,{...options,headers:{...options.headers,Origin:origin}}))});
  async function request({sender='neurologist',archive=true,meta={}}={}){
    const m={id:newMessageID(),group:'cardiology',kind:'review',issued:now(),expires:now()+2*DAY,...meta};
    return {...m,...await sealMessage(dev(sender),[people.cardiologist.contact],{surname,comment},m,{archive})};
  }
  async function op(sender,data,operation='create'){const envelope=await directEnvelope(dev(sender),operation,data,now());return handler(new Request(endpoint,{method:'POST',headers:{'Content-Type':'application/json',Origin:origin},body:JSON.stringify({envelope})}));}
  async function change(key,patch){const k='member:'+id(key);await db.seed(k,{...db.dump().get(k),...patch});}
  return {now,db,store,client,request,op,change,sent,advance:ms=>clock+=ms,setNow:at=>clock=at,lock:()=>unlocked=false};
}

test('sender history keeps a self-encrypted copy and strict 48-hour recipient / 90-day archive boundaries',async()=>{
  const f=await fixture(),message=await f.request();assert.equal((await f.op('neurologist',message)).status,200);
  const item=(await f.client.history(dev('neurologist'))).items[0];
  assert.equal(item.id,message.id);assert.equal(item.hasContent,true);assert.equal(item.archiveUntil,message.issued+90*DAY);
  assert.equal(item.expires,message.issued+2*DAY);
  f.setNow(message.expires-1);
  const live=await f.client.open(dev('cardiologist'),message.id);
  assert.equal((await openMessage(dev('cardiologist'),live.token,live.payload,[people.neurologist.contact],f.now())).surname,surname);
  f.setNow(message.expires);
  assert.equal((await f.client.list(dev('cardiologist'))).items.length,0);
  await assert.rejects(f.client.open(dev('cardiologist'),message.id),e=>e.status===404);
  await assert.rejects(f.client.ack(dev('cardiologist'),message.id),e=>e.status===404);
  await assert.rejects(openMessage(dev('cardiologist'),live.token,live.payload,[people.neurologist.contact],f.now()));
  f.setNow(message.issued+90*DAY-1);
  const history=await f.client.historyOpen(dev('neurologist'),message.id);
  assert.equal(history.archiveUntil,message.issued+90*DAY);
  const plaintext=await openArchivedMessage(dev('neurologist'),history.senderToken,history.payload,f.now());
  assert.equal(plaintext.surname,surname);assert.equal(plaintext.comment,comment);
  f.setNow(message.issued+90*DAY);
  assert.deepEqual((await f.client.history(dev('neurologist'))).items,[]);
  await assert.rejects(f.client.historyOpen(dev('neurologist'),message.id),e=>e.status===404);
  await assert.rejects(openArchivedMessage(dev('neurologist'),history.senderToken,history.payload,f.now()));
});

test('history is owned by its active sender, never recipient, colleague or administrator; content requires unlock',async()=>{
  const f=await fixture(),message=await f.request();await f.op('neurologist',message);
  for(const outsider of ['admin','cardiologist','colleague','bot']){
    assert.deepEqual((await f.client.history(dev(outsider))).items,[]);
    await assert.rejects(f.client.historyOpen(dev(outsider),message.id),e=>e.status===403);
  }
  f.lock();assert.equal((await f.client.history(dev('neurologist'))).items.length,1);
  await assert.rejects(f.client.historyOpen(dev('neurologist'),message.id),e=>e.status===428);
  assert.equal((await f.client.historyOpen(dev('neurologist'),message.id,{unlockToken:'A'.repeat(43)})).meta.id,message.id);
  await f.change('neurologist',{state:'revoked'});
  await assert.rejects(f.client.history(dev('neurologist')),e=>e.status===403);
  await assert.rejects(f.client.historyOpen(dev('neurologist'),message.id,{unlockToken:'A'.repeat(43)}),e=>e.status===403);
});

test('self-token must address the sender and authenticate this exact payload; invalid requests leave no history',async()=>{
  const f=await fixture(),message=await f.request();
  const alternate=await f.request({meta:{id:message.id,issued:message.issued,expires:message.expires}});
  const foreign=await f.request({sender:'colleague',meta:{id:message.id,issued:message.issued,expires:message.expires}});
  const parts=message.senderToken.split('.'),signature=Buffer.from(parts.at(-1),'base64url');signature[0]^=1;
  parts[parts.length-1]=signature.toString('base64url');
  for(const senderToken of ['PSO2.invalid',message.entries[0].token,alternate.senderToken,foreign.senderToken,parts.join('.')]){
    assert.ok((await f.op('neurologist',{...message,senderToken})).status>=400);
    assert.deepEqual((await f.client.history(dev('neurologist'))).items,[]);
  }
  const {payload,...missing}=message;
  assert.ok((await f.op('neurologist',missing)).status>=400);
  assert.equal((await f.op('neurologist',message)).status,200);
  const serialized=JSON.stringify([...f.db.dump()]);assert.ok(!serialized.includes(surname));assert.ok(!serialized.includes(comment));
});

test('archive records immutable participant names and roles, first opening and provider-acceptance timestamps',async()=>{
  const f=await fixture();
  await f.db.seed('pushsub:'+id('cardiologist'),{refreshed_at:f.now(),endpoint_hash:'1'.repeat(64),subscription:{endpoint:'https://push.example/synthetic'}});
  const message=await f.request();assert.equal((await f.op('neurologist',message)).status,200);
  const acceptedAt=f.now();f.advance(1000);
  const first=(await f.client.ack(dev('cardiologist'),message.id)).openedAt;
  f.advance(1000);assert.equal((await f.client.ack(dev('cardiologist'),message.id)).openedAt,first);
  await f.change('cardiologist',{name:'Synthetic new name',role:'intensivist'});
  const changed={...people.neurologist.contact,name:'Synthetic new sender',role:'rehab2_physician',state:'active'};
  const approvalProof=await makeRecipientGrant(dev('admin'),changed,{now:f.now()});
  assert.deepEqual(await f.client.update(dev('admin'),{...changed,approvalProof}),{state:'active'});
  f.setNow(message.expires+1);
  const history=await f.client.historyOpen(dev('neurologist'),message.id);
  assert.equal(history.senderName,people.neurologist.contact.name);assert.equal(history.senderRole,'neurologist');
  assert.deepEqual(history.recipients,[{id:id('cardiologist'),name:people.cardiologist.contact.name,role:'cardiologist',
    openedAt:first,pushState:'accepted',pushAcceptedAt:acceptedAt}]);
  assert.equal((await f.client.history(dev('neurologist'))).items[0].openedCount,1);
  const before=JSON.stringify(history.recipients);
  assert.equal(await f.store.pushFinish(message.id,id('cardiologist'),1,'accepted'),'stale');
  assert.equal(JSON.stringify((await f.client.historyOpen(dev('neurologist'),message.id)).recipients),before);
});

test('old PSO2 clients and legacy bot have normal live delivery without archive rows or archive quota',async()=>{
  const f=await fixture(),oldClient=await f.request({archive:false});
  const bucket='directarchivebucket:'+Math.floor((f.now()+90*DAY)/DAY),quota={bytes:250000000,until:f.now()+91*DAY};
  await f.db.seed(bucket,quota,quota.until);
  const archiveRows=()=>[...f.db.dump()].filter(([key])=>key.startsWith('directarchive')||key.startsWith('directhistory:'));
  const before=archiveRows();
  assert.equal((await f.op('neurologist',oldClient)).status,200);
  const token=await sealSurname(dev('bot'),people.cardiologist.contact,surname);
  const legacy={id:newMessageID(),group:'cardiology',kind:'admission',issued:f.now(),expires:f.now()+DAY,entries:[{recipientId:id('cardiologist'),token}]};
  assert.equal((await f.op('bot',legacy)).status,200);
  for(const [actor,message] of [['neurologist',oldClient],['bot',legacy]]){
    assert.deepEqual((await f.client.history(dev(actor))).items,[]);
    await assert.rejects(f.client.historyOpen(dev(actor),message.id),e=>e.status===404);
    assert.equal((await f.client.list(dev(actor),'outbox')).items[0].id,message.id);
  }
  const oldLive=await f.client.open(dev('cardiologist'),oldClient.id);
  assert.equal((await openMessage(dev('cardiologist'),oldLive.token,oldLive.payload,[people.neurologist.contact],f.now())).surname,surname);
  const botLive=await f.client.open(dev('cardiologist'),legacy.id);
  assert.equal((await openSurname(dev('cardiologist'),botLive.token,[people.bot.contact],f.now())).surname,surname);
  assert.deepEqual(archiveRows(),before);
  const archived=await f.request(),full=await f.op('neurologist',archived);
  assert.equal(full.status,429);assert.equal((await full.json()).error,'history_full');
  f.advance(3*DAY);
  for(const [actor,message] of [['neurologist',oldClient],['bot',legacy]]){
    assert.deepEqual((await f.client.history(dev(actor))).items,[]);
    await assert.rejects(f.client.historyOpen(dev(actor),message.id),e=>e.status===404);
    await assert.rejects(f.client.open(dev('cardiologist'),message.id),e=>e.status===404);
  }
  assert.deepEqual(archiveRows(),before);
});

test('retained history prevents conflicting reuse of a message ID after live delivery records expire',async()=>{
  const f=await fixture(),message=await f.request();
  assert.equal((await f.op('neurologist',message)).status,200);
  assert.equal((await f.op('neurologist',message)).status,200);
  f.setNow(message.expires+1);
  const fresh={...message,issued:f.now(),expires:f.now()+2*DAY};
  assert.equal(await f.store.create(id('neurologist'),requestHash(fresh),fresh),'conflict');
  const history=await f.client.history(dev('neurologist'));assert.equal(history.items.length,1);
  assert.equal(history.items[0].issued,message.issued);assert.equal(history.items[0].archiveUntil,message.issued+90*DAY);
});

test('history pagination is stable for expired encrypted deliveries and never mixes sender histories',async t=>{
  const f=await fixture(),messages=[];
  t.mock.method(Date,'now',f.now);
  for(let n=0;n<55;n++){
    if(n&&n%25===0)f.advance(DAY);
    const message=await f.request();assert.equal((await f.op('neurologist',message)).status,200);messages.push(message);
    f.advance(1000);
  }
  f.advance(3*DAY);
  const first=await f.client.history(dev('neurologist'));assert.equal(first.items.length,50);assert.ok(first.next);
  const second=await f.client.history(dev('neurologist'),first.next);assert.equal(second.items.length,5);assert.equal(second.next,null);
  const expected=messages.sort((a,b)=>b.issued-a.issued||(a.id<b.id?1:a.id>b.id?-1:0)).map(m=>m.id);
  assert.deepEqual([...first.items,...second.items].map(m=>m.id),expected);
  assert.deepEqual((await f.client.history(dev('colleague'))).items,[]);
  assert.ok([...first.items,...second.items].every(m=>m.hasContent));
});

test('opening sender history neither acknowledges recipients nor creates notifications or delivery queue entries',async()=>{
  const f=await fixture();
  await f.db.seed('pushsub:'+id('cardiologist'),{refreshed_at:f.now(),endpoint_hash:'1'.repeat(64),subscription:{endpoint:'https://push.example/synthetic'}});
  const message=await f.request();assert.equal((await f.op('neurologist',message)).status,200);
  const deliveryRows=()=>[...f.db.dump()].filter(([key])=>/^direct(?:entry:|msg:|archive:|push:)/.test(key));
  const before=deliveryRows();assert.equal(f.sent.length,1);
  for(let n=0;n<2;n++){
    const history=await f.client.historyOpen(dev('neurologist'),message.id);
    assert.equal((await openArchivedMessage(dev('neurologist'),history.senderToken,history.payload,f.now())).surname,surname);
    assert.equal(history.recipients[0].openedAt,null);
    assert.equal((await f.client.history(dev('neurologist'))).items[0].openedCount,0);
  }
  assert.deepEqual(deliveryRows(),before);assert.equal(f.sent.length,1);
});

test('replacement phone cannot inherit the original sender archive or decrypt its self-token',async()=>{
  const f=await fixture(),message=await f.request();assert.equal((await f.op('neurologist',message)).status,200);
  const archive=await f.client.historyOpen(dev('neurologist'),message.id);
  await f.change('colleague',{state:'pending',approval_proof:null});
  const replacement={...people.colleague.contact,name:people.neurologist.contact.name,role:'neurologist'};
  const proof=await makeRecipientGrant(dev('admin'),replacement,{now:f.now()});
  assert.deepEqual(await f.client.replace(dev('admin'),id('neurologist'),id('colleague'),proof),{state:'active'});
  assert.deepEqual((await f.client.history(dev('colleague'))).items,[]);
  await assert.rejects(f.client.historyOpen(dev('colleague'),message.id),e=>e.status===403);
  await assert.rejects(f.client.history(dev('neurologist')),e=>e.status===403);
  await assert.rejects(openArchivedMessage(dev('colleague'),archive.senderToken,archive.payload,f.now()));
});

test('first push for a sender clock ten seconds ahead is accepted with a server-bounded 48-hour lifetime',async()=>{
  const f=await fixture();
  await f.db.seed('pushsub:'+id('cardiologist'),{refreshed_at:f.now(),endpoint_hash:'1'.repeat(64),subscription:{endpoint:'https://push.example/synthetic'}});
  const issued=f.now()+10000,message=await f.request({meta:{issued,expires:issued+2*DAY}}),response=await f.op('neurologist',message);
  assert.equal(response.status,200);assert.equal((await response.json()).push,'accepted');assert.equal(f.sent.length,1);
  const push=f.sent[0];assert.equal(push.payload.id,message.id);assert.equal(push.payload.expires,f.now()+2*DAY);
  assert.equal(push.now,f.now());assert.equal(push.ttl,172800);
  const history=await f.client.historyOpen(dev('neurologist'),message.id);
  assert.equal(history.meta.expires,message.expires);
  assert.equal(history.recipients[0].pushState,'accepted');assert.equal(history.recipients[0].pushAcceptedAt,f.now());
});

test('legacy store without archive methods still serves existing routes and reports history unavailable',async()=>{
  const f=await fixture({withoutHistory:true}),message=await f.request({archive:false});
  assert.equal((await f.op('neurologist',message)).status,200);
  assert.ok((await f.client.directory(dev('neurologist'))).some(member=>member.id===id('cardiologist')));
  assert.equal((await f.client.open(dev('cardiologist'),message.id)).meta.id,message.id);
  const archived=await f.request(),response=await f.op('neurologist',archived);
  assert.equal(response.status,503);assert.deepEqual(await response.json(),{error:'history_unavailable'});
  assert.equal(f.db.dump().has('directmsg:'+archived.id),false,'an old store cannot silently discard an explicitly requested sender archive');
  await assert.rejects(f.client.history(dev('neurologist')),e=>e.status===503);
  await assert.rejects(f.client.historyOpen(dev('neurologist'),message.id),e=>e.status===503);
  for(const [operation,data] of [['history',{}],['history_open',{id:message.id}]]){
    const response=await f.op('neurologist',data,operation);
    assert.equal(response.status,503);assert.deepEqual(await response.json(),{error:'history_unavailable'});
  }
});
