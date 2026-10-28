import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {createMemoryDatabase} from './test-db.mjs';
import {createDirectStore} from './direct-store.mjs';
import {createDirectHandler} from '../direct-handler.mjs';
import {makeDevice} from '../../docs/crypto.mjs';
import {exportPublicCard,importPublicCard} from '../../docs/exchange.mjs';
import {makeRecipientGrant} from '../../docs/recipient-trust.mjs';
import {sealMessage,openMessage} from '../../docs/messages.mjs';
import {DirectClient,directEnvelope,newMessageID} from '../../docs/direct.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const roles=['admin','neurologist','cardiologist','intensivist','bot'];
const people=Object.fromEntries(await Promise.all(roles.map(async role=>{
  const device=await makeDevice(),card=await importPublicCard(await exportPublicCard(device,'Synthetic '+role));
  return [role,{device,contact:{...card,role,verified:true},role}];
})));
const origin='https://viewer.example',endpoint=origin+'/direct';
async function fixture(){
  let clock=Date.now();const now=()=>clock,db=createMemoryDatabase({now}),store=createDirectStore(db,{now});
  for(const {device,contact,role} of Object.values(people)){
    const proof=role==='admin'?null:await makeRecipientGrant(people.admin.device,contact,{now:now()});
    await db.seed('member:'+contact.id,{device_id:contact.id,name:contact.name,role,state:'active',card:contact.card,
      signing_spki:Buffer.from(await crypto.subtle.exportKey('spki',device.signing.publicKey)).toString('base64url'),
      approval_proof:proof,created_at:now(),approved_at:now(),revoked_at:null});
  }
  let unlocked=true;
  const handler=createDirectHandler({store:{...store,keys:async()=>null,unlockCheck:async()=>unlocked},allowedOrigin:origin,now});
  const client=new DirectClient(endpoint,{now,fetch:async(url,options)=>handler(new Request(url,{...options,headers:{...options.headers,Origin:origin}}))});
  async function request(sender,recipients,patch={}){
    const meta={id:newMessageID(),group:'cardiology',kind:'review',issued:now(),expires:now()+3600000,...patch};
    return {...meta,...await sealMessage(people[sender].device,recipients.map(r=>people[r].contact),{comment:'Synthetic encrypted content'},meta)};
  }
  async function op(sender,data){const envelope=await directEnvelope(people[sender].device,'create',data,now());return handler(new Request(endpoint,{method:'POST',headers:{'Content-Type':'application/json',Origin:origin},body:JSON.stringify({envelope})}));}
  async function change(role,patch){const key='member:'+people[role].contact.id;await db.seed(key,{...db.dump().get(key),...patch});}
  return {now,db,store,client,request,op,change,advance:ms=>clock+=ms,lock:()=>unlocked=false};
}
const dev=r=>people[r].device,id=r=>people[r].contact.id;

test('cardiologist and intensivist reply privately; neurologist can open and answer; group rights stay unchanged',async()=>{
  for(const [specialist,group] of [['cardiologist','cardiology'],['intensivist','orit']]){
    const f=await fixture(),parent=await f.request('neurologist',[specialist],{group});
    assert.equal((await f.op('neurologist',parent)).status,200);
    const reply=await f.request(specialist,['neurologist'],{group,kind:'reply',replyTo:parent.id});
    assert.equal((await f.op(specialist,reply)).status,200);
    const inbox=await f.client.list(dev('neurologist'));assert.deepEqual(inbox.items.map(m=>m.id),[reply.id]);
    const opened=await f.client.open(dev('neurologist'),reply.id);assert.equal(opened.meta.replyTo,parent.id);
    const body=await openMessage(dev('neurologist'),opened.token,opened.payload,[people[specialist].contact]);
    assert.equal(body.comment,'Synthetic encrypted content');assert.equal(body.replyTo,parent.id);
    assert.equal((await f.client.ack(dev('neurologist'),reply.id)).openedAt,f.now());
    assert.equal((await f.client.list(dev(specialist),'outbox')).items[0].openedCount,1);
    assert.equal((await f.client.list(dev('admin'))).items.length,0);
    await assert.rejects(f.client.open(dev('admin'),reply.id),e=>e.status===403);
    await assert.rejects(f.client.open(dev('neurologist'),parent.id),e=>e.status===403);
    const back=await f.request('neurologist',[specialist],{group,kind:'reply',replyTo:reply.id});
    assert.equal((await f.op('neurologist',back)).status,200);
    assert.equal((await f.client.open(dev(specialist),back.id)).meta.replyTo,reply.id);
    assert.equal((await f.op(specialist,await f.request(specialist,[specialist],{group}))).status,403);
    f.lock();await assert.rejects(f.client.open(dev('neurologist'),reply.id),e=>e.status===428);
  }
});

test('reply binds exact parent sender, rejects outsider, wrong group, bot, revoked and expired parents',async()=>{
  const f=await fixture(),parent=await f.request('neurologist',['cardiologist']);await f.op('neurologist',parent);
  const base={kind:'reply',replyTo:parent.id};
  assert.equal((await f.op('intensivist',await f.request('intensivist',['neurologist'],base))).status,403);
  assert.equal((await f.op('cardiologist',await f.request('cardiologist',['admin'],base))).status,409);
  assert.equal((await f.op('cardiologist',await f.request('cardiologist',['neurologist','admin'],base))).status,409);
  assert.equal((await f.op('cardiologist',await f.request('cardiologist',['neurologist'],{...base,group:'orit'}))).status,403);
  const reply=await f.request('cardiologist',['neurologist'],base);
  assert.equal((await f.op('cardiologist',{...reply,replyTo:newMessageID()})).status,400);
  assert.equal((await f.op('cardiologist',{...reply,payload:{...reply.payload,replyTo:newMessageID()}})).status,400);
  const admissionMeta={id:newMessageID(),group:'cardiology',kind:'admission',issued:f.now(),expires:f.now()+3600000};
  const admission={...admissionMeta,...await sealMessage(dev('bot'),[people.cardiologist.contact],{surname:'Тестов'},admissionMeta)};
  assert.equal((await f.op('bot',admission)).status,200);
  assert.equal((await f.op('cardiologist',await f.request('cardiologist',['bot'],{kind:'reply',replyTo:admission.id}))).status,403);
  await f.change('neurologist',{state:'revoked'});assert.equal((await f.op('cardiologist',reply)).status,403);
  await f.change('neurologist',{state:'active'});await f.change('cardiologist',{state:'revoked'});assert.equal((await f.op('cardiologist',reply)).status,403);
  await f.change('cardiologist',{state:'active'});f.advance(3600001);
  const fresh={...reply,issued:f.now(),expires:f.now()+60000,payload:{...reply.payload,issued:f.now(),expires:f.now()+60000}};
  // Store checks parent TTL atomically; HTTP signature validation is covered above.
  assert.equal(await f.store.create(id('cardiologist'),'0'.repeat(64),fresh),'missing');
});

test('reply retries are idempotent and notifications only target original human sender',async()=>{
  const f=await fixture(),parent=await f.request('admin',['cardiologist']);await f.op('admin',parent);
  const reply=await f.request('cardiologist',['admin'],{kind:'reply',replyTo:parent.id});
  assert.equal((await f.op('cardiologist',reply)).status,200);assert.equal((await f.op('cardiologist',reply)).status,200);
  assert.equal((await f.client.list(dev('admin'))).items.length,1);
  assert.equal((await f.client.open(dev('admin'),reply.id)).senderRole,'cardiologist');
  await f.db.seed('pushsub:'+id('admin'),{refreshed_at:f.now(),endpoint_hash:'1'.repeat(64),subscription:{endpoint:'https://push.example/synthetic'}});
  f.advance(30001);
  assert.deepEqual((await f.store.pushClaim(id('neurologist'),reply.id)).targets,[]);
  const claimed=(await f.store.pushClaim(id('cardiologist'),reply.id)).targets;assert.equal(claimed.length,1);assert.equal(claimed[0].recipientId,id('admin'));
  assert.ok(!JSON.stringify([...f.db.dump()]).includes('Synthetic encrypted content'));
  await f.change('admin',{role:'neurologist'});
  assert.equal((await f.client.list(dev('admin'))).items.length,0);
  await assert.rejects(f.client.open(dev('admin'),reply.id),e=>e.status===403);
});

test('reply to one intensivist never becomes a group broadcast and cannot be forged by a colleague',async()=>{
  const f=await fixture(),otherDevice=await makeDevice(),other={...await importPublicCard(await exportPublicCard(otherDevice,'Synthetic colleague')),role:'intensivist',verified:true};
  const proof=await makeRecipientGrant(dev('admin'),other,{now:f.now()});
  await f.db.seed('member:'+other.id,{device_id:other.id,name:other.name,role:other.role,state:'active',card:other.card,
    signing_spki:Buffer.from(await crypto.subtle.exportKey('spki',otherDevice.signing.publicKey)).toString('base64url'),
    approval_proof:proof,created_at:f.now(),approved_at:f.now(),revoked_at:null});
  const meta={id:newMessageID(),group:'orit',kind:'review',issued:f.now(),expires:f.now()+3600000};
  const parent={...meta,...await sealMessage(dev('neurologist'),[people.intensivist.contact,other],{comment:'Group synthetic'},meta)};
  assert.equal((await f.op('neurologist',parent)).status,200);
  const reply=await f.request('intensivist',['neurologist'],{group:'orit',kind:'reply',replyTo:parent.id});
  assert.equal((await f.op('intensivist',reply)).status,200);
  const back=await f.request('neurologist',['intensivist'],{group:'orit',kind:'reply',replyTo:reply.id});
  assert.equal((await f.op('neurologist',back)).status,200);
  assert.deepEqual((await f.client.list(otherDevice)).items.map(m=>m.id),[parent.id]);
  await assert.rejects(f.client.open(otherDevice,back.id),e=>e.status===403);
  const forgedMeta={id:newMessageID(),group:'orit',kind:'reply',replyTo:back.id,issued:f.now(),expires:f.now()+3600000};
  const forged={...forgedMeta,...await sealMessage(otherDevice,[people.neurologist.contact],{comment:'Unauthorized'},forgedMeta)};
  await assert.rejects(f.client.create(otherDevice,forged),e=>e.status===403);
});

test('an acknowledged retry remains idempotent after its parent expires; a new reply fails',async()=>{
  const f=await fixture(),parent=await f.request('neurologist',['cardiologist'],{expires:f.now()+60000});
  assert.equal((await f.op('neurologist',parent)).status,200);
  const reply=await f.request('cardiologist',['neurologist'],{kind:'reply',replyTo:parent.id});
  assert.equal((await f.op('cardiologist',reply)).status,200);
  f.advance(60001);
  assert.equal((await f.op('cardiologist',reply)).status,200);
  assert.equal((await f.client.list(dev('neurologist'))).items.length,1);
  const fresh={...reply,id:newMessageID()};
  assert.equal(await f.store.create(id('cardiologist'),'0'.repeat(64),fresh),'missing');
});
