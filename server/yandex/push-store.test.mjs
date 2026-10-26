import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createPushStore,deletePushSubscriptionTx} from './push-store.mjs';
import {createMemoryDatabase} from './test-db.mjs';

const DAY=86400000;
const id=n=>{const bytes=Buffer.alloc(32);bytes.writeUInt32BE(n,28);return bytes.toString('base64url');};
const nonce=n=>{const bytes=Buffer.alloc(16);bytes.writeUInt32BE(n,12);return bytes.toString('base64url');};
const hash=n=>n.toString(16).padStart(64,'0');
const sha=value=>createHash('sha256').update(value).digest('hex');
const subscriber=id(1),sender=id(2),other=id(3);
const subscription=(label='first')=>({endpoint:`https://fcm.googleapis.com/fcm/send/${label}`,keys:{auth:nonce(1),p256dh:'B'+'A'.repeat(86)}});
const vapid=n=>({publicKey:'B'+'A'.repeat(86),privateKey:{kty:'EC',crv:'P-256',x:id(n),y:id(n+1),d:id(n+2),ext:true}});

function fixture() {
  let clock=1700000000000;
  const now=()=>clock,db=createMemoryDatabase({now}),store=createPushStore(db,{now});
  return {db,store,now,advance:ms=>clock+=ms};
}

test('VAPID setup is private insert-once configuration even under competing cold starts',async()=>{
  const {db,store}=fixture();
  assert.equal(await store.keys(),null);
  await assert.rejects(()=>store.keys({...vapid(1),secret:'unexpected'}));
  const candidates=[vapid(1),vapid(10)],results=await Promise.all(candidates.map(value=>store.keys(value)));
  assert.deepEqual(results[0],results[1]);
  assert.deepEqual(await store.keys({invalid:true}),results[0]);
  assert.equal([...db.dump()].filter(([key])=>key==='config:vapid').length,1);
});

test('signed push nonce replay consumes quotas once and stale signed envelopes cannot be revived',async()=>{
  const {store,db,now,advance}=fixture();
  const results=await Promise.all(Array.from({length:10},()=>store.accept(subscriber,nonce(1),'status',now())));
  assert.equal(results.filter(value=>value==='ok').length,1);
  assert.equal(results.filter(value=>value==='replay').length,9);
  assert.equal([...db.dump()].filter(([key])=>key.startsWith('quota:push:')).every(([,value])=>value.used===1),true);
  const issued=now();advance(120001);
  assert.equal(await store.accept(subscriber,nonce(1),'status',issued),'invalid');
  assert.equal(await store.accept(subscriber,nonce(2),'status',now()+30001),'invalid');
});

test('test notifications have a three per minute cap without spending rejected nonce or counters',async()=>{
  const {store,db,now}=fixture();
  for(let n=1;n<=3;n++)assert.equal(await store.accept(subscriber,nonce(n),'test',now()),'ok');
  const before=JSON.stringify([...db.dump()]);
  assert.equal(await store.accept(subscriber,nonce(4),'test',now()),'limited');
  assert.equal(JSON.stringify([...db.dump()]),before);
  assert.equal(await store.accept(subscriber,nonce(4),'status',now()),'ok');
});

test('global and device quotas reject before any write and remain independent',async()=>{
  const {store,db,now}=fixture();
  for(let n=1;n<=20;n++)assert.equal(await store.accept(subscriber,nonce(n),'status',now()),'ok');
  assert.equal(await store.accept(subscriber,nonce(21),'register',now()),'limited');
  assert.equal(await store.accept(other,nonce(21),'status',now()),'ok');
  await db.seed(`quota:push:day:global:${Math.floor(now()/DAY)}`,{used:10000});
  const before=JSON.stringify([...db.dump()]);
  assert.equal(await store.accept(id(99),nonce(22),'status',now()),'limited');
  assert.equal(JSON.stringify([...db.dump()]),before);
});

test('subscription endpoints are unique across devices; updates release only their previous endpoint',async()=>{
  const {store,db}=fixture(),first=subscription(),second=subscription('second');
  const result=await Promise.all([subscriber,other].map(owner=>store.register(owner,first,[sender,sender])));
  assert.deepEqual(result.sort(),['conflict','ok']);
  const winner=await store.status(subscriber)?subscriber:other,loser=winner===subscriber?other:subscriber;
  assert.deepEqual(db.dump().get(`pushsub:${winner}`).senders,[...new Set([winner,sender])].sort());
  assert.equal(await store.register(winner,second,[]),'ok');
  assert.equal(await store.register(loser,first,[]),'ok');
  assert.equal(db.dump().get(`pushendpoint:${sha(first.endpoint)}`).device_id,loser);
  assert.equal(await store.unregister(winner),'ok');
  assert.equal(await store.status(loser),true);
  assert.equal(db.dump().has(`pushendpoint:${sha(second.endpoint)}`),false);
});

test('subscription checks reject private hosts, credential fields, oversized allowlists and malformed keys',async()=>{
  const {store}=fixture(),sub=subscription();
  for(const endpoint of ['http://fcm.googleapis.com/x','https://127.0.0.1/x','https://fcm.googleapis.com.evil.test/x','https://fcm.googleapis.com/x#secret']) {
    assert.equal(await store.register(subscriber,{...sub,endpoint},[]),'conflict');
  }
  assert.equal(await store.register(subscriber,{...sub,secret:'patient'},[]),'conflict');
  assert.equal(await store.register(subscriber,{...sub,keys:{...sub.keys,auth:'invalid'}},[]),'conflict');
  assert.equal(await store.register(subscriber,sub,Array.from({length:100},(_,n)=>id(n+10))),'conflict');
  assert.equal(await store.status(subscriber),false);
});

test('the 500 active subscription capacity is transactional and stale subscriptions free capacity',async()=>{
  const {store,db,now,advance}=fixture();
  for(let n=1;n<=499;n++)await db.seed(`pushsub:${id(n)}`,{device_id:id(n),endpoint_hash:hash(n),subscription:subscription(`seed${n}`),senders:[id(n)],refreshed_at:now()},now()+90*DAY);
  const results=await Promise.all([id(500),id(501)].map(owner=>store.register(owner,subscription(owner),[])));
  assert.deepEqual(results.sort(),['limited','ok']);
  advance(90*DAY+1);
  assert.equal(await store.status(id(1)),false);
  assert.equal(await store.testSubscription(id(1)),null);
  assert.equal(await store.register(id(600),subscription('fresh'),[]),'ok');
});

test('revocation cleanup and gone receipts preserve a newer subscription',async()=>{
  const {store,db}=fixture(),first=subscription(),next=subscription('new');
  await store.register(subscriber,first,[]);
  await store.register(subscriber,next,[]);
  assert.equal(await db.transaction(tx=>deletePushSubscriptionTx(tx,subscriber,sha(first.endpoint))),false);
  assert.deepEqual(await store.testSubscription(subscriber),next);
  assert.equal(await db.transaction(tx=>deletePushSubscriptionTx(tx,subscriber,sha(next.endpoint))),true);
  assert.equal(await store.status(subscriber),false);
  assert.equal(db.dump().has(`pushendpoint:${sha(next.endpoint)}`),false);
});

test('legacy notify fails closed absent explicit writer, current link and recipient allowance',async()=>{
  const {store,db,now}=fixture(),token=`PSO1.${subscriber}.${sender}.ciphertext.signature`;
  await store.register(subscriber,subscription(),[]);
  await db.seed(`legacy:${hash(1)}`,{sender_id:sender,token,expires:now()+600000});
  assert.deepEqual(await store.claim(sender,hash(1)),{status:'unavailable'});
  await db.seed(`legacywriter:${sender}`,{enabled:true});
  assert.deepEqual(await store.claim(sender,hash(1)),{status:'unavailable'});
  await store.register(subscriber,subscription(),[sender]);
  const results=await Promise.all(Array.from({length:5},()=>store.claim(sender,hash(1))));
  assert.equal(results.filter(row=>row.status==='ready').length,1);
  assert.equal(results.filter(row=>row.status==='already').length,4);
  await db.seed(`legacywriter:${sender}`,{enabled:false});
  assert.deepEqual(await store.claim(sender,hash(1)),{status:'unavailable'});
});

test('legacy finish pins endpoint deletion and cannot overwrite a completed claim',async()=>{
  const {store,db,now}=fixture(),first=subscription(),replacement=subscription('replacement');
  await store.register(subscriber,first,[sender]);
  await db.seed(`legacywriter:${sender}`,{enabled:true});
  await db.seed(`legacy:${hash(1)}`,{sender_id:sender,token:`PSO1.${subscriber}.${sender}.ciphertext.signature`,expires:now()+600000});
  assert.equal((await store.claim(sender,hash(1))).status,'ready');
  await store.register(subscriber,replacement,[sender]);
  assert.equal(await store.finish(hash(1),'gone'),'ok');
  assert.deepEqual(await store.testSubscription(subscriber),replacement);
  assert.equal(await store.finish(hash(1),'failed'),'unchanged');
  assert.deepEqual(await store.claim(sender,hash(1)),{status:'gone'});
});
