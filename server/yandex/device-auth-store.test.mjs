import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createDeviceAuthStore,revokeDeviceAuthTx,unlockCheckTx} from './device-auth-store.mjs';
import {createTeamStore} from './team-store.mjs';
import {createMemoryDatabase} from './test-db.mjs';

const id=n=>Buffer.alloc(32,n).toString('base64url');
const nonce=n=>Buffer.alloc(16,n).toString('base64url');
const sha=value=>createHash('sha256').update(value).digest('hex');
const credential=(n=1,counter=0)=>({id:Buffer.alloc(32,n).toString('base64url'),publicKey:Buffer.alloc(64,n).toString('base64url'),counter,transports:['internal']});
const CARD='PSO-CARD1.'+'A'.repeat(150), SPKI='A'.repeat(122), challenge='A'.repeat(43);
const admin=id(1), doctor=id(2), other=id(3), bot=id(4);

async function fixture() {
  let clock=1700000000000;
  const now=()=>clock,db=createMemoryDatabase({now}),store=createDeviceAuthStore(db,{now});
  async function seed(deviceId,role='neurologist',state='active') {
    await db.seed(`member:${deviceId}`,{device_id:deviceId,role,state,card:CARD,signing_spki:SPKI});
  }
  await seed(admin,'admin'); await seed(doctor); await seed(other); await seed(bot,'bot');
  return {db,store,now,seed,advance:ms=>clock+=ms};
}

test('auth acceptance shares team nonce space and refuses inactive devices or unpinned signing keys',async()=>{
  const {db,store,now,seed}=await fixture(),team=createTeamStore(db,{now});
  assert.equal(await team.accept(doctor,nonce(1),'status',now(),CARD,SPKI),'ok');
  assert.equal(await store.accept(doctor,nonce(1),now(),CARD,SPKI),'conflict');
  assert.equal(await store.accept(doctor,nonce(2),now(),CARD,'B'.repeat(121)+'A'),'denied');
  assert.equal(await store.accept(bot,nonce(3),now(),CARD,SPKI),'denied');
  await seed(other,'neurologist','revoked');
  assert.equal(await store.accept(other,nonce(4),now(),CARD,SPKI),'denied');
  assert.equal(await store.accept(doctor,nonce(5),now(),CARD,SPKI),'ok');
});

test('enrollment and unlock challenge state is bounded, purpose-bound, and consumed once under concurrency',async()=>{
  const {store,now}=await fixture();
  assert.equal(await store.challengePut(doctor,'unlock',challenge,now()+1000),'conflict');
  assert.equal(await store.challengePut(doctor,'enroll',challenge,now()+300001),'denied');
  assert.equal(await store.challengePut(doctor,'enroll',challenge,now()+300000),'ok');
  assert.equal(await store.challengeTake(doctor,'unlock'),null);
  const results=await Promise.all(Array.from({length:8},()=>store.challengeTake(doctor,'enroll')));
  assert.equal(results.filter(value=>value===challenge).length,1);
  assert.equal(results.filter(value=>value===null).length,7);
});

test('expired challenge is never returned even before physical TTL deletion',async()=>{
  const {db,store,now,advance}=await fixture();
  await db.seed(`authchallenge:${doctor}:enroll`,{challenge,expires:now()+1});
  advance(2);
  assert.equal(await store.challengeTake(doctor,'enroll'),null);
  assert.equal(db.dump().has(`authchallenge:${doctor}:enroll`),false);
});

test('credential ownership and enrollment session are atomic across devices',async()=>{
  const {db,store,now}=await fixture(),c=credential();
  const result=await Promise.all([doctor,other].map((owner,n)=>store.enroll(owner,c,sha(id(n+10)),now()+600000)));
  assert.deepEqual(result.sort(),['conflict','ok']);
  const winner=(await store.status(doctor)).enabled?doctor:other,loser=winner===doctor?other:doctor;
  assert.deepEqual(await store.credential(winner),c);
  assert.equal(await store.credential(loser),null);
  assert.equal([...db.dump()].filter(([key])=>key.startsWith('authsession:')).length,1);
  assert.equal(await store.enroll(loser,credential(8),sha(id(30)),now()+600001),'denied');
  assert.equal(await store.enroll(loser,{...credential(8),patient:'not allowed'},sha(id(30)),now()+5000),'denied');
});

test('counter advances once under concurrent unlock, invalidates old sessions, and rejects rollback',async()=>{
  const {store,now}=await fixture(),c=credential(1,4),oldToken=id(10),newTokens=[id(11),id(12)];
  assert.equal(await store.enroll(doctor,c,sha(oldToken),now()+600000),'ok');
  assert.equal(await store.unlockCheck(doctor,oldToken),true);
  const results=await Promise.all(newTokens.map(token=>store.unlock(doctor,c.id,4,5,sha(token),now()+600000)));
  assert.deepEqual(results.sort(),['conflict','ok']);
  assert.equal(await store.unlockCheck(doctor,oldToken),false);
  assert.equal((await Promise.all(newTokens.map(token=>store.unlockCheck(doctor,token)))).filter(Boolean).length,1);
  assert.equal(await store.unlock(doctor,c.id,5,4,sha(id(15)),now()+600000),'conflict');
  assert.equal(await store.unlock(doctor,c.id,5,5,sha(id(15)),now()+600000),'conflict');
  assert.equal((await store.credential(doctor)).counter,5);
});

test('zero counters supported by synced passkeys still rotate the sole usable session',async()=>{
  const {store,now}=await fixture(),c=credential(),first=id(10),second=id(11);
  assert.equal(await store.enroll(doctor,c,sha(first),now()+600000),'ok');
  assert.equal(await store.unlock(doctor,c.id,0,0,sha(second),now()+600000),'ok');
  assert.equal(await store.unlockCheck(doctor,first),false);
  assert.equal(await store.unlockCheck(doctor,second),true);
});

test('session stores only a hash of the UTF-8 token and expires at verification time',async()=>{
  const {db,store,now,advance,seed}=await fixture(),token=id(12);
  assert.equal(await store.unlockCheck(doctor,''),true);
  assert.equal(await store.unlockCheck(bot,''),false);
  await store.enroll(doctor,credential(),sha(token),now()+1000);
  assert.equal(JSON.stringify([...db.dump()]).includes(token),false);
  assert.equal(await store.unlockCheck(doctor,token),true);
  assert.equal(await store.unlockCheck(other,token),true); // Other device has not enabled holder verification.
  await store.enroll(other,credential(3),sha(id(15)),now()+1000);
  assert.equal(await store.unlockCheck(other,token),false);
  assert.equal(await db.transaction(tx=>unlockCheckTx(tx,doctor,token,now()+1000)),false);
  advance(1000);
  assert.equal(await store.unlockCheck(doctor,token),false);
  await seed(doctor,'neurologist','revoked');
  assert.equal(await store.status(doctor),null);
  assert.equal(await store.credential(doctor),null);
});

test('reset requires current verified organizer session, cannot be invoked by a doctor or reset a bot',async()=>{
  const {db,store,now}=await fixture(),adminToken=id(20),doctorToken=id(21);
  await store.enroll(admin,credential(8),sha(adminToken),now()+600000);
  await store.enroll(doctor,credential(9),sha(doctorToken),now()+600000);
  await store.challengePut(doctor,'unlock',challenge,now()+300000);
  assert.equal(await store.reset(doctor,other,doctorToken),'denied');
  assert.equal(await store.reset(admin,doctor,''),'locked');
  assert.equal(await store.reset(admin,bot,adminToken),'denied');
  assert.equal(await store.reset(admin,doctor,adminToken),'ok');
  assert.deepEqual(await store.status(doctor),{enabled:false});
  assert.equal(await store.challengeTake(doctor,'unlock'),null);
  assert.equal([...db.dump()].some(([key])=>key.startsWith(`authsession:${doctor}:`)),false);
  assert.equal(db.dump().has(`authtoken:${sha(doctorToken)}`),false);
  // Released credential ownership can be enrolled on the replacement phone.
  assert.equal(await store.enroll(other,credential(9),sha(id(22)),now()+600000),'ok');
});

test('revoke helper deletes authentication and owner indexes without touching another device',async()=>{
  const {db,store,now}=await fixture(),token=id(13);
  await store.enroll(doctor,credential(2),sha(token),now()+600000);
  await store.enroll(other,credential(3),sha(id(14)),now()+600000);
  await store.challengePut(doctor,'unlock',challenge,now()+300000);
  await db.transaction(tx=>revokeDeviceAuthTx(tx,doctor));
  assert.equal(db.dump().has(`authcred:${doctor}`),false);
  assert.equal(db.dump().has(`authcredid:${sha(credential(2).id)}`),false);
  assert.equal(db.dump().has(`authtoken:${sha(token)}`),false);
  assert.equal((await store.status(other)).enabled,true);
});
