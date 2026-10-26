import test from 'node:test';
import assert from 'node:assert/strict';
import {createTeamStore,acceptTeamRequest} from './team-store.mjs';
import {createMemoryDatabase} from './test-db.mjs';
import {createHash} from 'node:crypto';

const DAY=86400000;
const id=n=>Buffer.alloc(32,n).toString('base64url');
const nonce=n=>{const bytes=Buffer.alloc(16);bytes.writeUInt32BE(n,12);return bytes.toString('base64url');};
const hash=n=>n.toString(16).padStart(64,'0');
const CARD='PSO-CARD1.'+'A'.repeat(150), SPKI='A'.repeat(122);
const token=(recipient,sender)=>`PSO1.${recipient}.${sender}.${'A'.repeat(512)}.${'A'.repeat(86)}`;
const admin=id(1), neurologist=id(2), cardio=id(3), intensive=id(4), bot=id(5);

async function fixture() {
  let clock=1700000000000;
  const now=()=>clock, db=createMemoryDatabase({now}), store=createTeamStore(db,{now});
  async function seed(deviceId,role='neurologist',state='active',extra={}) {
    await db.seed(`member:${deviceId}`,{device_id:deviceId,name:`Synthetic ${role}`,role,state,card:CARD,signing_spki:SPKI,
      invite_hash:null,created_at:now(),approved_at:state==='active'?now():null,revoked_at:null,approval_proof:null,...extra});
  }
  await seed(admin,'admin');
  return {db,store,now,seed,advance:ms=>clock+=ms};
}

test('bootstrap card only binds to separately pinned active admin; unknown devices cannot become members',async()=>{
  const {db,store,now,seed}=await fixture();
  await seed(admin,'admin','active',{card:null});
  assert.equal(await store.accept(admin,nonce(1),'status',now(),CARD,'B'.repeat(121)+'A'),'denied');
  assert.equal(db.dump().get(`member:${admin}`).card,null);
  assert.equal(await store.accept(admin,nonce(1),'status',now(),CARD,SPKI),'ok');
  assert.equal(db.dump().get(`member:${admin}`).card,CARD);
  const stranger=id(9);
  assert.equal(await store.accept(stranger,nonce(2),'status',now(),CARD,SPKI),'ok');
  assert.deepEqual(await store.status(stranger),{name:null,role:null,state:'unregistered'});
  assert.deepEqual(await store.directory(stranger),{status:'denied'});
  assert.equal(await store.approve(stranger,stranger),'denied');
  assert.equal(db.dump().has(`member:${stranger}`),false);
});

test('concurrent nonce replay is spent once and shared acceptance preserves quota counts',async()=>{
  const {db,store,now}=await fixture();
  const outcomes=await Promise.all(Array.from({length:8},()=>store.accept(admin,nonce(1),'status',now(),CARD,SPKI)));
  assert.equal(outcomes.filter(x=>x==='ok').length,1);
  assert.equal(outcomes.filter(x=>x==='replay').length,7);
  assert.equal([...db.dump()].filter(([key])=>key.startsWith('quota:team:')).every(([,v])=>v.used===1),true);
  const reused=await db.transaction(tx=>acceptTeamRequest(tx,{deviceId:admin,nonce:nonce(1),op:'status',issued:now(),card:CARD,signingSpki:SPKI},now()));
  assert.equal(reused,'replay');
});

test('clock boundaries deny stale/future acceptance and nonce expiry cannot revive stale signed request',async()=>{
  const {store,now,advance}=await fixture();
  assert.equal(await store.accept(admin,nonce(1),'status',now()-60001,CARD,SPKI),'denied');
  assert.equal(await store.accept(admin,nonce(1),'status',now()+30001,CARD,SPKI),'denied');
  const issued=now();
  assert.equal(await store.accept(admin,nonce(1),'status',issued,CARD,SPKI),'ok');
  advance(120001);
  assert.equal(await store.accept(admin,nonce(1),'status',issued,CARD,SPKI),'denied');
});

test('quota rejection creates no nonce or unbounded identity counters',async()=>{
  const {db,store,now}=await fixture();
  for(let n=1;n<=60;n++) assert.equal(await store.accept(admin,nonce(n),'status',now(),CARD,SPKI),'ok');
  assert.equal(await store.accept(admin,nonce(61),'status',now(),CARD,SPKI),'limited');
  assert.equal(db.dump().has(`nonce:team:${admin}:${nonce(61)}`),false);
  const day=Math.floor(now()/DAY), key=`quota:team:day:global:${day}`;
  await db.seed(key,{used:20000});
  const before=db.dump().size;
  assert.equal(await store.accept(id(22),nonce(90),'status',now(),CARD,SPKI),'limited');
  assert.equal(db.dump().size,before);
  assert.equal(db.dump().get(key).used,20000);
});

test('one invitation has one claimant, remains pending until admin approval, and cannot restore a revoked member',async()=>{
  const {store}=await fixture();
  assert.deepEqual(await store.invite(neurologist,hash(1),'Fixture','neurologist'),{status:'denied'});
  assert.deepEqual(await store.invite(admin,hash(1),'Fixture','admin'),{status:'invalid'});
  const invite=await store.invite(admin,hash(1),'Fixture','neurologist');
  assert.equal(invite.status,'created');
  assert.deepEqual(await store.invite(admin,hash(1),'Fixture','neurologist'),{status:'exists',expires:invite.expires});
  assert.deepEqual(await store.invite(admin,hash(1),'Changed','neurologist'),{status:'conflict'});
  const results=await Promise.all([neurologist,id(8)].map(who=>store.claim(who,hash(1),CARD,SPKI)));
  assert.deepEqual(results.sort(),['denied','pending']);
  const winner=(await store.status(neurologist)).state==='pending'?neurologist:id(8);
  assert.deepEqual(await store.directory(winner),{status:'denied'});
  assert.equal(await store.approve(winner,winner),'denied');
  assert.equal((await store.pending(admin)).members.length,1);
  assert.equal(await store.approve(admin,winner),'active');
  assert.equal(await store.claim(winner,hash(1),CARD,SPKI),'active');
  assert.equal(await store.revoke(admin,winner),'revoked');
  assert.equal(await store.claim(winner,hash(1),CARD,SPKI),'conflict');
  assert.equal(await store.approve(admin,winner),'denied');
  assert.equal(await store.revoke(admin,admin),'denied');
});

test('expired invitations and invitations from a revoked organizer fail closed',async()=>{
  const {store,advance,seed}=await fixture();
  await store.invite(admin,hash(1),'Fixture','neurologist');
  advance(2*DAY);
  assert.equal(await store.claim(neurologist,hash(1),CARD,SPKI),'denied');
  await store.invite(admin,hash(2),'Fixture','neurologist');
  await seed(admin,'admin','revoked');
  assert.equal(await store.claim(neurologist,hash(2),CARD,SPKI),'denied');
  assert.deepEqual(await store.pending(admin),{status:'denied'});
});

test('team revocation removes holder credential, pending challenges and every session atomically',async()=>{
  const {db,store,seed,now}=await fixture();
  await seed(neurologist);
  const credential='A'.repeat(32), credentialHash=createHash('sha256').update(credential).digest('hex');
  await db.seed(`authcred:${neurologist}`,{credential_id:credential});
  await db.seed(`authcredid:${credentialHash}`,{device_id:neurologist});
  await db.seed(`authchallenge:${neurologist}:unlock`,{challenge:'synthetic',expires:now()+10000});
  await db.seed(`authchallenge:${neurologist}:enroll`,{challenge:'synthetic',expires:now()+10000});
  for(const h of [hash(1),hash(2)]) {
    const session={device_id:neurologist,token_hash:h,expires:now()+10000};
    await db.seed(`authsession:${neurologist}:${h}`,session);
    await db.seed(`authtoken:${h}`,session);
  }
  assert.equal(await store.revoke(admin,neurologist),'revoked');
  const leftovers=[...db.dump().keys()].filter(key=>key.startsWith('auth'));
  assert.deepEqual(leftovers,[]);
});

test('parallel cardiologist approvals cannot allocate two active seats; two bot identities are permitted',async()=>{
  const {store,seed}=await fixture();
  await seed(cardio,'cardiologist','pending');await seed(id(6),'cardiologist','pending');
  assert.deepEqual((await Promise.all([cardio,id(6)].map(who=>store.approve(admin,who)))).sort(),['active','conflict']);
  await seed(bot,'bot','pending');await seed(id(7),'bot','pending');
  assert.deepEqual(await Promise.all([bot,id(7)].map(who=>store.approve(admin,who))),['active','active']);
});

test('cardinality bounds apply to pending enrollment and 25-seat specialist/bot approvals',async()=>{
  const {store,seed}=await fixture();
  for(let n=10;n<35;n++) await seed(id(n),'intensivist');
  await seed(intensive,'intensivist','pending');
  assert.equal(await store.approve(admin,intensive),'conflict');
  for(let n=35;n<108;n++) await seed(id(n),'neurologist');
  // admin +25 intensivists +1 pending +73 neurologists =100 total.
  assert.equal((await store.invite(admin,hash(1),'Fixture','neurologist')).status,'created');
  assert.equal(await store.claim(id(200),hash(1),CARD,SPKI),'limited');
});

test('only bots send admissions; review sender and full current recipient roster are checked atomically',async()=>{
  const {store,seed,now}=await fixture();
  await seed(neurologist);await seed(bot,'bot');await seed(cardio,'cardiologist');await seed(intensive,'intensivist');await seed(id(6),'intensivist');
  const entries=sender=>[intensive,id(6)].map(recipientId=>({recipientId,token:token(recipientId,sender)}));
  const send=(sender,kind,list=entries(sender))=>store.create(sender,hash(1),hash(9),'orit',kind,now(),now()+3600000,list);
  assert.equal(await send(neurologist,'admission'),'denied');
  assert.equal(await send(bot,'review'),'denied');
  assert.equal(await send(cardio,'review'),'denied');
  assert.equal(await send(neurologist,'review',entries(neurologist).slice(0,1)),'roster_changed');
  assert.equal(await send(neurologist,'review',[...entries(neurologist),{recipientId:cardio,token:token(cardio,neurologist)}]),'roster_changed');
  assert.equal(await send(neurologist,'review',[...entries(neurologist),entries(neurologist)[0]]),'invalid');
  assert.equal(await send(bot,'admission'),'created');
  assert.equal((await store.resolve(cardio,hash(1))).status,'denied');
  assert.equal((await store.resolve(admin,hash(1))).status,'denied');
  assert.equal((await store.resolve(intensive,hash(1))).token,token(intensive,bot));
});

test('concurrent message creates are idempotent; changed payload conflicts; revocation prevents fresh writes and reads',async()=>{
  const {db,store,seed,now,advance}=await fixture();
  await seed(neurologist);await seed(intensive,'intensivist');
  const issued=now()-120000,expires=now()+3600000, entries=[{recipientId:intensive,token:token(intensive,neurologist)}];
  const send=(h=hash(1),request=hash(2))=>store.create(neurologist,h,request,'orit','review',issued,expires,entries);
  assert.deepEqual((await Promise.all([send(),send(),send()])).sort(),['created','exists','exists']);
  assert.equal([...db.dump()].filter(([key])=>key.startsWith('quota:team:create-')).every(([,v])=>v.used===1),true);
  assert.equal(await send(hash(1),hash(3)),'conflict');
  await store.revoke(admin,intensive);
  assert.equal((await store.resolve(intensive,hash(1))).status,'denied');
  assert.equal(await send(),'exists');
  assert.equal(await send(hash(4)),'roster_changed');
  await seed(intensive,'intensivist');
  await store.revoke(admin,neurologist);
  assert.equal(await send(),'denied');
  assert.equal((await store.resolve(intensive,hash(1))).status,'ok');
  advance(3600000);
  assert.equal((await store.resolve(intensive,hash(1))).status,'missing');
});

test('team/legacy identifier collision and changed token sender are rejected',async()=>{
  const {db,store,seed,now}=await fixture();
  await seed(neurologist);await seed(intensive,'intensivist');
  await db.seed(`legacy:${hash(1)}`,{synthetic:true});
  assert.equal(await store.create(neurologist,hash(1),hash(2),'orit','review',now(),now()+10000,
    [{recipientId:intensive,token:token(intensive,neurologist)}]),'conflict');
  assert.equal(await store.create(neurologist,hash(2),hash(3),'orit','review',now(),now()+10000,
    [{recipientId:intensive,token:token(intensive,bot)}]),'invalid');
});

test('push requires recipient consent, claims once under concurrency, and gone cannot delete a replacement endpoint',async()=>{
  const {db,store,seed,now}=await fixture();
  await seed(neurologist);await seed(intensive,'intensivist');
  const expires=now()+10000;
  assert.equal(await store.create(neurologist,hash(1),hash(2),'orit','review',now(),expires,
    [{recipientId:intensive,token:token(intensive,neurologist)}]),'created');
  const subscription={device_id:intensive,endpoint_hash:hash(3),subscription:{endpoint:'https://web.push.apple.com/synthetic'},senders:[intensive],refreshed_at:now()};
  await db.seed(`pushsub:${intensive}`,subscription);
  assert.deepEqual(await store.pushClaim(neurologist,hash(1)),{targets:[]});
  await db.seed(`pushsub:${intensive}`,{...subscription,senders:[intensive,neurologist]});
  const claims=await Promise.all([store.pushClaim(neurologist,hash(1)),store.pushClaim(neurologist,hash(1))]);
  assert.deepEqual(claims.map(c=>c.targets.length).sort(),[0,1]);
  assert.equal(claims.flatMap(c=>c.targets)[0].recipientId,intensive);
  await db.seed(`pushsub:${intensive}`,{...subscription,endpoint_hash:hash(4)});
  assert.equal(await store.pushFinish(hash(1),intensive,'gone'),'ok');
  assert.equal(db.dump().get(`pushsub:${intensive}`).endpoint_hash,hash(4));
  assert.equal(await store.pushFinish(hash(1),intensive,'accepted'),'unchanged');
  assert.deepEqual(await store.pushClaim(neurologist,hash(1)),{targets:[]});
  assert.deepEqual(await store.pushClaim(bot,hash(1)),{targets:[]});
});

test('revoked sender, stale subscription or removed membership cannot emit a push',async()=>{
  const {db,store,seed,now}=await fixture();
  await seed(neurologist);await seed(intensive,'intensivist');
  await store.create(neurologist,hash(1),hash(2),'orit','review',now(),now()+10000,
    [{recipientId:intensive,token:token(intensive,neurologist)}]);
  const sub={device_id:intensive,endpoint_hash:hash(3),subscription:{endpoint:'https://web.push.apple.com/synthetic'},senders:[neurologist],refreshed_at:now()-90*DAY-1};
  await db.seed(`pushsub:${intensive}`,sub);
  await db.seed(`pushendpoint:${hash(3)}`,{device_id:intensive,refreshed_at:sub.refreshed_at});
  assert.deepEqual(await store.pushClaim(neurologist,hash(1)),{targets:[]});
  await db.seed(`pushsub:${intensive}`,{...sub,refreshed_at:now()});
  await store.revoke(admin,neurologist);
  assert.deepEqual(await store.pushClaim(neurologist,hash(1)),{targets:[]});
  await seed(neurologist);
  await store.revoke(admin,intensive);
  assert.equal(db.dump().has(`pushsub:${intensive}`),false);
  assert.equal(db.dump().has(`pushendpoint:${hash(3)}`),false);
  assert.deepEqual(await store.pushClaim(neurologist,hash(1)),{targets:[]});
});
