import test from 'node:test';
import assert from 'node:assert/strict';
import { createDirectStore } from './direct-store.mjs';
import { createMemoryDatabase } from './test-db.mjs';
import { createDeviceAuthStore } from './device-auth-store.mjs';

const DAY = 86400000, START = 1792915200000;
const id = n => Buffer.alloc(32,n).toString('base64url');
const mid = n => Buffer.alloc(16,n).toString('base64url');
const ADMIN=id(1),BOT=id(2),NEURO=id(3),CARDIO=id(4),ICU=id(5),ICU2=id(6),NEW=id(7);
const card = `PSO-CARD1.${'A'.repeat(120)}`, spki = Buffer.alloc(91,1).toString('base64url');
const proof = (subjectId,name,role,expires=START+2*DAY) => ({grant:{subjectId,name,role,issuerId:ADMIN,expires},signature:'test-public-signature'});
const member = (device_id,role,state='active') => ({device_id,name:`Doctor ${device_id.slice(0,4)}`,role,state,card,signing_spki:spki,created_at:START-1000,approved_at:START-500,revoked_at:null,approval_proof:role === 'admin' ? null : proof(device_id,`Doctor ${device_id.slice(0,4)}`,role)});
const hash = n => Number(n).toString(16).padStart(64,'0');

async function fixture() {
  let clock = START;
  const db = createMemoryDatabase({now:() => clock});
  for (const [device,role] of [[ADMIN,'admin'],[BOT,'bot'],[NEURO,'neurologist'],[CARDIO,'cardiologist'],[ICU,'intensivist']]) await db.seed(`member:${device}`,member(device,role));
  const store = createDirectStore(db,{now:() => clock});
  const data = (n,{sender=BOT,group='cardiology',kind='admission',recipients=group === 'cardiology' ? [CARDIO] : [ICU],ttl=DAY,payload=false,issued=clock}={}) => ({id:mid(n),group,kind,issued,expires:issued+ttl,
    entries:recipients.map(recipientId => ({recipientId,token:`PSO${payload ? 2 : 1}.${recipientId}.${sender}.ciphertext.signature`})),
    ...(payload ? {payload:{ciphertext:'X'.repeat(1024),id:mid(n)}} : {})});
  return {db,store,data,now:() => clock,setNow:value => { clock=value; },advance:delta => { clock+=delta; }};
}

test('create is idempotent, checks sender permission and rejects conflicting identifiers',async () => {
  const f = await fixture(), data = f.data(1);
  assert.equal(await f.store.create(BOT,hash(1),data),'created');
  assert.equal(await f.store.create(BOT,hash(1),data),'exists');
  assert.equal(await f.store.create(BOT,hash(2),data),'conflict');
  assert.equal(await f.store.create(NEURO,hash(3),f.data(2,{sender:NEURO})),'denied');
  assert.equal(await f.store.create(NEURO,hash(4),f.data(3,{sender:NEURO,kind:'review'})),'created');
  assert.equal(await f.store.create(BOT,hash(5),f.data(4,{kind:'review'})),'denied');
  assert.equal([...f.db.dump()].filter(([key]) => key.startsWith('directmsg:')).length,2);
});

test('create atomically rechecks exact current recipient roster and grant bindings',async () => {
  const f = await fixture(), oldRoster = f.data(1,{group:'orit'});
  await f.db.seed(`member:${ICU2}`,member(ICU2,'intensivist'));
  assert.equal(await f.store.create(BOT,hash(1),oldRoster),'roster_changed');
  assert.equal(await f.store.create(BOT,hash(1),f.data(1,{group:'orit',recipients:[ICU,ICU2]})),'created');
  const changed = member(CARDIO,'cardiologist'); changed.name='Renamed';
  await f.db.seed(`member:${CARDIO}`,changed);
  assert.equal(await f.store.create(BOT,hash(2),f.data(2)),'denied');
  changed.approval_proof=proof(CARDIO,changed.name,changed.role,START);
  await f.db.seed(`member:${CARDIO}`,changed);
  assert.equal(await f.store.create(BOT,hash(2),f.data(2)),'denied');
});

test('revoked grant issuer and invalid ciphertext routing fail closed',async () => {
  const f = await fixture(), wrong = f.data(1);
  wrong.entries[0].token=`PSO1.${ICU}.${BOT}.ciphertext.signature`;
  assert.equal(await f.store.create(BOT,hash(1),wrong),'invalid');
  await f.db.seed(`member:${ADMIN}`,member(ADMIN,'admin','revoked'));
  assert.equal(await f.store.create(BOT,hash(2),f.data(2)),'denied');
});

test('only bound active signed device requests consume shared nonce protection',async () => {
  const f = await fixture();
  assert.equal(await f.store.accept(CARDIO,mid(10),'open',START,card,spki),'ok');
  assert.equal(await f.store.accept(CARDIO,mid(10),'inbox',START,card,spki),'replay');
  assert.equal(await f.store.accept(CARDIO,mid(11),'open',START,card,'wrong-key'),'denied');
  assert.equal(await f.store.accept(NEW,mid(12),'open',START,card,spki),'denied');
  assert.equal(await f.store.accept(CARDIO,mid(13),'unsupported',START,card,spki),'denied');
});

test('inbox pagination follows issued and ID descending without duplicates',async () => {
  const f = await fixture();
  for (let n=1;n<=55;n++) assert.equal(await f.store.create(BOT,hash(n),f.data(n)),'created');
  const expected = Array.from({length:55},(_,n) => mid(n+1)).sort().reverse();
  const first = await f.store.list(CARDIO,false);
  assert.equal(first.items.length,50); assert.ok(first.next);
  const second = await f.store.list(CARDIO,false,first.next);
  assert.equal(second.items.length,5); assert.equal(second.next,null);
  assert.deepEqual([...first.items,...second.items].map(m => m.id),expected);
  assert.equal((await f.store.list(BOT,true)).items.length,50);
  assert.equal((await f.store.list(ICU,false)).items.length,0);
  assert.deepEqual(await f.store.list(CARDIO,false,{id:'bad',issued:1}),{status:'invalid'});
});

test('open is recipient-only; concurrent acknowledgement increments receipt once',async () => {
  const f = await fixture(), data = f.data(1);
  await f.store.create(BOT,hash(1),data);
  assert.deepEqual(await f.store.open(ICU,data.id),{status:'denied'});
  assert.deepEqual(await f.store.open(BOT,data.id),{status:'denied'});
  const opened = await f.store.open(CARDIO,data.id);
  assert.equal(opened.token,data.entries[0].token); assert.equal(opened.payload,null);
  const receipts = await Promise.all([f.store.open(CARDIO,data.id,true),f.store.open(CARDIO,data.id,true)]);
  assert.deepEqual(receipts,[{openedAt:START},{openedAt:START}]);
  f.advance(1000);
  assert.deepEqual(await f.store.open(CARDIO,data.id,true),{openedAt:START});
  assert.equal((await f.store.list(BOT,true)).items[0].openedCount,1);
});

test('current recipient role, revocation and expiry block access',async () => {
  const f = await fixture(), data = f.data(1,{ttl:10000,payload:true});
  await f.store.create(BOT,hash(1),data);
  await f.db.seed(`member:${CARDIO}`,member(CARDIO,'neurologist'));
  assert.deepEqual(await f.store.open(CARDIO,data.id),{status:'denied'});
  assert.equal((await f.store.list(CARDIO,false)).items.length,0);
  await f.db.seed(`member:${CARDIO}`,member(CARDIO,'cardiologist','revoked'));
  assert.deepEqual(await f.store.list(CARDIO,false),{status:'denied'});
  await f.db.seed(`member:${CARDIO}`,member(CARDIO,'cardiologist'));
  f.advance(10000);
  assert.deepEqual(await f.store.open(CARDIO,data.id),{status:'missing'});
  assert.equal((await f.store.list(CARDIO,false)).items.length,0);
  assert.equal(f.db.dump().has(`directpayload:${data.id}`),false);
  assert.equal(f.db.dump().has(`directmsg:${data.id}`),false);
});

test('phone replacement revokes old device and never copies old ciphertext to new key',async () => {
  const f = await fixture(), data = f.data(1);
  await f.store.create(BOT,hash(1),data);
  await f.db.seed(`member:${NEW}`,member(NEW,'cardiologist','pending'));
  await f.db.seed(`pushsub:${CARDIO}`,{device_id:CARDIO,endpoint_hash:hash(5),subscription:{endpoint:'old'},refreshed_at:START,senders:[BOT]});
  await f.db.seed(`pushendpoint:${hash(5)}`,{device_id:CARDIO});
  const auth = createDeviceAuthStore(f.db,{now:f.now});
  assert.equal(await auth.enroll(CARDIO,{id:'credential1234567',publicKey:'A'.repeat(64),counter:0,transports:['internal']},hash(99),START+600000),'ok');
  await f.db.seed(`authchallenge:${CARDIO}:unlock`,{challenge:'A'.repeat(43),expires:START+300000});
  const prior = f.db.dump().get(`member:${CARDIO}`);
  assert.deepEqual(await f.store.replace(ADMIN,CARDIO,NEW,proof(NEW,prior.name,prior.role)),{state:'active'});
  assert.deepEqual(await f.store.open(CARDIO,data.id),{status:'denied'});
  assert.deepEqual(await f.store.open(NEW,data.id),{status:'denied'});
  assert.equal(f.db.dump().has(`pushsub:${CARDIO}`),false);
  assert.equal(f.db.dump().has(`pushendpoint:${hash(5)}`),false);
  assert.equal([...f.db.dump()].some(([key]) => key.startsWith('authcred:') || key.startsWith('authcredid:') || key.startsWith('authchallenge:') || key.startsWith('authsession:') || key.startsWith('authtoken:')),false);
  assert.equal(await f.store.create(BOT,hash(2),f.data(2)),'roster_changed');
  assert.equal(await f.store.create(BOT,hash(2),f.data(2,{recipients:[NEW]})),'created');
  assert.equal((await f.store.open(NEW,mid(2))).token.includes(NEW),true);
});

test('admin mutations enforce issuer binding and current role capacity',async () => {
  const f = await fixture(), old = f.db.dump().get(`member:${ICU}`);
  assert.deepEqual(await f.store.certify(NEURO,ICU,proof(ICU,old.name,old.role)),{status:'denied'});
  assert.deepEqual(await f.store.certify(ADMIN,ICU,proof(ICU,'Wrong',old.role)),{status:'invalid'});
  assert.deepEqual(await f.store.certify(ADMIN,ICU,proof(ICU,old.name,old.role)),{state:'active'});
  assert.deepEqual(await f.store.update(ADMIN,ICU,old.name,'cardiologist','active',proof(ICU,old.name,'cardiologist')),{status:'conflict'});
  assert.deepEqual(await f.store.update(ADMIN,ICU,old.name,old.role,'revoked'),{state:'revoked'});
  assert.equal(f.db.dump().get(`member:${ICU}`).approval_proof,null);
  assert.deepEqual(await f.store.members(ICU),{status:'denied'});
  assert.equal((await f.store.members(ADMIN)).members.length,5);
});

test('photo payload is separate from every scanned index and quota is rolling-day',async () => {
  const f = await fixture();
  for (let n=1;n<=30;n++) assert.equal(await f.store.create(NEURO,hash(n),f.data(n,{sender:NEURO,kind:'review',payload:true,ttl:60000})),'created');
  assert.equal(await f.store.create(NEURO,hash(31),f.data(31,{sender:NEURO,kind:'review',payload:true})),'limited');
  const rows = f.db.dump();
  for (const [key,value] of rows) if (!key.startsWith('directpayload:')) assert.equal(JSON.stringify(value).includes('X'.repeat(100)),false,key);
  assert.equal((await f.store.open(CARDIO,mid(1))).payload.ciphertext.length,1024);
  f.advance(60001); // ciphertext expiry does not reset daily photo cap
  assert.equal(await f.store.create(NEURO,hash(31),f.data(31,{sender:NEURO,kind:'review',payload:true})),'limited');
  f.advance(DAY);
  assert.equal(await f.store.create(NEURO,hash(31),f.data(31,{sender:NEURO,kind:'review',payload:true})),'created');
});

test('concurrent creates cannot exceed sender rolling quota',async () => {
  const f = await fixture();
  await f.db.transaction(async tx => {
    for (let n=0;n<499;n++) await tx.put(`directquota:sender:${BOT}:${String(n).padStart(4,'0')}`,{created_at:START,expires:START+DAY,payload_bytes:0},START+DAY);
  });
  const results = await Promise.all([f.store.create(BOT,hash(1),f.data(1)),f.store.create(BOT,hash(2),f.data(2))]);
  assert.deepEqual(results.sort(),['created','limited']);
});

async function subscribe(f,device=CARDIO,endpointHash=hash(10)) {
  await f.db.seed(`pushsub:${device}`,{device_id:device,endpoint_hash:endpointHash,subscription:{endpoint:`https://push.example/${endpointHash}`},senders:[BOT,NEURO],refreshed_at:f.now()},f.now()+90*DAY);
}

test('push claims are exclusive, lease expiry retries and stale completion cannot win',async () => {
  const f = await fixture(); await subscribe(f);
  await f.store.create(BOT,hash(1),f.data(1));
  const claims = await Promise.all([f.store.pushClaim(BOT),f.store.pushClaim(BOT)]);
  assert.deepEqual(claims.map(c => c.targets.length).sort(),[0,1]);
  assert.equal(claims.flatMap(c => c.targets)[0].lease,1);
  f.advance(60000);
  const retry = await f.store.pushClaim(BOT);
  assert.equal(retry.targets[0].lease,2);
  assert.equal(await f.store.pushFinish(mid(1),CARDIO,1,'accepted'),'stale');
  assert.equal(await f.store.pushFinish(mid(1),CARDIO,2,'accepted'),'ok');
  f.advance(120000);
  assert.equal((await f.store.pushClaim(BOT)).targets.length,0);
});

test('gone completion preserves a newly registered push endpoint',async () => {
  const f = await fixture(); await subscribe(f);
  await f.store.create(BOT,hash(1),f.data(1)); await f.store.pushClaim(BOT);
  await subscribe(f,CARDIO,hash(11));
  assert.equal(await f.store.pushFinish(mid(1),CARDIO,1,'gone'),'ok');
  assert.equal(f.db.dump().get(`pushsub:${CARDIO}`).endpoint_hash,hash(11));
  f.advance(60000);
  assert.equal((await f.store.pushClaim(BOT)).targets[0].lease,2);
  assert.equal(await f.store.pushFinish(mid(1),CARDIO,2,'gone'),'ok');
  assert.equal(f.db.dump().has(`pushsub:${CARDIO}`),false);
});

test('push retries respect backoff, cap eight attempts and current authorization',async () => {
  const f = await fixture(); await subscribe(f);
  await f.store.create(BOT,hash(1),f.data(1));
  assert.equal((await f.store.pushClaim(NEURO)).targets.length,0);
  await f.db.seed(`member:${CARDIO}`,member(CARDIO,'neurologist'));
  assert.equal((await f.store.pushClaim(BOT)).targets.length,0);
  await f.db.seed(`member:${CARDIO}`,member(CARDIO,'cardiologist'));
  f.advance(30000); // ineligible devices are deferred without spending an attempt
  for (let n=1;n<=8;n++) {
    const target = (await f.store.pushClaim(BOT)).targets[0]; assert.equal(target.lease,n);
    assert.equal(await f.store.pushFinish(mid(1),CARDIO,n,'failed'),'ok');
    assert.equal((await f.store.pushClaim(BOT)).targets.length,0);
    f.advance(Math.min(3600000,30000*2**Math.min(n,6)));
  }
  assert.equal((await f.store.pushClaim(BOT)).targets.length,0);
});

test('push batch leaves remaining recipients queued and never scans payload data',async () => {
  const f = await fixture(); await subscribe(f);
  for (let n=1;n<=21;n++) assert.equal(await f.store.create(BOT,hash(n),f.data(n,{payload:true})),'created');
  assert.equal((await f.store.pushClaim(BOT)).targets.length,20);
  assert.equal((await f.store.pushClaim(BOT)).targets.length,1);
  const queue = [...f.db.dump()].filter(([key]) => key.startsWith('directpush:'));
  assert.equal(queue.length,63);
  assert.ok(queue.every(([,value]) => Object.keys(value).sort().join(',') === 'message_id,recipient_id,sender_id'));
});

test('bounded push scan makes durable progress past missing subscriptions',async () => {
  const f = await fixture();
  for (let n=1;n<=100;n++) { await f.store.create(BOT,hash(n),f.data(n)); f.advance(1); }
  await subscribe(f,ICU);
  await f.store.create(BOT,hash(101),f.data(101,{group:'orit'}));
  const originalTransaction=f.db.transaction.bind(f.db); let operations=0;
  f.db.transaction=callback=>originalTransaction(tx=>callback(new Proxy(tx,{get(target,property){return(...args)=>{operations++;return target[property](...args);};}})));
  assert.equal((await f.store.pushClaim(BOT)).targets.length,0);
  assert.ok(operations<400,`bounded operations: ${operations}`);
  f.db.transaction=originalTransaction;
  const deferred = [...f.db.dump()].filter(([key,value]) => key.startsWith('directentry:') && value.recipient_id===CARDIO && value.next_attempt>0);
  assert.equal(deferred.length,32);
  assert.ok(deferred.every(([,value]) => value.next_attempt===f.now()+30000 && value.push_attempts===0));
  assert.equal((await f.store.pushClaim(BOT)).targets.length,0);
  assert.equal((await f.store.pushClaim(BOT)).targets.length,0);
  const next = await f.store.pushClaim(BOT);
  assert.equal(next.targets.length,1);
  assert.equal(next.targets[0].id,mid(101));
  assert.equal(next.targets[0].recipientId,ICU);
  assert.equal(next.targets[0].lease,1);
});

test('another doctor cannot delay someone else\'s message-filtered push queue',async () => {
  const f = await fixture();
  await f.store.create(BOT,hash(1),f.data(1));
  assert.equal((await f.store.pushClaim(NEURO,mid(1))).targets.length,0);
  assert.equal(f.db.dump().get(`directentry:${mid(1)}:${CARDIO}`).next_attempt,0);
});
