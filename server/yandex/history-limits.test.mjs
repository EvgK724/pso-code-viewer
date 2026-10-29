import test from 'node:test';
import assert from 'node:assert/strict';
import {createMemoryDatabase} from './test-db.mjs';
import {createDirectStore} from './direct-store.mjs';
const DAY=86400000,START=1792915200000;
const id=n=>Buffer.alloc(32,n).toString('base64url'),mid=n=>Buffer.alloc(16,n).toString('base64url');
const ADMIN=id(1),NEURO=id(2),ICU=id(3),spki=Buffer.alloc(91,1).toString('base64url');
const card='PSO-CARD1.'+'A'.repeat(120);
const member=(n,role)=>({device_id:id(n),name:'Synthetic',role,state:'active',card,signing_spki:spki,approval_proof:role==='admin'?null:{grant:{subjectId:id(n),issuerId:ADMIN,name:'Synthetic',role,expires:START+100*DAY}}});
async function fixture(){
 let clock=START;const now=()=>clock,db=createMemoryDatabase({now});
 for(const [n,role] of [[1,'admin'],[2,'neurologist'],[3,'intensivist']])await db.seed('member:'+id(n),member(n,role));
 const store=createDirectStore(db,{now});
 const data=(n,{sender=ADMIN,ttl=2*DAY,archive=true,recipients=[ICU]}={})=>({id:mid(n),group:'orit',kind:'review',issued:clock,expires:clock+ttl,
  entries:recipients.map(recipientId=>({recipientId,token:`PSO2.${recipientId}.${sender}.cipher.hash.signature`})),
  payload:{ciphertext:'encrypted',id:mid(n)},...(archive?{senderToken:`PSO2.${sender}.${sender}.cipher.hash.signature`}:{})});
 return {db,store,data,now,setNow:v=>clock=v};
}

test('archive capacity rejects atomically with history_full and cannot silently drop sender history',async()=>{
 const f=await fixture(),expiry=START+90*DAY,bucket=Math.floor(expiry/DAY),key='directarchivebucket:'+bucket;
 await f.db.seed(key,{bytes:250000000,until:(bucket+1)*DAY},(bucket+1)*DAY);
 const before=f.db.dump(),request=f.data(1);
 assert.equal(await f.store.create(ADMIN,'a'.repeat(64),request),'history_full');
 assert.deepEqual(f.db.dump(),before);
 await f.db.seed(key,{bytes:249000000,until:(bucket+1)*DAY},(bucket+1)*DAY);
 assert.equal(await f.store.create(ADMIN,'a'.repeat(64),request),'created');
 const used=f.db.dump().get(key).bytes;assert.ok(used>249000000&&used<250000000);
 assert.equal(await f.store.create(ADMIN,'a'.repeat(64),request),'exists');
 assert.equal(f.db.dump().get(key).bytes,used,'retries never charge history twice');
});

test('daily send quota stays 24 hours while archive accounting and owner history retain 90 days',async()=>{
 const f=await fixture(),request=f.data(1);assert.equal(await f.store.create(ADMIN,'a'.repeat(64),request),'created');
 f.setNow(START+3*DAY);
 const dump=f.db.dump();assert.equal([...dump.keys()].filter(k=>k.startsWith('directquota:')).length,0);
 assert.ok(dump.has('directarchive:'+request.id));assert.ok(dump.has('directpayload:'+request.id));
 assert.equal((await f.store.history(ADMIN)).items.length,1);
 assert.equal(await f.store.create(ADMIN,'a'.repeat(64),request),'exists','known original retry is not created anew after live expiry');
 assert.equal(await f.store.create(ADMIN,'b'.repeat(64),f.data(1)),'conflict','old ID cannot be reused with new dates');
 f.setNow(START+90*DAY);
 assert.equal((await f.store.history(ADMIN)).items.length,0);assert.deepEqual(await f.store.historyOpen(ADMIN,request.id),{status:'missing'});
 assert.ok(!f.db.dump().has('directpayload:'+request.id));
});

test('legacy sends bypass full archive quota and preserve only original live delivery records',async()=>{
 const f=await fixture(),request=f.data(1,{archive:false}),until=START+91*DAY;
 await f.db.seed('directarchivebucket:full',{bytes:250000000,until},until);
 assert.equal(await f.store.create(ADMIN,'a'.repeat(64),request),'created');
 assert.deepEqual((await f.store.history(ADMIN)).items,[]);
 assert.deepEqual(await f.store.historyOpen(ADMIN,request.id),{status:'missing'});
 assert.ok(f.db.dump().has('directpayload:'+request.id));
 assert.ok(f.db.dump().has('directmsg:'+request.id));
 assert.deepEqual(f.db.dump().get('directarchivebucket:full'),{bytes:250000000,until});
 f.setNow(START+2*DAY);
 assert.equal(f.db.dump().has('directpayload:'+request.id),false);
 assert.deepEqual((await f.store.history(ADMIN)).items,[]);
});

test('daily encrypted-byte cap rejects before delivery or archive writes without limiting payload-free legacy sends',async()=>{
 const f=await fixture(),until=START+DAY,BOT=id(4);
 await f.db.seed('member:'+BOT,member(4,'bot'));
 await f.db.seed('directquota:sender:'+ADMIN+':existing',{created_at:START,expires:until,payload_bytes:45000000},until);
 await f.db.seed('directquota:sender:'+BOT+':existing',{created_at:START,expires:until,payload_bytes:45000000},until);
 const before=f.db.dump(),request=f.data(1);
 assert.equal(await f.store.create(ADMIN,'a'.repeat(64),request),'limited');
 assert.deepEqual(f.db.dump(),before);
 const old=f.data(2,{archive:false,sender:BOT});delete old.payload;old.kind='admission';
 old.entries=old.entries.map(e=>({...e,token:`PSO1.${e.recipientId}.${BOT}.cipher.signature`}));
 assert.equal(await f.store.create(BOT,'b'.repeat(64),old),'created');
 assert.equal(f.db.dump().has('directarchive:'+old.id),false);
});

test('worst-size recipient history create and push claims fit bounded YDB operation budget',async()=>{
 const f=await fixture(),recipients=[];
 for(let n=10;n<35;n++){const rid=id(n);recipients.push(rid);await f.db.seed('member:'+rid,member(n,'intensivist'));
  await f.db.seed('pushsub:'+rid,{refreshed_at:START,endpoint_hash:'a'.repeat(64),subscription:{endpoint:'https://push.example/'+n}});}
 // Exclude the initial ICU from the exact roster.
 await f.db.seed('member:'+ICU,{...member(3,'intensivist'),state:'revoked'});
 let operations=0;const original=f.db.transaction.bind(f.db);
 f.db.transaction=callback=>original(tx=>callback(new Proxy(tx,{get(target,key){return(...args)=>{operations++;return target[key](...args);};}})));
 const request=f.data(1,{recipients});
 assert.equal(await f.store.create(ADMIN,'a'.repeat(64),request),'created');assert.ok(operations<512,`create ${operations}`);
 operations=0;const claims=await f.store.pushClaim(ADMIN,request.id);assert.equal(claims.targets.length,25);assert.ok(operations<512,`claim ${operations}`);
 assert.ok(f.db.dump().get('directarchive:'+request.id).recipients.every(r=>r.pushState==='sending'&&r.pushAcceptedAt===null));
 operations=0;await f.store.pushFinish(request.id,recipients[0],1,'accepted');assert.ok(operations<512,`finish ${operations}`);
 const receipts=f.db.dump().get('directarchive:'+request.id).recipients;
 assert.equal(receipts.filter(r=>r.pushState==='accepted'&&r.pushAcceptedAt===START).length,1);
 assert.equal(receipts.filter(r=>r.pushState==='sending'&&r.pushAcceptedAt===null).length,24);
});
