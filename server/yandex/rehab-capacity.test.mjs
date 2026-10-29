import test from 'node:test';
import assert from 'node:assert/strict';
import {createMemoryDatabase} from './test-db.mjs';
import {createTeamStore} from './team-store.mjs';
import {createDirectStore} from './direct-store.mjs';
const START=Date.now(),DAY=86400000;
const id=n=>Buffer.alloc(32,n).toString('base64url'),mid=n=>Buffer.alloc(16,n).toString('base64url');
const ADMIN=id(1),BOT=id(2),NEURO=id(3),ICU=id(4);
const proof=(subjectId,role)=>({grant:{subjectId,issuerId:ADMIN,name:'Synthetic',role,expires:START+DAY},signature:'fixture'});
const member=(n,role,state='active')=>({device_id:id(n),name:'Synthetic',role,state,card:'PSO-CARD1.'+'A'.repeat(120),signing_spki:Buffer.alloc(91,1).toString('base64url'),approval_proof:role==='admin'?null:proof(id(n),role)});
async function fixture(){
 const db=createMemoryDatabase({now:()=>START});
 for(const [n,r] of [[1,'admin'],[2,'bot'],[3,'neurologist'],[4,'intensivist']])await db.seed('member:'+id(n),member(n,r));
 return {db,team:createTeamStore(db,{now:()=>START}),direct:createDirectStore(db,{now:()=>START})};
}

test('rehab1 seats count across specialties in approve, edit and phone replacement',async()=>{
 const f=await fixture(),roles=['rehab1_physician','psychologist','speech_therapist','exercise_therapist'];
 for(let n=10;n<35;n++)await f.db.seed('member:'+id(n),member(n,roles[n%4]));
 await f.db.seed('member:'+id(35),member(35,'psychologist','pending'));
 assert.equal(await f.team.approve(ADMIN,id(35)),'conflict');
 assert.equal((await f.direct.update(ADMIN,ICU,'Synthetic','exercise_therapist','active',proof(ICU,'exercise_therapist'))).status,'conflict');
 assert.equal((await f.direct.replace(ADMIN,id(10),id(35),proof(id(35),roles[10%4]))).state,'active');
 assert.equal(f.db.dump().get('member:'+id(10)).state,'revoked');
 assert.equal(f.db.dump().get('member:'+id(35)).role,roles[10%4]);
 // Freeing a seat must permit another specialty to occupy that same group seat.
 assert.equal(await f.team.revoke(ADMIN,id(11)),'revoked');
 assert.equal((await f.direct.update(ADMIN,ICU,'Synthetic','exercise_therapist','active',proof(ICU,'exercise_therapist'))).state,'active');
});

test('rehab2 supports several rehabilitologists, capped independently of rehab1',async()=>{
 const f=await fixture();
 for(let n=10;n<35;n++)await f.db.seed('member:'+id(n),member(n,'rehab2_physician'));
 await f.db.seed('member:'+id(35),member(35,'rehab2_physician','pending'));
 assert.equal(await f.team.approve(ADMIN,id(35)),'conflict');
 await f.db.seed('member:'+id(36),member(36,'rehab1_physician','pending'));
 assert.equal(await f.team.approve(ADMIN,id(36)),'active');
 assert.equal((await f.direct.replace(ADMIN,id(10),id(35),proof(id(35),'rehab2_physician'))).state,'active');
});

test('bot bounded retry advances past rehab rows without changing them or starving PSO',async()=>{
 const f=await fixture();
 // More than one bounded scan of rehabilitation entries ordered before PSO.
 const rehabKeys=[];
 for(let n=10;n<45;n++){
  const m={id:mid(n),sender_id:NEURO,group_name:'rehab1',kind:'review',issued:START-1000,expires:START+DAY};
  const e={message_id:m.id,recipient_id:id(90),push_state:'queued',push_attempts:0,lease_until:0,next_attempt:0};
  await f.db.seed('directmsg:'+m.id,m);
  await f.db.seed('directentry:'+m.id+':'+e.recipient_id,e);
  const key='directpush:all:'+String(0).padStart(16,'0')+':'+String(n).padStart(4,'0');
  await f.db.seed(key,{message_id:m.id,recipient_id:e.recipient_id,sender_id:NEURO});rehabKeys.push(key);
 }
 const m={id:mid(70),sender_id:BOT,group_name:'orit',kind:'admission',issued:START,expires:START+DAY};
 const e={message_id:m.id,recipient_id:ICU,push_state:'queued',push_attempts:0,lease_until:0,next_attempt:0};
 await f.db.seed('directmsg:'+m.id,m);await f.db.seed('directentry:'+m.id+':'+ICU,e);
 await f.db.seed('directpush:all:'+String(0).padStart(16,'0')+':9999',{message_id:m.id,recipient_id:ICU,sender_id:BOT});
 await f.db.seed('pushsub:'+ICU,{refreshed_at:START,endpoint_hash:'a'.repeat(64),subscription:{endpoint:'https://push.example/synthetic'}});
 const before=f.db.dump();
 assert.deepEqual((await f.direct.pushClaim(BOT)).targets,[]);
 const targets=(await f.direct.pushClaim(BOT)).targets;
 assert.equal(targets.length,1);assert.equal(targets[0].recipientId,ICU);
 for(const key of rehabKeys)assert.deepEqual(f.db.dump().get(key),before.get(key));
 for(let n=10;n<45;n++)assert.deepEqual(f.db.dump().get('directentry:'+mid(n)+':'+id(90)),before.get('directentry:'+mid(n)+':'+id(90)));
});

test('message-specific first push dispatch claims all 25 recipients while global retry stays bounded to 20',async()=>{
 for(const specific of [true,false]){
  const f=await fixture(),recipients=[];
  for(let n=10;n<35;n++){
   const recipientId=id(n);recipients.push(recipientId);
   await f.db.seed('member:'+recipientId,member(n,'rehab2_physician'));
   await f.db.seed('pushsub:'+recipientId,{refreshed_at:START,endpoint_hash:'a'.repeat(64),subscription:{endpoint:'https://push.example/synthetic/'+n}});
  }
  const data={id:mid(70),group:'rehab2',kind:'review',issued:START,expires:START+DAY,payload:{ciphertext:'synthetic'},entries:recipients.map(recipientId=>({recipientId,token:`PSO2.${recipientId}.${NEURO}.cipher.signature`}))};
  assert.equal(await f.direct.create(NEURO,'b'.repeat(64),data),'created');
  const claims=await f.direct.pushClaim(NEURO,specific?data.id:null);
  assert.equal(claims.targets.length,specific?25:20);
  if(specific)assert.deepEqual(claims.targets.map(t=>t.recipientId).sort(),recipients.sort());
 }
});
