import test from 'node:test';
import assert from 'node:assert/strict';
import {createTeamStore,roleCapacityReached} from './team-store.mjs';
import {createDirectStore} from './direct-store.mjs';
import {createMemoryDatabase} from './test-db.mjs';

const DAY=86400000,START=1792915200000;
const id=n=>Buffer.alloc(32,n).toString('base64url'),hash=n=>n.toString(16).padStart(64,'0');
const ADMIN=id(1),NEURO=id(2),OTHER=id(3),NEXT=id(4);
const CARD='PSO-CARD1.'+'A'.repeat(150),SPKI='A'.repeat(122);
const proof=(subjectId,name,role,expires=START+30*DAY)=>({grant:{subjectId,name,role,issuerId:ADMIN,expires},signature:'test-public-signature'});
async function fixture(){
 let clock=START;const now=()=>clock,db=createMemoryDatabase({now}),team=createTeamStore(db,{now}),direct=createDirectStore(db,{now});
 async function seed(deviceId,role='neurologist',extra={}){const m={device_id:deviceId,name:`Doctor ${deviceId.slice(0,4)}`,role,state:'active',card:CARD,signing_spki:SPKI,created_at:START-1000,approved_at:START-500,revoked_at:null,approval_proof:role==='admin'?null:proof(deviceId,`Doctor ${deviceId.slice(0,4)}`,role),...extra};await db.seed('member:'+deviceId,m);return m;}
 await seed(ADMIN,'admin');await seed(NEURO);await seed(OTHER);
 async function invite(n,role='rehab1_physician',who=NEURO){assert.equal((await team.invite(ADMIN,hash(n),'Invitation spelling',role,CARD)).status,'created');return team.claim(who,hash(n),CARD,SPKI);}
 const row=who=>db.dump().get('member:'+who);
 async function approve(who=NEURO,role=row(who).pending_role){return direct.certify(ADMIN,who,proof(who,row(who).name,role));}
 return {db,team,direct,seed,invite,approve,row,now,advance:delta=>clock+=delta};
}

test('additional role stays pending without changing identity, keys, proof, membership or old-client projection',async()=>{
 const f=await fixture(),original=f.row(NEURO);await f.db.seed('authcred:'+NEURO,{sentinel:'holder'});await f.db.seed('pushsub:'+NEURO,{sentinel:'subscription'});
 assert.equal(await f.invite(1),'pending');
 const pending=f.row(NEURO);for(const key of ['name','card','signing_spki','role','state','approval_proof','created_at','approved_at'])assert.deepEqual(pending[key],original[key]);
 assert.deepEqual(await f.team.status(NEURO),{state:'active',role:'neurologist',name:original.name});
 assert.equal((await f.team.status(NEURO,true)).pendingRole,'rehab1_physician');
 assert.equal((await f.team.pending(ADMIN)).members.length,0);assert.equal((await f.team.pending(ADMIN,true)).members.length,1);
 assert.deepEqual(await f.direct.certify(OTHER,NEURO,proof(NEURO,original.name,'rehab1_physician')),{status:'denied'});
 assert.deepEqual(await f.direct.certify(ADMIN,NEURO,proof(NEURO,'Different name','rehab1_physician')),{status:'invalid'});
 assert.deepEqual(await f.approve(),{state:'active'});assert.deepEqual(await f.approve(NEURO,'rehab1_physician'),{state:'active'});
 assert.deepEqual(f.row(NEURO).roles,['neurologist','rehab1_physician']);assert.deepEqual(f.row(NEURO).approval_proof,original.approval_proof);
 assert.equal(f.row(NEURO).role_proofs.length,1);assert.equal(f.row(NEURO).pending_role,null);
 assert.equal(await f.team.claim(NEURO,hash(1),CARD,SPKI),'active');
 assert.equal(f.db.dump().get('authcred:'+NEURO).sentinel,'holder');assert.equal(f.db.dump().get('pushsub:'+NEURO).sentinel,'subscription');
 const legacy=(await f.direct.directory(OTHER)).members.find(m=>m.id===NEURO);assert.deepEqual(Object.keys(legacy).sort(),['approvalProof','card','id','name','role']);
 const newer=(await f.direct.directory(OTHER,true)).members.find(m=>m.id===NEURO);assert.deepEqual(newer.roles,['neurologist','rehab1_physician']);assert.equal(newer.roleProofs.length,1);
});

test('second clinical requests conflict until first approved and bot/admin/cardio/ICU cannot gain extra roles',async()=>{
 const f=await fixture();assert.equal(await f.invite(1),'pending');assert.equal(await f.invite(2,'rehab2_physician'),'conflict');
 assert.deepEqual(await f.direct.certify(ADMIN,NEURO,proof(NEURO,f.row(NEURO).name,'rehab2_physician')),{status:'denied'});
 assert.deepEqual(await f.approve(),{state:'active'});assert.equal(await f.team.claim(NEURO,hash(2),CARD,SPKI),'pending');assert.deepEqual(await f.approve(),{state:'active'});
 assert.deepEqual(f.row(NEURO).roles,['neurologist','rehab1_physician','rehab2_physician']);
 for(const [n,role] of [[10,'bot'],[11,'cardiologist'],[12,'intensivist']]){assert.equal(await f.invite(n,role,OTHER),'conflict');await f.seed(id(n),role);assert.equal(await f.invite(n+10,'rehab1_physician',id(n)),'conflict');}
 assert.equal(await f.invite(30,'rehab1_physician',ADMIN),'conflict');
});

test('expired pending additional role can be replaced by a fresh invitation without disabling the phone',async()=>{
 const f=await fixture();assert.equal(await f.invite(1),'pending');f.advance(2*DAY+1);
 assert.deepEqual(await f.approve(),{status:'denied'});assert.equal(f.row(NEURO).state,'active');
 assert.equal(await f.invite(2,'rehab2_physician'),'pending');assert.equal(f.row(NEURO).pending_role,'rehab2_physician');
 assert.deepEqual(await f.approve(),{state:'active'});assert.deepEqual(f.row(NEURO).roles,['neurologist','rehab2_physician']);
 assert.equal(await f.team.claim(NEURO,hash(1),CARD,SPKI),'conflict');
});

test('simultaneous extra-role approval respects group capacity and counts each device once',async()=>{
 const f=await fixture();for(let n=20;n<44;n++)await f.seed(id(n),'psychologist');
 assert.equal(await f.invite(1),'pending');assert.equal(await f.invite(2,'exercise_therapist',OTHER),'pending');
 const results=await Promise.all([f.approve(),f.approve(OTHER)]);assert.deepEqual(results.map(x=>x.state??x.status).sort(),['active','conflict']);
 const active=[...f.db.dump().values()].filter(m=>m.state==='active'&&m.device_id);assert.equal(roleCapacityReached(active,'rehab1_physician'),true);
 const winner=f.row(NEURO).roles?NEURO:OTHER;const secondary=f.row(winner).roles[1]==='rehab1_physician'?'speech_therapist':'rehab1_physician';
 assert.equal(await f.invite(3,secondary,winner),'pending');assert.deepEqual(await f.approve(winner),{state:'active'},'A second role in same direction uses no extra device seat');
});

test('combined identity rename and replacement require complete exact-role proofs and revoke all old-key access',async()=>{
 const f=await fixture();await f.invite(1);await f.approve();const original=f.row(NEURO),roles=original.roles;
 assert.deepEqual(await f.direct.update(ADMIN,NEURO,'New name','neurologist','active',proof(NEURO,'New name','neurologist')),{status:'invalid'});
 assert.deepEqual(await f.direct.update(ADMIN,NEURO,'New name','neurologist','active',proof(NEURO,'New name','neurologist'),roles,[proof(NEURO,'Wrong','rehab1_physician')]),{status:'invalid'});
 assert.deepEqual(await f.direct.update(ADMIN,NEURO,'New name','neurologist','active',proof(NEURO,'New name','neurologist'),roles,[proof(NEURO,'New name','rehab1_physician')]),{state:'active'});
 await f.seed(NEXT,'neurologist',{state:'pending'});
 assert.deepEqual(await f.direct.replace(ADMIN,NEURO,NEXT,proof(NEXT,'New name','neurologist')),{status:'invalid'});
 assert.equal(f.row(NEURO).state,'active');
 assert.deepEqual(await f.direct.replace(ADMIN,NEURO,NEXT,proof(NEXT,'New name','neurologist'),[proof(NEXT,'New name','rehab1_physician')]),{state:'active'});
 assert.equal(f.row(NEURO).state,'revoked');assert.deepEqual(f.row(NEXT).roles,roles);assert.equal(f.row(NEXT).role_proofs[0].grant.subjectId,NEXT);
 assert.deepEqual(await f.direct.update(ADMIN,NEXT,'New name','neurologist','revoked'),{state:'revoked'},'Legacy admin can revoke all roles atomically');
});
