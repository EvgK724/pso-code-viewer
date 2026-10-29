import test from 'node:test';
import assert from 'node:assert/strict';
import {createReleaseNotifications} from './release-notifications.mjs';
import {createMemoryDatabase} from './test-db.mjs';

const DAY=86400000;
const id=n=>{const b=Buffer.alloc(32);b.writeUInt32BE(n,28);return b.toString('base64url');};
function fixture(){
  let clock=1793000000000;
  const now=()=>clock,db=createMemoryDatabase({now}),calls=[];
  const keys=async()=>({publicKey:'test-only',privateKey:{testOnly:true}});
  const send=async(subscription,_keys,payload,options)=>{calls.push({subscription,payload,options});return {status:'accepted'};};
  const service=(version=18,options={})=>createReleaseNotifications(db,{now,keys,send,version,...options});
  async function member(n,{role='neurologist',state='active',version=17,capability=1,sub=true,roles}={}){
    await db.seed('member:'+id(n),{device_id:id(n),name:'Синтетический участник',role,state,...(roles?{roles}:{})});
    if(version!==null)await db.seed('release-client:'+id(n),{device_id:id(n),version,notifications_version:capability,refreshed_at:now()},now()+90*DAY);
    if(sub)await db.seed('pushsub:'+id(n),{device_id:id(n),endpoint_hash:'endpoint-'+n,subscription:{endpoint:'https://web.push.apple.com/synthetic-'+n,keys:{}},refreshed_at:now()},now()+90*DAY);
  }
  return {db,now,calls,service,member,advance:ms=>clock+=ms};
}

test('new-release fanout targets each active capable human once, excluding bots and patient records',async()=>{
  const f=fixture();
  await f.member(1,{role:'admin',version:18});
  await f.member(2,{roles:['neurologist','rehab1_physician']});
  await f.member(3,{role:'bot'});
  await f.member(4,{state:'revoked'});
  await f.member(5,{state:'pending'});
  await f.member(6,{version:18});
  await f.member(7,{capability:0});
  await f.member(8,{version:null});
  await f.member(9,{sub:false});
  await f.member(10,{role:'cardiologist'});
  const api=f.service();
  assert.deepEqual(await api.status(id(1),{clientVersion:18,notificationsVersion:1}),{version:18,updateAvailable:false});
  assert.equal(f.calls.length,2);
  assert.deepEqual(f.calls.map(c=>c.subscription.endpoint).sort(),['https://web.push.apple.com/synthetic-10','https://web.push.apple.com/synthetic-2']);
  for(const c of f.calls){assert.deepEqual(c.payload,{v:1,type:'release',version:18,expires:f.now()+7*DAY});assert.equal(c.options.ttl,604800);assert.equal(c.options.timeout,3000);}
  f.advance(60001);
  await api.status(id(1),{clientVersion:18,notificationsVersion:1});
  assert.equal(f.calls.length,2,'Refreshing an organizer does not repeat a release push');
  assert.deepEqual(await api.status(id(9),{clientVersion:17,notificationsVersion:0}),{version:18,updateAvailable:true},'No push permission still gets the in-app update prompt');
  assert.equal([...f.db.dump().keys()].some(key=>/^(direct:|history:|entry:|message:)/.test(key)),false);
});

test('bot, revoked, pending and unknown callers cannot register or initiate broadcasts',async()=>{
  const f=fixture(),api=f.service();
  await f.member(1,{role:'bot',version:null});await f.member(2,{state:'revoked',version:null});await f.member(3,{state:'pending',version:null});
  const before=[...f.db.dump()];
  for(const n of [1,2,3,4])assert.deepEqual(await api.status(id(n),{clientVersion:17,notificationsVersion:1}),{status:'denied'});
  assert.deepEqual([...f.db.dump()],before);assert.equal(f.calls.length,0);
  for(const data of [{clientVersion:'17',notificationsVersion:1},{clientVersion:0,notificationsVersion:1},{clientVersion:1000001,notificationsVersion:1},{clientVersion:17,notificationsVersion:2},{clientVersion:17,notificationsVersion:1,role:'admin'}])
    assert.deepEqual(await api.status(id(1),data),{status:'invalid'});
  assert.deepEqual([...f.db.dump()],before);
});

test('competing requests and ambiguous network outcomes cannot duplicate a release notification',async()=>{
  const f=fixture();await f.member(1,{role:'admin',version:18});await f.member(2);
  let attempts=0;
  const api=f.service(18,{send:async()=>{attempts++;throw new Error('Synthetic lost delivery response');}});
  await Promise.all(Array.from({length:5},()=>api.status(id(1),{clientVersion:18,notificationsVersion:1})));
  assert.equal(attempts,1);
  assert.equal(f.db.dump().get('release-notice:18:'+id(2)).state,'failed');
  f.advance(60001);await api.status(id(1),{clientVersion:18,notificationsVersion:1});assert.equal(attempts,1);
  assert.deepEqual(await api.status(id(2),{clientVersion:17,notificationsVersion:1}),{version:18,updateAvailable:true});
});

test('future releases are independent and old suspended tabs do not downgrade installed version',async()=>{
  const f=fixture();await f.member(1,{role:'admin',version:18});await f.member(2);
  await f.service(18).status(id(1),{clientVersion:18,notificationsVersion:1});assert.equal(f.calls.length,1);
  await f.service(18).status(id(2),{clientVersion:18,notificationsVersion:1});
  assert.deepEqual(await f.service(18).status(id(2),{clientVersion:17,notificationsVersion:1}),{version:18,updateAvailable:true});
  assert.equal(f.db.dump().get('release-client:'+id(2)).version,18);
  await f.service(19).status(id(1),{clientVersion:19,notificationsVersion:1});
  assert.equal(f.calls.length,2);assert.equal(f.calls[1].payload.version,19);
});

test('bounded fanout continues over later requests without skipping recipients',async()=>{
  const f=fixture();await f.member(1,{role:'admin',version:18});
  for(let n=2;n<=31;n++)await f.member(n);
  const api=f.service();await api.status(id(1),{clientVersion:18,notificationsVersion:1});assert.equal(f.calls.length,5);
  for(let n=2;n<=6;n++){
    f.advance(60001);await api.status(id(1),{clientVersion:18,notificationsVersion:1});assert.equal(f.calls.length,n*5);
  }
  assert.equal(new Set(f.calls.map(c=>c.subscription.endpoint)).size,30);
});

test('gone receipt preserves a newly registered subscription, and missing keys consume no send receipt',async()=>{
  const f=fixture();await f.member(1,{role:'admin',version:18});await f.member(2);
  const withoutKeys=f.service(18,{keys:async()=>null});
  await withoutKeys.status(id(1),{clientVersion:18,notificationsVersion:1});
  assert.equal(f.db.dump().has('release-notice:18:'+id(2)),false);
  const api=f.service(18,{send:async()=>{
    await f.db.seed('pushsub:'+id(2),{device_id:id(2),endpoint_hash:'replacement',subscription:{endpoint:'https://web.push.apple.com/replacement'},refreshed_at:f.now()});
    return {status:'gone'};
  }});
  await api.status(id(1),{clientVersion:18,notificationsVersion:1});
  assert.equal(f.db.dump().get('pushsub:'+id(2)).endpoint_hash,'replacement');
  assert.equal(f.db.dump().get('release-notice:18:'+id(2)).state,'gone');
});

test('legacy workers and stale subscriptions are never sent the new release payload',async()=>{
  const f=fixture();await f.member(1,{role:'admin',version:18});await f.member(2,{capability:0});await f.member(3);
  await f.db.seed('pushsub:'+id(3),{device_id:id(3),endpoint_hash:'old',subscription:{endpoint:'https://web.push.apple.com/old'},refreshed_at:f.now()-91*DAY});
  const api=f.service();await api.status(id(1),{clientVersion:18,notificationsVersion:1});assert.equal(f.calls.length,0);
  await f.service(17).status(id(2),{clientVersion:17,notificationsVersion:1});
  f.advance(60001);await api.status(id(1),{clientVersion:18,notificationsVersion:1});assert.equal(f.calls.length,1);
  assert.equal(f.calls[0].subscription.endpoint,'https://web.push.apple.com/synthetic-2');
});
