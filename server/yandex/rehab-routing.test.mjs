import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {createMemoryDatabase} from './test-db.mjs';
import {createDirectStore} from './direct-store.mjs';
import {createTeamStore} from './team-store.mjs';
import {createDirectHandler} from '../direct-handler.mjs';
import {createTeamHandler} from '../team-handler.mjs';
import {makeDevice} from '../../docs/crypto.mjs';
import {exportPublicCard,importPublicCard} from '../../docs/exchange.mjs';
import {makeRecipientGrant,verifyRecipientGrant} from '../../docs/recipient-trust.mjs';
import {sealMessage,openMessage} from '../../docs/messages.mjs';
import {DirectClient,directEnvelope,newMessageID} from '../../docs/direct.mjs';
import {TeamClient,teamEnvelope} from '../../docs/team.mjs';

if(!globalThis.crypto)globalThis.crypto=webcrypto;
const rehab1=['rehab1_physician','psychologist','speech_therapist','exercise_therapist'];
const rehab2=['rehab2_physician','rehab2_colleague'];
const rehab=[...rehab1,...rehab2];
const roles=['admin','neurologist','cardiologist','intensivist','bot',...rehab];
const people=Object.fromEntries(await Promise.all(roles.map(async key=>{
  const role=key==='rehab2_colleague'?'rehab2_physician':key;
  const device=await makeDevice(),card=await importPublicCard(await exportPublicCard(device,'Synthetic '+key));
  return [key,{device,contact:{...card,role,verified:true},role}];
})));
const dev=key=>people[key].device,id=key=>people[key].contact.id;
const origin='https://viewer.example',endpoint=origin+'/direct';
const surname='Тестов',comment='Вымышленное сообщение для проверки реабилитации';

async function fixture({exclude=[]}={}){
  let clock=Date.now();const now=()=>clock,db=createMemoryDatabase({now}),store=createDirectStore(db,{now});
  for(const [key,{device,contact,role}] of Object.entries(people)){
    if(exclude.includes(key))continue;
    const approval_proof=role==='admin'?null:await makeRecipientGrant(dev('admin'),contact,{now:now()});
    await db.seed('member:'+contact.id,{device_id:contact.id,name:contact.name,role,state:'active',card:contact.card,
      signing_spki:Buffer.from(await crypto.subtle.exportKey('spki',device.signing.publicKey)).toString('base64url'),
      approval_proof,created_at:now(),approved_at:now(),revoked_at:null});
  }
  const handler=createDirectHandler({store:{...store,keys:async()=>null,unlockCheck:async()=>true},allowedOrigin:origin,now});
  const fetcher=handle=>async(url,options)=>handle(new Request(url,{...options,headers:{...options.headers,Origin:origin}}));
  const client=new DirectClient(endpoint,{now,fetch:fetcher(handler)});
  const teamStore=createTeamStore(db,{now});
  const teamHandler=createTeamHandler({store:{...teamStore,keys:async()=>null},allowedOrigin:origin,now});
  const team=new TeamClient(origin+'/team',{now,fetch:fetcher(teamHandler)});
  async function request(sender,group,recipients=group==='rehab1'?rehab1:rehab2){
    const meta={id:newMessageID(),group,kind:'review',issued:now(),expires:now()+3600000};
    return {...meta,...await sealMessage(dev(sender),recipients.map(r=>people[r].contact),{surname,comment},meta)};
  }
  async function op(sender,data){const envelope=await directEnvelope(dev(sender),'create',data,now());return handler(new Request(endpoint,{method:'POST',headers:{'Content-Type':'application/json',Origin:origin},body:JSON.stringify({envelope})}));}
  async function raw(service,sender,operation,data={},tamper){
    const envelope=await (service==='team'?teamEnvelope:directEnvelope)(dev(sender),operation,data,now());
    if(tamper)envelope.data=tamper(envelope.data);
    return (service==='team'?teamHandler:handler)(new Request(origin+'/'+service,{method:'POST',headers:{'Content-Type':'application/json',Origin:origin},body:JSON.stringify({envelope})}));
  }
  async function change(key,patch){const k='member:'+id(key);await db.seed(k,{...db.dump().get(k),...patch});}
  const durable=()=>[...db.dump()].filter(([key])=>/^direct(msg|entry|payload|in:|out:|quota|push)/.test(key));
  return {now,db,store,client,team,teamStore,request,op,raw,change,durable,advance:ms=>clock+=ms};
}

test('both rehab groups receive one atomic encrypted message each; only their own recipients can read it',async()=>{
  for(const [sender,group,recipients] of [['neurologist','rehab1',rehab1],['admin','rehab2',rehab2]]){
    const f=await fixture(),message=await f.request(sender,group);
    assert.equal((await f.op(sender,message)).status,200);
    assert.equal((await f.op(sender,message)).status,200,'lost-response retry remains idempotent');
    const rows=[...f.db.dump()].filter(([key])=>key.startsWith('directmsg:'));
    assert.equal(rows.length,1);assert.equal(rows[0][1].recipient_count,recipients.length);
    for(const recipient of recipients){
      const inbox=await f.client.list(dev(recipient));assert.deepEqual(inbox.items.map(m=>m.id),[message.id]);
      const opened=await f.client.open(dev(recipient),message.id);
      const plaintext=await openMessage(dev(recipient),opened.token,opened.payload,[people[sender].contact]);
      assert.equal(plaintext.surname,surname);assert.equal(plaintext.comment,comment);
      assert.equal((await f.client.ack(dev(recipient),message.id)).openedAt,f.now());
    }
    assert.equal((await f.client.list(dev(sender),'outbox')).items[0].openedCount,recipients.length);
    for(const outsider of roles.filter(r=>!recipients.includes(r))){
      assert.equal((await f.client.list(dev(outsider))).items.length,0);
      await assert.rejects(f.client.open(dev(outsider),message.id),e=>e.status===403);
    }
    const serialized=JSON.stringify([...f.db.dump()]);assert.ok(!serialized.includes(surname));assert.ok(!serialized.includes(comment));
  }
});

test('rehab recipient roster changes, omissions and extra recipients never cause partial delivery',async()=>{
  const f=await fixture();
  for(const recipients of [rehab1.slice(0,3),[...rehab1,'cardiologist'],[...rehab1,'rehab2_physician']]){
    const message=await f.request('neurologist','rehab1',recipients);
    assert.equal((await f.op('neurologist',message)).status,409);
    assert.deepEqual(f.durable(),[]);
  }
  const stale=await f.request('neurologist','rehab1');
  await f.change('psychologist',{state:'revoked'});
  const rejected=await f.op('neurologist',stale);assert.ok([403,409].includes(rejected.status));
  assert.deepEqual(f.durable(),[]);
  const current=await f.request('neurologist','rehab1',rehab1.filter(r=>r!=='psychologist'));
  assert.equal((await f.op('neurologist',current)).status,200);
  await assert.rejects(f.client.open(dev('psychologist'),current.id),e=>e.status===403);
});

test('bot and all receiving specialists cannot originate rehab messages',async()=>{
  const f=await fixture();
  for(const sender of ['bot','cardiologist','intensivist',...rehab]){
    const message=await f.request(sender,'rehab1');
    assert.equal((await f.op(sender,message)).status,403,sender);
  }
  assert.deepEqual(f.durable(),[]);
});

test('rehab refuses legacy envelopes, missing encrypted body, plaintext extras and non-review kinds',async()=>{
  const f=await fixture(),good=await f.request('neurologist','rehab1');
  const {payload,...noPayload}=good;
  const cases=[noPayload,{...good,payload:null},{...good,comment},
    {...good,entries:good.entries.map(e=>({...e,token:e.token.replace('PSO2.','PSO1.')}))},
    {...good,kind:'admission',payload:{...payload,kind:'admission'}},
    {...good,kind:'reply',replyTo:newMessageID(),payload:{...payload,kind:'reply',replyTo:newMessageID()}}];
  for(const bad of cases){assert.ok((await f.op('neurologist',bad)).status>=400);assert.deepEqual(f.durable(),[]);}
});

test('revoked or reassigned rehab recipients lose inbox/open/ack access without receiving other-group history',async()=>{
  const f=await fixture(),message=await f.request('neurologist','rehab1');await f.op('neurologist',message);
  await f.change('psychologist',{role:'rehab2_physician'});
  assert.equal((await f.client.list(dev('psychologist'))).items.length,0);
  await assert.rejects(f.client.open(dev('psychologist'),message.id),e=>e.status===403);
  await assert.rejects(f.client.ack(dev('psychologist'),message.id),e=>e.status===403);
  await f.change('speech_therapist',{state:'revoked'});
  await assert.rejects(f.client.open(dev('speech_therapist'),message.id),e=>e.status===403);
  assert.equal((await f.client.list(dev('exercise_therapist'))).items.length,1);
});

test('bot cannot claim or mutate rehab notifications; originating neurologist can notify all recipients',async()=>{
  const f=await fixture(),message=await f.request('neurologist','rehab1');await f.op('neurologist',message);
  for(const recipient of rehab1)await f.db.seed('pushsub:'+id(recipient),{refreshed_at:f.now(),endpoint_hash:'1'.repeat(64),subscription:{endpoint:'https://push.example/synthetic'}});
  f.advance(30001);const before=f.durable();
  assert.deepEqual((await f.store.pushClaim(id('bot'),message.id)).targets,[]);
  assert.deepEqual((await f.store.pushClaim(id('bot'))).targets,[]);
  assert.deepEqual(f.durable(),before);
  const targets=(await f.store.pushClaim(id('neurologist'),message.id)).targets;
  assert.deepEqual(targets.map(t=>t.recipientId).sort(),rehab1.map(id).sort());
  assert.ok(targets.every(t=>t.id===message.id));
});

test('all five rehab roles complete invitation, approval, signed grant and role-bound membership workflow',async()=>{
  const f=await fixture({exclude:rehab});
  for(const role of [...rehab1,'rehab2_physician']){
    const person=people[role],invite=await f.team.invite(dev('admin'),person.contact.name,person.role,people.admin.contact.card);
    const info=await f.team.invitationInfo(dev(role),invite.id);assert.equal(info.id,invite.id);
    assert.deepEqual(await f.team.claim(dev(role),invite.id),{state:'pending'});
    assert.equal((await f.team.pending(dev('admin'))).find(m=>m.id===id(role)).role,role);
    assert.deepEqual(await f.team.change(dev('admin'),'approve',id(role)),{state:'active'});
    const grant=await makeRecipientGrant(dev('admin'),person.contact,{now:f.now()});
    await f.client.certify(dev('admin'),id(role),grant);
    assert.equal((await f.team.status(dev(role))).role,role);
    const member=(await f.client.directory(dev('admin'))).find(m=>m.id===id(role));
    await verifyRecipientGrant(member,people.admin.contact.card,f.now());
    assert.equal((await f.client.members(dev('admin'))).find(m=>m.id===id(role)).role,role);
  }
  const message=await f.request('neurologist','rehab1');assert.equal((await f.op('neurologist',message)).status,200);
});

test('changing specialty and replacing a rehab phone requires a matching new signed grant',async()=>{
  const f=await fixture({exclude:['rehab2_colleague']});
  const changed={...people.psychologist.contact,name:'Synthetic reassigned',role:'rehab2_physician',state:'active'};
  const approvalProof=await makeRecipientGrant(dev('admin'),changed,{now:f.now()});
  assert.deepEqual(await f.client.update(dev('admin'),{...changed,approvalProof}),{state:'active'});
  assert.equal((await f.team.status(dev('psychologist'))).role,'rehab2_physician');
  const fresh=people.rehab2_colleague,invite=await f.team.invite(dev('admin'),fresh.contact.name,fresh.role,people.admin.contact.card);
  await f.team.claim(fresh.device,invite.id);
  const replacement={...fresh.contact,name:changed.name,role:changed.role};
  const replacementProof=await makeRecipientGrant(dev('admin'),replacement,{now:f.now()});
  assert.deepEqual(await f.client.replace(dev('admin'),changed.id,fresh.contact.id,replacementProof),{state:'active'});
  assert.equal((await f.team.status(dev('psychologist'))).state,'revoked');
  assert.equal((await f.team.status(fresh.device)).role,'rehab2_physician');
});

test('legacy bot directories keep the original role vocabulary while human directories expose rehab roles',async()=>{
  const f=await fixture(),oldRoles=['admin','neurologist','cardiologist','intensivist','bot'];
  for(const client of [f.client,f.team]){
    const botRoster=await client.directory(dev('bot'));
    const botMembers=Array.isArray(botRoster)?botRoster:botRoster.members;
    assert.deepEqual(botMembers.map(m=>m.role).sort(),[...oldRoles].sort());
    assert.ok(botMembers.some(m=>m.id===id('bot')));
    const humanRoster=await client.directory(dev('neurologist'));
    const humanMembers=Array.isArray(humanRoster)?humanRoster:humanRoster.members;
    for(const role of [...rehab1,'rehab2_physician'])assert.ok(humanMembers.some(m=>m.role===role),role);
  }
});

test('old installed clients retain legacy directory, admin and pending schemas until explicitly opting in',async()=>{
  const f=await fixture();
  await f.change('speech_therapist',{state:'pending'});
  await f.change('intensivist',{state:'pending'});
  for(const [service,actor,operation] of [
    ['direct','neurologist','directory'],['direct','admin','admin_members'],
    ['team','neurologist','directory'],['team','admin','pending']
  ]){
    const oldResponse=await f.raw(service,actor,operation,{});assert.equal(oldResponse.status,200);
    const old=(await oldResponse.json()).members;
    assert.ok(old.every(m=>!rehab.includes(m.role)),operation+' excludes unknown roles');
    const freshResponse=await f.raw(service,actor,operation,{includeRehab:true});assert.equal(freshResponse.status,200);
    const fresh=(await freshResponse.json()).members;
    assert.deepEqual(fresh.filter(m=>!rehab.includes(m.role)),old,'legacy members and shapes remain identical');
    assert.ok(fresh.some(m=>rehab.includes(m.role)),operation+' includes rehab after signed opt-in');
    if(operation==='pending')assert.deepEqual(fresh.map(m=>m.role).sort(),['intensivist','speech_therapist']);
  }
});

test('directory capability flag must be exactly true, is signed, and is rejected on unrelated operations',async()=>{
  const f=await fixture();
  for(const [service,operation] of [['direct','directory'],['direct','admin_members'],['team','directory'],['team','pending']]){
    for(const data of [{includeRehab:false},{includeRehab:'true'},{includeRehab:1},{includeRehab:true,extra:true}]){
      assert.equal((await f.raw(service,'admin',operation,data)).status,400,service+' '+operation);
    }
    assert.equal((await f.raw(service,'admin',operation,{},()=>({includeRehab:true}))).status,403,'unsigned capability change');
  }
  assert.equal((await f.raw('direct','admin','retry',{includeRehab:true})).status,400);
  assert.equal((await f.raw('team','admin','status',{includeRehab:true})).status,400);
});

test('direct notification handler processes a full 25-recipient batch without dropping the final five',async()=>{
  const f=await fixture(),delivered=[],finished=[];
  const messageId=newMessageID();
  const targets=Array.from({length:25},(_,n)=>({id:messageId,recipientId:Buffer.alloc(32,n+1).toString('base64url'),
    expires:f.now()+60000,lease:1,subscription:{endpoint:'https://push.example/synthetic/'+n}}));
  const handler=createDirectHandler({allowedOrigin:origin,now:f.now,
    store:{...f.store,unlockCheck:async()=>true,pushClaim:async()=>({targets}),
      pushFinish:async(...args)=>{finished.push(args);return'ok';},
      keys:async()=>({publicKey:Buffer.alloc(65,1).toString('base64url'),privateKey:{}})},
    send:async(subscription,keys,payload)=>{delivered.push({subscription,payload});return{status:'accepted'};}});
  const envelope=await directEnvelope(dev('neurologist'),'retry',{},f.now());
  const response=await handler(new Request(endpoint,{method:'POST',headers:{'Content-Type':'application/json',Origin:origin},body:JSON.stringify({envelope})}));
  assert.equal(response.status,200);assert.deepEqual(await response.json(),{accepted:25,queued:0});
  assert.equal(delivered.length,25);assert.equal(finished.length,25);
  assert.ok(delivered.every(d=>d.payload.id===messageId));
  assert.equal(new Set(finished.map(args=>args[1])).size,25);
});
