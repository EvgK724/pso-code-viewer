import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {createTeamHandler,MAX_TEAM_BODY_BYTES,safeServiceDiagnostic} from './team-handler.mjs';
import {createVapidKeys} from './web-push.mjs';
import {makeDevice,base64url} from '../docs/crypto.mjs';
import {deviceIdentity,exportPublicCard,importPublicCard,sealSurname,openSurname} from '../docs/exchange.mjs';

if(!globalThis.crypto)globalThis.crypto=webcrypto;
const ORIGIN='https://viewer.example',URL='https://broker.example/functions/v1/pso-team',NOW=Date.now();
const enc=new TextEncoder(),vapid=await createVapidKeys();
const devices=await Promise.all(Array.from({length:6},()=>makeDevice()));
const [admin,neuro,cardio,icuA,icuB,bot]=devices;
const identities=await Promise.all(devices.map(deviceIdentity));
const [adminID,neuroID,cardioID,icuAID,icuBID,botID]=identities.map(x=>x.id);
const cards=await Promise.all(devices.map(d=>exportPublicCard(d,'Устройство')));
const contacts=await Promise.all(cards.map(async card=>({...await importPublicCard(card),verified:true})));
const roleNames=['admin','neurologist','cardiologist','intensivist','intensivist','bot'];
const rid=()=>base64url(crypto.getRandomValues(new Uint8Array(16)));
const idHash=async id=>Buffer.from(await crypto.subtle.digest('SHA-256',Buffer.from(id,'base64url'))).toString('hex');
async function envelope(device,op,data={},issued=NOW) {
  const unsigned={v:1,op,issued,nonce:rid(),card:await exportPublicCard(device,'Устройство'),data};
  return {...unsigned,signature:base64url(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},device.signing.privateKey,enc.encode('PSO-TEAM-v1\0'+JSON.stringify(unsigned))))};
}
function request(body,{origin=ORIGIN,url=URL,method='POST',raw,headers={}}={}) {
  return new Request(url,{method,headers:{Origin:origin,'Content-Type':'application/json',...headers},...(method==='POST'?{body:raw===undefined?JSON.stringify(body):raw}:{})});
}
async function dataFor(sender=neuro,{group='orit',kind='review',at=NOW,recipients=[contacts[3],contacts[4]],id=rid()}={}) {
  const entries=await Promise.all(recipients.map(async c=>({recipientId:c.id,token:await sealSurname(sender,c,'Иванов',{department:'ОРИТ',ttlMinutes:60})})));
  return {id,group,kind,issued:at,expires:at+3600000,entries};
}
function fixture({sendStatus='accepted',throwSend=false,acceptResult,createResult,finishError=false}={}) {
  let clock=NOW;
  const calls=[],sent=[],finished=[],nonces=new Set(),roster=new Map(),links=new Map(),invites=new Map(),claims=new Set(),subscriptions=new Map();
  for(let i=0;i<devices.length;i++)roster.set(identities[i].id,{id:identities[i].id,name:'Тест '+i,role:roleNames[i],card:cards[i],state:'active'});
  for(const id of [cardioID,icuAID,icuBID])subscriptions.set(id,{subscription:{endpoint:'https://web.push.apple.com/'+id,keys:{}},senders:[adminID,neuroID,botID]});
  const active=id=>roster.get(id)?.state==='active';
  const publicMember=m=>({id:m.id,name:m.name,role:m.role,card:m.card});
  const isAdmin=id=>active(id)&&roster.get(id)?.role==='admin';
  const store={
    async accept(id,nonce,op,issued,card,spki){calls.push(['accept',id,nonce,op,issued,card,spki]);if(acceptResult)return acceptResult;if(nonces.has(id+nonce))return'replay';nonces.add(id+nonce);return'ok';},
    async status(id){calls.push(['status',id]);const m=roster.get(id);return m?{state:m.state,role:m.role,name:m.name}:{state:'unregistered',role:null,name:null};},
    async directory(id){calls.push(['directory',id]);return active(id)?{status:'ok',members:[...roster.values()].filter(m=>m.state==='active').map(publicMember)}:{status:'denied'};},
    async invite(id,hash,name,role,organizerCard){calls.push(['invite',id,hash,name,role,organizerCard]);if(!isAdmin(id))return{status:'denied'};const old=invites.get(hash);if(old&&(old.name!==name||old.role!==role||old.organizerCard!==organizerCard))return{status:'conflict'};if(!old)invites.set(hash,{inviter:id,name,role,organizerCard,expires:clock+86400000,claimed:null});return{status:old?'exists':'created',expires:invites.get(hash).expires};},
    async inviteInfo(id,hash){calls.push(['inviteInfo',id,hash]);if(roster.get(id)?.state==='revoked')return{status:'denied'};const invite=invites.get(hash);if(!invite||!Number.isSafeInteger(invite.expires)||invite.expires<=clock||invite.claimed||!invite.organizerCard||!isAdmin(invite.inviter))return{status:'missing'};return{status:'ok',expires:invite.expires,organizerCard:invite.organizerCard};},
    async claim(id,hash,card,spki){calls.push(['claim',id,hash,card,spki]);const invite=invites.get(hash);if(!invite||invite.expires<=clock)return'denied';if(invite.claimed&&invite.claimed!==id)return'conflict';if(invite.claimed===id)return roster.get(id).state;if(roster.has(id))return'conflict';invite.claimed=id;roster.set(id,{id,name:invite.name,role:invite.role,card,state:'pending'});return'pending';},
    async pending(id){calls.push(['pending',id]);return isAdmin(id)?{status:'ok',members:[...roster.values()].filter(m=>m.state==='pending').map(publicMember)}:{status:'denied'};},
    async approve(id,target){calls.push(['approve',id,target]);if(!isAdmin(id))return'denied';const m=roster.get(target);if(!m||m.state!=='pending')return'denied';if(m.role==='cardiologist'&&[...roster.values()].some(v=>v.state==='active'&&v.role==='cardiologist'))return'conflict';m.state='active';return'active';},
    async revoke(id,target){calls.push(['revoke',id,target]);if(!isAdmin(id)||roster.get(target)?.role==='admin')return'denied';const m=roster.get(target);if(!m)return'denied';m.state='revoked';return'revoked';},
    async create(sender,hash,requestHash,group,kind,issued,expires,entries){
      calls.push(['create',sender,hash,requestHash,group,kind,issued,expires,entries]);if(createResult)return createResult;
      const role=roster.get(sender)?.role;if(!active(sender)||(kind==='admission'?role!=='bot':!['admin','neurologist'].includes(role)))return'denied';
      const old=links.get(hash);if(old)return old.requestHash===requestHash&&old.expires>clock?'exists':'conflict';
      if(issued>clock+30000||expires<=clock)return'invalid';
      const expected=[...roster.values()].filter(m=>m.state==='active'&&m.role===(group==='cardiology'?'cardiologist':'intensivist')).map(m=>m.id).sort();
      if(!expected.length||JSON.stringify(expected)!==JSON.stringify(entries.map(e=>e.recipientId).sort()))return'roster_changed';
      links.set(hash,{sender,requestHash,group,kind,issued,expires,entries});return'created';
    },
    async resolve(id,hash){calls.push(['resolve',id,hash]);const l=links.get(hash);if(!l||l.expires<=clock)return{status:'missing'};const e=l.entries.find(e=>e.recipientId===id);if(!active(id)||!e)return{status:'denied'};const s=roster.get(l.sender);return{status:'ok',token:e.token,expires:l.expires,senderCard:s.card,senderName:s.name};},
    async pushClaim(sender,hash){calls.push(['pushClaim',sender,hash]);const l=links.get(hash),targets=[];if(!l||l.sender!==sender||!active(sender))return{targets};for(const e of l.entries){const key=hash+e.recipientId,sub=subscriptions.get(e.recipientId);if(!active(e.recipientId)||claims.has(key)||!sub||!sub.senders.includes(sender))continue;claims.add(key);targets.push({recipientId:e.recipientId,subscription:sub.subscription,expires:l.expires});}return{targets};},
    async pushFinish(hash,id,status){finished.push({hash,id,status});if(finishError)throw Error('Private DB detail');},
    async keys(value){calls.push(['keys',value]);return vapid;}
  };
  const handler=createTeamHandler({store,allowedOrigin:ORIGIN,now:()=>clock,send:async(sub,key,payload)=>{sent.push({sub,key,payload});if(throwSend)throw Error('Private provider detail');return{status:sendStatus};}});
  return {store,handler,calls,sent,finished,roster,links,invites,subscriptions,claims,setTime(value){clock=value;},
    async op(device,op,data={},options={}){return handler(request({envelope:await envelope(device,op,data,clock)},options));}};
}

test('signed status exposes own role; public/extra-data requests cannot self-assign membership',async()=>{
  const f=fixture();assert.deepEqual(await(await f.op(neuro,'status')).json(),{state:'active',role:'neurologist',name:'Тест 1'});
  assert.equal((await f.op(neuro,'status',{role:'admin'})).status,400);
  assert.equal((await f.handler(request({op:'status'}))).status,400);
  assert.equal((await f.op(cardio,'directory')).status,200,'Recipients obtain approved sender cards for notification consent');
  f.roster.get(cardioID).state='revoked';assert.equal((await f.op(cardio,'directory')).status,403);
  assert.equal(f.sent.length,0);
});

test('all outer signed fields are bound and no unverified request reaches storage',async()=>{
  const f=fixture(),original=await envelope(admin,'invite',{id:rid(),name:'Тест',role:'neurologist'});
  const corrupted=Buffer.from(original.signature,'base64url');corrupted[0]^=1;
  for(const e of [
    {...original,card:cards[1]},{...original,op:'claim'},{...original,issued:NOW-1},{...original,nonce:rid()},
    {...original,data:{...original.data,role:'bot'}},{...original,signature:corrupted.toString('base64url')}
  ])assert.equal((await f.handler(request({envelope:e}))).status,403);
  assert.equal(f.calls.length,0);
});

test('fresh authentication, nonce replay and storage rate failures map to explicit errors',async()=>{
  const f=fixture(),e=await envelope(neuro,'status');assert.equal((await f.handler(request({envelope:e}))).status,200);
  const replay=await f.handler(request({envelope:e}));assert.equal(replay.status,409);assert.deepEqual(await replay.json(),{error:'replay'});
  for(const at of [NOW-60001,NOW+30001]){
    const response=await f.handler(request({envelope:await envelope(neuro,'status',{},at)}));
    assert.equal(response.status,400);assert.deepEqual(await response.json(),{error:'clock_skew'});
  }
  assert.equal((await fixture({acceptResult:'limited'}).op(neuro,'status')).status,429);
});

test('clock hint is limited to structurally valid timestamps and never reaches storage',async()=>{
  const f=fixture(),original=await envelope(neuro,'status');
  for(const changed of [{issued:String(NOW-60001)},{issued:null},{v:2,issued:NOW-60001},{op:'private-secret',issued:NOW-60001}]){
    const response=await f.handler(request({envelope:{...original,...changed}}));
    assert.equal(response.status,400);assert.deepEqual(await response.json(),{error:'request_rejected'});
  }
  assert.equal(f.calls.length,0);
});

test('unexpected database failures expose only allowlisted stage/code/status for every team operation',async()=>{
  const error=Object.assign(new Error('PRIVATE SQL name=Иванов card='+cards[0]),{
    code:'database_conflict',status:400040,cause:{sql:'PRIVATE SQL',parameters:cards[0]},deviceId:adminID
  });
  const operations=[['accept','status',{}],['status','status',{}],['directory','directory',{}],['pending','pending',{}],
    ['invite','invite',{id:rid(),name:'Новый врач',role:'neurologist'}],['inviteInfo','invite_info',{id:rid()}],['claim','claim',{id:rid()}],
    ['approve','approve',{deviceId:neuroID}],['revoke','revoke',{deviceId:neuroID}],['resolve','resolve',{id:rid()}],
    ['create','create',await dataFor()]];
  for(const [failedMethod,op,data] of operations){
    const f=fixture();f.store[failedMethod]=async()=>{throw error;};
    const response=await f.op(admin,op,op==='create'?await dataFor(admin):data);
    assert.equal(response.status,503,failedMethod);
    assert.deepEqual(await response.json(),{error:'request_rejected',diagnostic:{stage:failedMethod==='accept'?'accept':op,code:'database_conflict',status:400040}});
  }
});

test('diagnostics cannot echo unknown codes, numeric data, messages, stack or causes',async()=>{
  const f=fixture();
  f.store.approve=async()=>{throw Object.assign(new Error('PRIVATE secret'),{
    code:'PRIVATE patient Иванов',status:123456,cause:'PRIVATE key',stack:'PRIVATE stack'
  });};
  const response=await f.op(admin,'approve',{deviceId:neuroID});
  assert.equal(response.status,503);
  assert.deepEqual(await response.json(),{error:'request_rejected',diagnostic:{stage:'approve',code:'internal_error',status:null}});
  assert.deepEqual(safeServiceDiagnostic({code:'database_unavailable',status:400060},'PRIVATE stage'),{
    stage:'validation',code:'database_unavailable',status:400060
  });
  for(const status of ['400040',Infinity,400000,400040.5,400110])assert.equal(safeServiceDiagnostic({status},'accept').status,null);
});

test('invitation possession creates pending enrollment only; admin approves a bound immutable device',async()=>{
  const f=fixture(),newDevice=await makeDevice(),newID=(await deviceIdentity(newDevice)).id,id=rid();
  const invitation=await f.op(admin,'invite',{id,name:'Новый врач',role:'neurologist'});assert.equal(invitation.status,200);assert.equal((await invitation.json()).id,id);
  assert.equal((await f.op(neuro,'invite',{id:rid(),name:'Другой врач',role:'bot'})).status,403);
  assert.equal((await f.op(admin,'invite',{id:rid(),name:'Другой врач',role:'admin'})).status,400);
  const claimed=await f.op(newDevice,'claim',{id});assert.deepEqual(await claimed.json(),{state:'pending'});
  assert.equal((await f.op(newDevice,'directory')).status,403);assert.equal((await f.op(newDevice,'pending')).status,403);
  const pending=await(await f.op(admin,'pending')).json();assert.equal(pending.members[0].id,newID);assert.equal(pending.members[0].role,'neurologist');
  assert.equal((await f.op(neuro,'approve',{deviceId:newID})).status,403);
  assert.deepEqual(await(await f.op(admin,'approve',{deviceId:newID})).json(),{state:'active'});
  assert.deepEqual(await(await f.op(newDevice,'claim',{id})).json(),{state:'active'});
  assert.equal((await f.op(icuA,'claim',{id})).status,409);
  assert.equal((await f.op(admin,'revoke',{deviceId:adminID})).status,403);
  assert.deepEqual(await(await f.op(admin,'revoke',{deviceId:newID})).json(),{state:'revoked'});
});

test('short invitation stores the exact signed organizer snapshot and returns only public lookup fields without claiming',async()=>{
  const f=fixture(),stranger=await makeDevice(),strangerID=(await deviceIdentity(stranger)).id,id=rid();
  const organizerCard=await exportPublicCard(admin,'Организатор'),data={id,name:'Новый врач',role:'neurologist',organizerCard};
  assert.notEqual(organizerCard,cards[0],'Envelope display name differs from the invitation snapshot');
  const created=await f.op(admin,'invite',data);assert.equal(created.status,200);
  const {expires}=await created.json(),hash=await idHash(id),before=structuredClone(f.invites.get(hash));
  for(let n=0;n<2;n++) {
    const info=await f.op(stranger,'invite_info',{id});assert.equal(info.status,200);
    assert.deepEqual(await info.json(),{id,expires,organizerCard});
    assert.deepEqual(f.invites.get(hash),before);
    assert.equal(f.roster.has(strangerID),false);
  }
  assert.equal(f.calls.some(call=>call[0]==='claim'),false);
  assert.equal((await f.op(admin,'invite',data)).status,200);
  assert.equal((await f.op(admin,'invite',{...data,organizerCard:cards[0]})).status,409);
  assert.deepEqual(await(await f.op(stranger,'claim',{id})).json(),{state:'pending'});
  assert.equal((await f.op(stranger,'invite_info',{id})).status,404);
});

test('invitation snapshots must be canonical and match both public keys of the signed issuer before storage',async()=>{
  const f=fixture(),data={id:rid(),name:'Новый врач',role:'neurologist'};
  const otherEncryption=await exportPublicCard({encryption:neuro.encryption,signing:admin.signing},'Организатор');
  for(const organizerCard of [cards[1],otherEncryption])
    assert.equal((await f.op(admin,'invite',{...data,organizerCard})).status,403);
  for(const organizerCard of [null,'PSO-CARD1.invalid',' '+cards[0],cards[0]+'\n'])
    assert.equal((await f.op(admin,'invite',{...data,organizerCard})).status,400);
  assert.equal((await f.op(admin,'invite',{...data,organizerCard:cards[0],extra:true})).status,400);
  assert.equal((await f.op(neuro,'invite_info',{id:data.id,organizerCard:cards[0]})).status,400);
  assert.equal(f.calls.length,0);
  const legacy=fixture();delete legacy.store.inviteInfo;
  assert.equal((await legacy.op(admin,'invite',{...data,organizerCard:cards[0]})).status,503);
  assert.equal(legacy.calls.length,0);
  assert.equal((await legacy.op(admin,'invite',data)).status,200,'Old adapters still accept the legacy format');
});

test('invitation lookup is signed and rejects missing, expired, legacy, claimed and revoked invitations or requesters',async()=>{
  const f=fixture(),id=rid(),legacyID=rid(),data={id,name:'Private invitee name',role:'bot',organizerCard:cards[0]};
  assert.equal((await f.op(neuro,'invite_info',{id})).status,404);
  assert.equal((await f.op(admin,'invite',data)).status,200);
  assert.equal((await f.op(admin,'invite',{id:legacyID,name:'Legacy',role:'bot'})).status,200);
  assert.equal((await f.op(neuro,'invite_info',{id:legacyID})).status,404);
  const signed=await envelope(neuro,'invite_info',{id}),corrupted={...signed,data:{id:rid()}};
  assert.equal((await f.handler(request({envelope:corrupted}))).status,403);
  const info=await f.handler(request({envelope:signed}));assert.equal(info.status,200);
  assert.equal((await f.handler(request({envelope:signed}))).status,409);
  f.roster.get(neuroID).state='revoked';
  assert.equal((await f.op(neuro,'invite_info',{id})).status,403);
  f.roster.get(neuroID).state='active';f.roster.get(adminID).state='revoked';
  assert.equal((await f.op(neuro,'invite_info',{id})).status,404);
  f.roster.get(adminID).state='active';f.setTime(NOW+86400000);
  assert.equal((await f.op(neuro,'invite_info',{id})).status,404);
  assert.equal(f.calls.some(call=>call[0]==='claim'),false);
});

test('invalid invitation lookup storage data cannot escape as a public card or stale success',async()=>{
  const f=fixture(),id=rid();
  for(const organizerCard of ['PSO-CARD1.invalid',' '+cards[0]]) {
    f.store.inviteInfo=async()=>({status:'ok',expires:NOW+1000,organizerCard});
    assert.equal((await f.op(neuro,'invite_info',{id})).status,503);
  }
  f.store.inviteInfo=async()=>({status:'ok',expires:NOW,organizerCard:cards[0]});
  assert.equal((await f.op(neuro,'invite_info',{id})).status,404);
});

test('group ciphertext opens independently for each selected intensivist, not neurologist or cardiologist',async()=>{
  const f=fixture(),data=await dataFor();const created=await f.op(neuro,'create',data);assert.equal(created.status,200);
  assert.equal((await created.json()).push,'accepted');
  for(const [device,id] of [[icuA,icuAID],[icuB,icuBID]]){
    const r=await f.op(device,'resolve',{id:data.id});assert.equal(r.status,200);const body=await r.json();
    assert.equal(body.token.split('.')[1],id);assert.equal(body.senderCard,cards[1]);
    assert.equal((await openSurname(device,body.token,[contacts[1]])).surname,'Иванов');
  }
  assert.equal((await f.op(cardio,'resolve',{id:data.id})).status,403);assert.equal((await f.op(neuro,'resolve',{id:data.id})).status,403);
  assert.equal(f.sent.length,2);for(const s of f.sent)assert.deepEqual(s.payload,{v:1,id:data.id,expires:data.expires});
  assert.ok(!JSON.stringify(f.sent.map(s=>s.payload)).includes('Иванов'));
});

test('kind and destination roles are enforced: only bot admissions and only neurologist/admin reviews',async()=>{
  const f=fixture();
  assert.equal((await f.op(neuro,'create',await dataFor(neuro,{kind:'admission'}))).status,403);
  assert.equal((await f.op(bot,'create',await dataFor(bot,{kind:'review'}))).status,403);
  assert.equal((await f.op(cardio,'create',await dataFor(cardio))).status,403);
  assert.equal((await f.op(bot,'create',await dataFor(bot,{kind:'admission',group:'cardiology',recipients:[contacts[2]]}))).status,200);
  assert.equal((await f.op(admin,'create',await dataFor(admin))).status,200);
});

test('incorrect recipient, mixed sender, invalid token signature and duplicate entries fail before DB admission',async()=>{
  const f=fixture(),data=await dataFor();
  const other=await dataFor(bot),badToken=data.entries[0].token.split('.');const s=Buffer.from(badToken[4],'base64url');s[0]^=1;badToken[4]=s.toString('base64url');
  for(const entries of [
    [{...data.entries[0],recipientId:cardioID},data.entries[1]],other.entries,
    [{...data.entries[0],token:badToken.join('.')},data.entries[1]]
  ])assert.equal((await f.op(neuro,'create',{...data,entries})).status,403);
  assert.equal((await f.op(neuro,'create',{...data,entries:[data.entries[0],data.entries[0]]})).status,400);
  assert.equal(f.calls.length,0);
});

test('identical committed retry remains valid past 60 seconds and never repeats push; changed ID data conflicts',async()=>{
  const f=fixture(),data=await dataFor();assert.equal((await f.op(neuro,'create',data)).status,200);assert.equal(f.sent.length,2);
  f.setTime(NOW+120000);f.roster.get(icuBID).state='revoked';
  const retry=await f.op(neuro,'create',data);assert.equal(retry.status,200);assert.equal(f.sent.length,2);
  assert.equal(f.calls.filter(c=>c[0]==='pushClaim').length,1);
  const altered=await f.op(neuro,'create',{...data,group:'cardiology'});assert.equal(altered.status,409);assert.deepEqual(await altered.json(),{error:'id_conflict'});
  assert.equal(f.links.size,1);
});

test('delayed first creation succeeds with fresh authentication and the same durable payload',async()=>{
  const f=fixture(),data=await dataFor();f.setTime(NOW+120000);
  const first=await f.op(neuro,'create',data);assert.equal(first.status,200);assert.equal(f.links.size,1);
  assert.equal((await first.json()).id,data.id);assert.equal(f.sent.length,2);
  const retry=await f.op(neuro,'create',data);assert.equal(retry.status,200);assert.equal(f.links.size,1);assert.equal(f.sent.length,2);
});

test('stale recipient set has a distinct no-commit roster_changed error',async()=>{
  const f=fixture(),data=await dataFor(neuro,{recipients:[contacts[3]]});const response=await f.op(neuro,'create',data);
  assert.equal(response.status,409);assert.deepEqual(await response.json(),{error:'roster_changed'});assert.equal(f.links.size,0);assert.equal(f.sent.length,0);
  const extra=await dataFor(neuro,{recipients:[contacts[3],contacts[4],contacts[2]]});assert.equal((await f.op(neuro,'create',extra)).status,409);
});

test('unknown/expired links yield 404 for legacy fallback; known links deny revoked recipients without fallback',async()=>{
  const f=fixture();f.roster.get(cardioID).state='revoked';assert.equal((await f.op(cardio,'resolve',{id:rid()})).status,404);
  const data=await dataFor();assert.equal((await f.op(neuro,'create',data)).status,200);
  f.roster.get(icuAID).state='revoked';assert.equal((await f.op(icuA,'resolve',{id:data.id})).status,403);
  f.setTime(data.expires);assert.equal((await f.op(icuB,'resolve',{id:data.id})).status,404);
});

test('partial/missing consent and provider failures preserve committed link and never reveal endpoints',async()=>{
  const f=fixture(),data=await dataFor();f.subscriptions.get(icuBID).senders=[];
  const response=await f.op(neuro,'create',data);assert.deepEqual(await response.json(),{id:data.id,expires:data.expires,push:'partial'});assert.equal(f.sent.length,1);
  const broken=fixture({throwSend:true,finishError:true}),d=await dataFor();const r=await broken.op(neuro,'create',d);
  assert.equal(r.status,200);assert.deepEqual(await r.json(),{id:d.id,expires:d.expires,push:'unavailable'});assert.equal(broken.links.size,1);assert.equal(broken.finished.length,2);
  assert.equal((await broken.op(icuA,'resolve',{id:d.id})).status,200);
  assert.equal((await broken.op(neuro,'create',d)).status,200);assert.equal(broken.sent.length,2);
});

test('push claim cannot add a recipient beyond the signed group manifest',async()=>{
  const f=fixture(),data=await dataFor();
  f.store.pushClaim=async()=>({targets:[{recipientId:cardioID,subscription:f.subscriptions.get(cardioID).subscription,expires:data.expires}]});
  const r=await f.op(neuro,'create',data);assert.equal(r.status,200);assert.equal((await r.json()).push,'unavailable');
  assert.equal(f.sent.length,0);assert.equal(f.links.size,1);
});

test('CORS, method, size, schema and canonical encoding checks precede privileged operations',async()=>{
  const f=fixture(),e=await envelope(admin,'status');
  assert.equal((await f.handler(request({envelope:e},{origin:'https://evil.example'}))).status,403);
  assert.equal((await f.handler(request(null,{method:'GET'}))).status,405);
  assert.equal((await f.handler(request(null,{raw:' '.repeat(MAX_TEAM_BODY_BYTES+1)}))).status,413);
  assert.equal((await f.handler(request({envelope:e},{headers:{'Content-Type':'text/plain'}}))).status,415);
  assert.equal((await f.handler(request({envelope:e},{url:URL+'?card=private'}))).status,400);
  assert.equal((await f.op(admin,'invite',{id:rid(),name:'A'.repeat(61),role:'neurologist'})).status,400);
  assert.equal((await f.op(admin,'approve',{deviceId:neuroID,role:'admin'})).status,400);
  assert.equal(f.calls.length,0);
  const preflight=await f.handler(request(null,{method:'OPTIONS',headers:{'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'Content-Type'}}));
  assert.equal(preflight.status,204);assert.equal(preflight.headers.get('access-control-allow-origin'),ORIGIN);
});

