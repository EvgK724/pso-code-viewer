import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {makeDevice} from '../docs/crypto.mjs';
import {exportPublicCard,importPublicCard,deviceIdentity,sealSurname,openSurname} from '../docs/exchange.mjs';
import {TeamClient,teamEnvelope,joinIDFromInput,randomTeamID} from '../docs/team.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const device=await makeDevice(),other=await makeDevice(),third=await makeDevice();
const base='https://viewer.example/pso-code-viewer/',endpoint='https://api.example/pso-team';
const cards=await Promise.all([device,other,third].map((d,i)=>exportPublicCard(d,'Доктор '+i)));
const contacts=await Promise.all(cards.map(importPublicCard));
const member=(i,role)=>({id:contacts[i].id,name:'Доктор '+i,role,card:cards[i]});
const reply=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});
function client(fn){return new TeamClient(endpoint,{fetch:async(u,options)=>{assert.equal(u,endpoint);assert.equal(options.credentials,'omit');assert.equal(options.cache,'no-store');assert.equal(options.redirect,'error');const {envelope}=JSON.parse(options.body);return fn(envelope,options);}});}

test('team envelope binds operation, entire data and own public card by existing key',async()=>{
 const e=await teamEnvelope(device,'claim',{id:randomTeamID()});const {signature,...unsigned}=e;
 const card=await importPublicCard(e.card);assert.equal(card.name,'Устройство');assert.equal(card.id,(await deviceIdentity(device)).id);
 const valid=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},card.signingPublicKey,Buffer.from(signature,'base64url'),new TextEncoder().encode('PSO-TEAM-v1\0'+JSON.stringify(unsigned)));assert.equal(valid,true);
 unsigned.data.id=randomTeamID();assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},card.signingPublicKey,Buffer.from(signature,'base64url'),new TextEncoder().encode('PSO-TEAM-v1\0'+JSON.stringify(unsigned))),false);
 assert.equal(e.nonce.length,22);
});
test('invite parser accepts only same origin/path canonical opaque ID',()=>{
 const id=randomTeamID();assert.equal(joinIDFromInput(base+'#join='+id,base),id);assert.equal(joinIDFromInput(base+'index.html#join='+id,base),id);
 for(const input of ['https://foreign.example/#join='+id,base+'?x=1#join='+id,base+'other/#join='+id,base+'#join=bad','https://user:pass@viewer.example/pso-code-viewer/#join='+id])assert.equal(joinIDFromInput(input,base),null);
});
test('authenticated directory validates every key and role without trusting asserted identity',async()=>{
 const list=await client(()=>reply({members:[member(0,'neurologist'),member(1,'cardiologist')]})).directory(device);assert.equal(list[1].verified,true);assert.equal(list[1].id,contacts[1].id);
 for(const entry of [{...member(1,'cardiologist'),id:contacts[2].id},{...member(1,'cardiologist'),role:'owner'},{...member(1,'cardiologist'),name:'Name\nInjected'}])await assert.rejects(client(()=>reply({members:[entry]})).directory(device));
 await assert.rejects(client(()=>reply({members:[member(1,'cardiologist'),member(1,'cardiologist')]})).directory(device));
});
test('review creation binds a complete roster while never sending surname plaintext',async()=>{
 const recipients=[contacts[1],contacts[2]].map(c=>({...c,verified:true}));const entries=await Promise.all(recipients.map(async r=>({recipientId:r.id,token:await sealSurname(device,r,'Тестов',{ttlMinutes:60})})));
 let payload;const c=client(e=>{payload=e.data;return reply({id:e.data.id,expires:e.data.expires,push:'partial'});});
 const result=await c.create(device,{group:'orit',ttlMinutes:60,entries},base);assert.equal(payload.kind,'review');assert.equal(payload.entries.length,2);assert.ok(!JSON.stringify(payload).includes('Тестов'));assert.match(result.link,/#r=[A-Za-z0-9_-]{22}$/);assert.equal(result.push,'partial');
 for(let i=0;i<2;i++){assert.equal((await openSurname([other,third][i],entries[i].token,[{...contacts[0],verified:true}])).surname,'Тестов');await assert.rejects(openSurname([third,other][i],entries[i].token,[{...contacts[0],verified:true}]));}
});
test('resolve binds returned sender card to token and refuses nonmember403',async()=>{
 const token=await sealSurname(device,{...contacts[1],verified:true},'Тестов');
 const record=await client(()=>reply({token,expires:Date.now()+60000,senderCard:cards[0],senderName:'Отправитель'})).resolve(other,randomTeamID());assert.equal(record.sender.id,contacts[0].id);assert.equal((await openSurname(other,record.token,[record.sender])).surname,'Тестов');
 await assert.rejects(client(()=>reply({token,expires:Date.now()+60000,senderCard:cards[2],senderName:'Отправитель'})).resolve(other,randomTeamID()),/не совпадает/);
 await assert.rejects(client(()=>reply({error:'request_rejected'},403)).resolve(other,randomTeamID()),e=>e.status===403);
});
test('status and invitation responses are validated; claim does not invent active membership',async()=>{
 const c=client(e=>e.op==='invite'?reply({id:e.data.id,expires:Date.now()+60000}):e.op==='claim'?reply({state:'pending'}):reply({state:'unregistered',role:null,name:null}));
 assert.equal((await c.status(device)).state,'unregistered');const invite=await c.invite(device,'Доктор','neurologist');assert.equal((await c.claim(device,invite.id)).state,'pending');
 await assert.rejects(c.invite(device,'Доктор','admin'));await assert.rejects(client(()=>reply({state:'active',role:'owner',name:'Doctor'})).status(device));
});
test('transport preserves HTTP error class and rejects malformed/oversized responses',async()=>{
 for(const status of [403,404,409,429])await assert.rejects(client(()=>reply({},status)).status(device),e=>e.status===status);
 await assert.rejects(client(()=>new Response('x'.repeat(1000001),{headers:{'Content-Type':'application/json'}})).status(device),/слишком большой/);
 await assert.rejects(client(()=>new Response('{}',{headers:{'Content-Type':'text/html'}})).status(device),/Неверный/);
});

test('new invitation submits a caller-owned exact public-card snapshot while old payload stays compatible',async()=>{
 let sent;const c=client(e=>{sent=e;return reply({id:e.data.id,expires:Date.now()+60000});});
 await c.invite(device,'Доктор','cardiologist',cards[0]);
 assert.equal(sent.op,'invite');assert.equal(sent.data.organizerCard,cards[0]);
 assert.deepEqual(Object.keys(sent.data).sort(),['id','name','organizerCard','role']);
 const before=sent;
 await assert.rejects(c.invite(device,'Доктор','cardiologist',cards[1]),/не совпадает/);assert.equal(sent,before);
 await assert.rejects(c.invite(device,'Доктор','cardiologist',' '+cards[0]),/не совпадает/);assert.equal(sent,before);
 await c.invite(device,'Доктор','cardiologist');assert.deepEqual(Object.keys(sent.data).sort(),['id','name','role']);
});

test('invitation info is a signed read-only operation with exact ID and card response',async()=>{
 const id=randomTeamID(),info={id,expires:Date.now()+60000,organizerCard:cards[0]};let sent;
 const result=await client(e=>{sent=e;return reply(info);}).invitationInfo(other,id);
 assert.deepEqual(result,info);assert.equal(sent.op,'invite_info');assert.deepEqual(sent.data,{id});
 const {signature,...unsigned}=sent,owner=await importPublicCard(sent.card);
 assert.equal(owner.id,contacts[1].id);
 assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},owner.signingPublicKey,Buffer.from(signature,'base64url'),new TextEncoder().encode('PSO-TEAM-v1\0'+JSON.stringify(unsigned))),true);
});

test('invitation info rejects missing, spent, expired and malformed responses without claim or fallback',async()=>{
 const id=randomTeamID(),info={id,expires:Date.now()+60000,organizerCard:cards[0]};
 for(const bad of [null,{}, {...info,extra:true}, {...info,id:randomTeamID()}, {...info,expires:Date.now()-1},
   {...info,expires:Date.now()+0.5}, {...info,organizerCard:' '+cards[0]}, {...info,organizerCard:'PSO-CARD1'}]){
   const ops=[];await assert.rejects(client(e=>{ops.push(e.op);return reply(bad);}).invitationInfo(other,id));
   assert.deepEqual(ops,['invite_info']);
 }
 for(const status of [403,404,409])await assert.rejects(client(()=>reply({},status)).invitationInfo(other,id),e=>e.status===status);
 let calls=0;await assert.rejects(client(()=>{calls++;return reply(info);}).invitationInfo(other,'bad'));assert.equal(calls,0);
});

test('additional role status preserves active membership and requests modern role projection',async()=>{
 const active={state:'active',role:'neurologist',name:'Давыдова',pendingRole:'rehab1_physician'};
 let sent;assert.deepEqual(await client(e=>{sent=e;return reply(active);}).status(device),active);assert.deepEqual(sent.data,{includeRoles:true});
 const multi={...active,roles:['neurologist','rehab1_physician']};delete multi.pendingRole;
 assert.deepEqual(await client(()=>reply(multi)).status(device),multi);
 const directory=await client(e=>{sent=e;return reply({members:[{...member(1,'neurologist'),roles:multi.roles}]});}).directory(device);
 assert.deepEqual(directory[0].roles,multi.roles);assert.equal(sent.data.includeRoles,true);
 for(const bad of [{...multi,roles:[]},{...multi,roles:['rehab1_physician','neurologist']},{...multi,roles:['neurologist','bot']},{...multi,roles:['neurologist','neurologist']},{...active,pendingRole:'neurologist'},{...active,pendingRole:'admin'},{state:'unregistered',role:null,name:null,roles:[]}])await assert.rejects(client(()=>reply(bad)).status(device));
});
