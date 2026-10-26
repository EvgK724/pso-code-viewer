import test from 'node:test';
import assert from 'node:assert/strict';
import {createMemoryDatabase} from './test-db.mjs';
import {composeStores} from './runtime.mjs';
import {createDirectHandler} from '../direct-handler.mjs';
import {makeDevice,base64url} from '../../docs/crypto.mjs';
import {exportPublicCard,importPublicCard,sealSurname,openSurname} from '../../docs/exchange.mjs';
import {makeRecipientGrant} from '../../docs/recipient-trust.mjs';
import {sealMessage,openMessage} from '../../docs/messages.mjs';
const origin='https://viewer.example';
test('unchanged crypto handlers work with the real YDB store implementations',async()=>{
 const now=Date.now(),db=createMemoryDatabase({now:()=>now}),stores=composeStores(db);
 const devices=await Promise.all(Array.from({length:5},()=>makeDevice()));
 const roles=['admin','bot','cardiologist','intensivist','neurologist'];
 const cards=await Promise.all(devices.map(d=>exportPublicCard(d,'Тест')));
 const contacts=await Promise.all(cards.map(async c=>({...await importPublicCard(c),verified:true})));
 for(let i=0;i<devices.length;i++){
  const m={id:contacts[i].id,name:'Тест',role:roles[i],card:cards[i]};
  const proof=i?await makeRecipientGrant(devices[0],m,{now}):null;
  await db.seed('member:'+m.id,{device_id:m.id,name:m.name,role:m.role,card:m.card,state:'active',signing_spki:Buffer.from(await crypto.subtle.exportKey('spki',contacts[i].signingPublicKey)).toString('base64url'),approval_proof:proof,created_at:now,approved_at:now,revoked_at:null,invite_hash:null});
 }
 const handler=createDirectHandler({store:stores.direct,allowedOrigin:origin,now:()=>now,send:async()=>{throw new Error('No real push in local test');}});
 const randomId=()=>base64url(crypto.getRandomValues(new Uint8Array(16)));
 async function call(i,op,data={}){
  const e={v:1,op,issued:now,nonce:randomId(),card:cards[i],data};
  const signature=base64url(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},devices[i].signing.privateKey,new TextEncoder().encode('PSO-TEAM-v1\0'+JSON.stringify(e))));
  const response=await handler(new Request(origin+'/api/pso-direct',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:JSON.stringify({envelope:{...e,signature}})}));
  return {status:response.status,data:await response.json()};
 }
 const admission={id:randomId(),group:'cardiology',kind:'admission',issued:now,expires:now+3600000,entries:[{recipientId:contacts[2].id,token:await sealSurname(devices[1],contacts[2],'Вымышленный',{department:'ОРИТ',ttlMinutes:60,now})}]};
 assert.equal((await call(1,'create',admission)).status,200);
 assert.equal((await call(1,'create',admission)).status,200);
 const opened=await call(2,'open',{id:admission.id});assert.equal(opened.status,200);
 assert.equal((await openSurname(devices[2],opened.data.token,[contacts[1]],now)).surname,'Вымышленный');
 assert.equal((await call(3,'open',{id:admission.id})).status,403);
 assert.equal((await call(2,'ack',{id:admission.id})).status,200);
 assert.equal((await call(1,'outbox')).data.items[0].openedCount,1);
 const meta={id:randomId(),group:'orit',kind:'review',issued:now,expires:now+3600000};
 const encrypted=await sealMessage(devices[4],[contacts[3]],{surname:'Пример',department:'ОРИТ',comment:'Только тест',photo:null},meta);
 assert.equal((await call(4,'create',{...meta,...encrypted})).status,200);
 const review=await call(3,'open',{id:meta.id});assert.equal(review.status,200);
 assert.equal((await openMessage(devices[3],review.data.token,review.data.payload,[contacts[4]],now)).comment,'Только тест');
 assert(!JSON.stringify([...db.dump()]).includes('Вымышленный'));
 assert(!JSON.stringify([...db.dump()]).includes('Только тест'));
 assert.equal(await stores.team.revoke(contacts[0].id,contacts[2].id),'revoked');
 assert.equal((await call(2,'open',{id:admission.id})).status,403);
});
