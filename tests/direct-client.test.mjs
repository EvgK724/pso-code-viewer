import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {makeDevice} from '../docs/crypto.mjs';
import {exportPublicCard,importPublicCard} from '../docs/exchange.mjs';
import {DirectClient,directEnvelope,directIDFromInput,newMessageID,validatePending} from '../docs/direct.mjs';
import {sealMessage} from '../docs/messages.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const device=await makeDevice(),recipient=await makeDevice(),card=await importPublicCard(await exportPublicCard(device,'Автор'));
const rc={...await importPublicCard(await exportPublicCard(recipient,'Получатель')),verified:true};
const response=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});

test('direct request signs operation and unlock token with device key and never adds session headers',async()=>{
  let envelope;const client=new DirectClient('https://service.example/pso-direct',{fetch:async(url,options)=>{
    assert.equal(url,'https://service.example/pso-direct');assert.equal(options.credentials,'omit');assert.equal(options.cache,'no-store');assert.equal(options.redirect,'error');assert.equal(options.referrerPolicy,'no-referrer');
    assert.deepEqual(options.headers,{'Content-Type':'application/json'});envelope=JSON.parse(options.body).envelope;return response({value:true});
  }});
  await client.request(device,'open',{id:newMessageID(),unlockToken:'only-in-signed-body'});
  const {signature,...unsigned}=envelope;
  assert.equal(unsigned.data.unlockToken,'only-in-signed-body');
  assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},card.signingPublicKey,Buffer.from(signature,'base64url'),new TextEncoder().encode('PSO-TEAM-v1\0'+JSON.stringify(unsigned))),true);
  unsigned.data.unlockToken='substituted';
  assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},card.signingPublicKey,Buffer.from(signature,'base64url'),new TextEncoder().encode('PSO-TEAM-v1\0'+JSON.stringify(unsigned))),false);
  await assert.rejects(directEnvelope(device,'delete_everything',{}));
});

test('direct URLs stay in the installed app path and accept only canonical random IDs',()=>{
  const id=newMessageID(),base='https://viewer.example/pso-code-viewer/';
  for(const path of ['', 'index.html'])assert.equal(directIDFromInput(base+path+'#m='+id,base),id);
  for(const input of ['https://evil.example/#m='+id,base+'extra/#m='+id,base+'?key=1#m='+id,base+'#m='+id+'&x=1','https://u@viewer.example/pso-code-viewer/#m='+id,base+'#m=abc'])assert.equal(directIDFromInput(input,base),null);
});

test('direct list rejects injected plaintext fields and invalid metadata',async()=>{
  const now=Date.now(),item={id:newMessageID(),group:'cardiology',kind:'review',issued:now,expires:now+60000,senderId:card.id,senderName:'Автор',openedAt:null,recipientCount:1,openedCount:0};
  let body={items:[item],next:null};const client=new DirectClient('https://service.example/api',{fetch:async()=>response(body)});
  assert.equal((await client.list(device)).items[0].id,item.id);
  for(const change of [{...item,surname:'Иванов'},{...item,openedCount:2},{...item,group:'public'},{...item,senderName:'Имя\nПодмена'}]){body={items:[change],next:null};await assert.rejects(client.list(device));}
});

test('encrypted retry queue validation rejects plaintext or altered outer fields',async()=>{
  const issued=Date.now(),meta={id:newMessageID(),group:'cardiology',kind:'review',issued,expires:issued+60000};
  const sealed=await sealMessage(device,[rc],{surname:'Иванов',comment:'Проверить историю'},meta),data={...meta,...sealed};
  assert.equal(validatePending(data),data);assert.ok(!JSON.stringify(data).includes('Иванов'));assert.ok(!JSON.stringify(data).includes('Проверить историю'));
  for(const change of [{...data,surname:'Иванов'},{...data,kind:'admission'},{...data,payload:{...data.payload,photo:'plaintext'}},{...data,entries:[{...data.entries[0],recipientId:card.id}]},{...data,entries:[{...data.entries[0],surname:'Иванов'}]}])assert.throws(()=>validatePending(change));
  assert.throws(()=>validatePending(data,meta.expires));
});

test('HTTP428 is distinguished for a single explicit device unlock retry',async()=>{
  const client=new DirectClient('https://service.example/api',{fetch:async()=>response({error:'unlock_required'},428)});
  await assert.rejects(client.open(device,newMessageID()),e=>e.status===428&&e.code==='unlock_required');
});
