import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {PushClient,pushEnvelope,pushKeyBytes} from '../docs/push.mjs';
import {makeDevice} from '../docs/crypto.mjs';
import {importPublicCard,deviceIdentity} from '../docs/exchange.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const endpoint='https://push.example/functions/v1/pso-push';
const decode=s=>Buffer.from(s,'base64url');
const encode=b=>Buffer.from(b).toString('base64url');
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json'}});

test('push requests prove possession of existing device signing key without real doctor or patient name',async()=>{
 const device=await makeDevice(); const old=device.signing.privateKey;
 const e=await pushEnvelope(device,'notify',{id:'AAAAAAAAAAAAAAAAAAAAAA'},1730000000000);
 const {signature,...unsigned}=e;
 const card=await importPublicCard(e.card);
 assert.equal(card.name,'Устройство'); assert.equal(card.id,(await deviceIdentity(device)).id);
 assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},card.signingPublicKey,decode(signature),new TextEncoder().encode('PSO-PUSH-v1\0'+JSON.stringify(unsigned))),true);
 assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},card.signingPublicKey,decode(signature),new TextEncoder().encode('PSO-PUSH-v1\0'+JSON.stringify({...unsigned,op:'test'}))),false);
 assert.equal(device.signing.privateKey,old);assert.equal(old.extractable,false);
 const second=await pushEnvelope(device,'notify',e.data,1730000000000);assert.notEqual(second.nonce,e.nonce);
});

test('notification registration authorizes only own identity and verified contact IDs',async()=>{
 const device=await makeDevice(),requests=[];
 const client=new PushClient(endpoint,{fetch:async(url,options)=>{requests.push(JSON.parse(options.body));assert.equal(options.redirect,'error');assert.equal(options.credentials,'omit');assert.equal(options.cache,'no-store');return json({status:'enabled'});}});
 const sub={toJSON:()=>({endpoint:'https://web.push.apple.com/a',keys:{auth:'a',p256dh:'b'}})};
 await client.register(device,sub,[{id:'verified',verified:true},{id:'unverified',verified:false},{id:'verified',verified:true}]);
 const body=requests[0].envelope;
 assert.deepEqual(body.data.senders,[(await deviceIdentity(device)).id,'verified'].sort());
 assert.deepEqual(body.data.subscription,sub.toJSON());assert.equal(body.op,'register');
});

test('push client validates config, canonical IDs, response shapes and transport errors',async()=>{
 const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const publicKey=encode(await crypto.subtle.exportKey('raw',pair.publicKey));
 const configClient=new PushClient(endpoint,{fetch:async()=>json({v:1,publicKey})});
 assert.equal(await configClient.config(),publicKey);assert.equal(pushKeyBytes(publicKey).length,65);
 assert.throws(()=>pushKeyBytes(publicKey.slice(1)));
 const device=await makeDevice();
 let calls=0; const client=new PushClient(endpoint,{fetch:async()=>{calls++;return json({status:'accepted'});}});
 assert.throws(()=>client.notify(device,'https://evil.test'));
 assert.throws(()=>client.notify(device,'AAAAAAAAAAAAAAAAAAAAAB'));
 assert.equal(calls,0);assert.equal(await client.notify(device,'AAAAAAAAAAAAAAAAAAAAAA'),'accepted');
 for(const response of [json({status:'delivered'}),json({status:'accepted',patient:'x'}),json({},429),json({},403),json({},500),new Response('x'.repeat(3000),{headers:{'Content-Type':'application/json'}})]) {
  const bad=new PushClient(endpoint,{fetch:async()=>response});await assert.rejects(bad.test(device));
 }
 const failed=new PushClient(endpoint,{fetch:async()=>{throw new TypeError('Secret transport detail');}});
 await assert.rejects(failed.test(device),error=>/Проверьте интернет/.test(error.message)&&!error.message.includes('Secret'));
});

test('default browser fetch is called with its required global receiver',async()=>{
 const original=globalThis.fetch;
 globalThis.fetch=function(){assert.equal(this,globalThis);return Promise.resolve(json({status:'disabled'}));};
 try {const client=new PushClient(endpoint);assert.equal(await client.status(await makeDevice()),'disabled');}
 finally {globalThis.fetch=original;}
});
