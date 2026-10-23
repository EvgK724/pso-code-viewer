// Signed HTTP protocol tests with real WebCrypto. Storage is deliberately fake;
// its ownership, quota and replay decisions must also be checked against SQL.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {createPushHandler} from './push-handler.mjs';
import {createVapidKeys} from './web-push.mjs';
import {makeDevice,base64url} from '../docs/crypto.mjs';
import {deviceIdentity,exportPublicCard} from '../docs/exchange.mjs';
import {pushEnvelope} from '../docs/push.mjs';

if(!globalThis.crypto)globalThis.crypto=webcrypto;
const ORIGIN='https://viewer.example', API='https://service.example/functions/v1/pso-push', NOW=1792785600000;
const alice=await makeDevice(),bob=await makeDevice(),mallory=await makeDevice();
const aliceID=(await deviceIdentity(alice)).id,bobID=(await deviceIdentity(bob)).id,malloryID=(await deviceIdentity(mallory)).id;
const vapid=await createVapidKeys(),enc=new TextEncoder();
const subPair=await webcrypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
const subscription={endpoint:'https://web.push.apple.com/synthetic-subscription',expirationTime:null,
  keys:{p256dh:base64url(await webcrypto.subtle.exportKey('raw',subPair.publicKey)),auth:base64url(webcrypto.getRandomValues(new Uint8Array(16)))}};
const freshID=()=>base64url(webcrypto.getRandomValues(new Uint8Array(16)));
const hashID=async id=>Buffer.from(await webcrypto.subtle.digest('SHA-256',Buffer.from(id,'base64url'))).toString('hex');
const signed=(device,op,data={},at=NOW)=>pushEnvelope(device,op,data,at);
function request(body,{origin=ORIGIN,url=API,method='POST',headers={},raw}={}) {
  return new Request(url,{method,headers:{Origin:origin,'Content-Type':'application/json',...headers},
    ...(method==='POST'?{body:raw===undefined?JSON.stringify(body):raw}:{})});
}
function fixture({acceptResult,registerResult,claimResult,sendResult='accepted',throwSend=false,sendGate,at=NOW}={}) {
  const calls=[], sends=[], nonces=new Set(), subscribers=new Map(), links=new Map(), deliveries=new Map(), approved=new Set([aliceID]);
  const store={
    async keys(value){calls.push(['keys',value]);return vapid;},
    async accept(owner,nonce,op,issued){
      calls.push(['accept',owner,nonce,op,issued]);if(acceptResult)return acceptResult;
      const key=owner+':'+nonce;if(nonces.has(key))return'replay';nonces.add(key);return'ok';
    },
    async register(owner,sub,senders){calls.push(['register',owner,sub,senders]);if(registerResult)return registerResult;subscribers.set(owner,{sub,senders});return'ok';},
    async unregister(owner){calls.push(['unregister',owner]);subscribers.delete(owner);},
    async status(owner){calls.push(['status',owner]);return subscribers.has(owner);},
    async testSubscription(owner){calls.push(['testSubscription',owner]);return subscribers.get(owner)?.sub||null;},
    async claim(owner,idHash){
      calls.push(['claim',owner,idHash]);if(claimResult)return claimResult;
      const link=links.get(idHash),subscriber=link&&subscribers.get(link.recipient);
      if(!approved.has(owner)||!link||link.sender!==owner||link.expires<=at||!subscriber||!subscriber.senders.includes(owner))return{status:'unavailable'};
      if(deliveries.has(idHash))return{status:deliveries.get(idHash)};
      deliveries.set(idHash,'already');return{status:'ready',subscription:subscriber.sub,expires:link.expires};
    },
    async finish(idHash,status){calls.push(['finish',idHash,status]);deliveries.set(idHash,status);}
  };
  const send=async(sub,keys,payload,options)=>{
    sends.push({sub,keys,payload,options});if(sendGate)await sendGate;if(throwSend)throw new Error('Sensitive provider detail');return{status:sendResult};
  };
  const handler=createPushHandler({store,allowedOrigin:ORIGIN,crypto:webcrypto,now:()=>at,send});
  return{calls,sends,store,subscribers,links,deliveries,approved,handler,
    async op(device,op,data={},options={}){return handler(request({envelope:await signed(device,op,data)},options));},
    async addLink({sender=aliceID,recipient=bobID,expires=NOW+3600000}={}){
      const id=freshID();links.set(await hashID(id),{sender,recipient,expires,token:'immutable-synthetic-ciphertext'});return id;
    }};
}
async function subscribe(f,device=bob,senders=[aliceID]) {
  const response=await f.op(device,'register',{subscription,senders});assert.equal(response.status,200);return response;
}

test('public config exposes only VAPID public key, caches server key access, and never returns secrets',async()=>{
  const f=fixture();
  for(let i=0;i<2;i++){
    const response=await f.handler(request({op:'config'}));assert.equal(response.status,200);
    assert.equal(response.headers.get('cache-control'),'no-store');
    assert.deepEqual(await response.json(),{v:1,publicKey:vapid.publicKey});
  }
  assert.equal(f.calls.filter(c=>c[0]==='keys').length,1);
  assert.equal(f.sends.length,0);
  assert.equal(f.calls.filter(c=>c[0]==='accept').length,0);
});

test('initial VAPID generation stays inside server storage and a failed key lookup can recover',async()=>{
  const f=fixture();let saved=null,failOnce=true;
  f.store.keys=async value=>{
    if(failOnce){failOnce=false;throw new Error('Private storage detail');}
    if(value)saved=value;
    return saved;
  };
  const failed=await f.handler(request({op:'config'}));assert.equal(failed.status,503);
  assert.deepEqual(await failed.json(),{error:'request_rejected'});
  const retried=await f.handler(request({op:'config'}));assert.equal(retried.status,200);
  assert.ok(saved?.privateKey?.d,'Generated private VAPID key is delivered only to the server store');
  assert.deepEqual(await retried.json(),{v:1,publicKey:saved.publicKey});
});

test('registration derives owner from signature, validates subscription and normalizes sender allowlist',async()=>{
  const f=fixture();
  const response=await f.op(bob,'register',{subscription,senders:[aliceID,aliceID,bobID]});
  assert.equal(response.status,200);assert.deepEqual(await response.json(),{status:'enabled'});
  const registration=f.calls.find(c=>c[0]==='register');
  assert.equal(registration[1],bobID);
  assert.deepEqual(registration[2],{endpoint:subscription.endpoint,keys:subscription.keys});
  assert.deepEqual(registration[3],[aliceID,bobID].sort());
  assert.equal(f.sends.length,0,'Registering does not send an unsolicited notification');
  for(const data of [
    {subscription,senders:[aliceID],owner:aliceID},
    {subscription:{...subscription,endpoint:'https://127.0.0.1/private'},senders:[]},
    {subscription,senders:['bad']},{subscription,senders:Array(101).fill(aliceID)},
    {subscription,senders:'all'},{subscription:{...subscription,keys:{...subscription.keys,p256dh:'bad'}},senders:[]}
  ]) assert.equal((await f.op(bob,'register',data)).status,400);
  assert.equal(f.calls.filter(c=>c[0]==='register').length,1);
});

test('all signed fields are bound: card, operation, timestamp, nonce, payload and signature',async()=>{
  const f=fixture(),original=await signed(bob,'register',{subscription,senders:[aliceID]});
  const otherCard=await exportPublicCard(mallory,'Устройство');
  const signature=Buffer.from(original.signature,'base64url');signature[0]^=1;
  const mutations=[
    {...original,card:otherCard},{...original,op:'unregister'},
    {...original,issued:NOW-1},{...original,nonce:freshID()},
    {...original,data:{subscription,senders:[malloryID]}},
    {...original,data:{subscription:{...subscription,endpoint:'https://web.push.apple.com/different'},senders:[aliceID]}},
    {...original,signature:signature.toString('base64url')}
  ];
  for(const envelope of mutations) assert.equal((await f.handler(request({envelope}))).status,403);
  assert.equal(f.calls.length,0,'Unverified requests never reach replay, DB or key store');
  assert.equal(f.sends.length,0);
  const wrongSigned=await signed(mallory,'status');wrongSigned.card=original.card;
  assert.equal((await f.handler(request({envelope:wrongSigned}))).status,403);
});

test('timestamp boundaries, replay and rate-limit storage outcomes are enforced',async()=>{
  for(const issued of [NOW-60001,NOW+30001,1.5]){
    const f=fixture(),e=await signed(bob,'status',{},Number.isInteger(issued)?issued:NOW);e.issued=issued;
    assert.equal((await f.handler(request({envelope:e}))).status,400);assert.equal(f.calls.length,0);
  }
  for(const issued of [NOW-60000,NOW+30000]){
    const f=fixture();assert.equal((await f.handler(request({envelope:await signed(bob,'status',{},issued)}))).status,200);
  }
  const f=fixture(),e=await signed(bob,'status');
  assert.equal((await f.handler(request({envelope:e}))).status,200);
  assert.equal((await f.handler(request({envelope:e}))).status,409);
  assert.equal(f.calls.filter(c=>c[0]==='status').length,1);
  assert.equal((await fixture({acceptResult:'limited'}).op(bob,'status')).status,429);
  assert.equal((await fixture({acceptResult:'denied'}).op(bob,'status')).status,400);
  assert.equal((await fixture({registerResult:'limited'}).op(bob,'register',{subscription,senders:[]})).status,429);
});

test('status, unsubscribe and test operate only on the signing device',async()=>{
  const f=fixture();await subscribe(f);
  assert.deepEqual(await(await f.op(bob,'status')).json(),{status:'enabled'});
  assert.deepEqual(await(await f.op(mallory,'status')).json(),{status:'disabled'});
  for(const op of ['status','test','unregister']){
    assert.equal((await f.op(mallory,op,{owner:bobID})).status,400);
    assert.equal((await f.op(mallory,op,{recipient:bobID})).status,400);
  }
  assert.deepEqual(await(await f.op(mallory,'test')).json(),{status:'unavailable'});
  assert.equal(f.sends.length,0);
  assert.deepEqual(await(await f.op(bob,'test')).json(),{status:'accepted'});
  assert.deepEqual(f.sends[0].payload,{v:1,id:null,expires:NOW+120000});
  assert.equal(f.sends[0].options.ttl,120);
  assert.deepEqual(f.sends[0].sub,{endpoint:subscription.endpoint,keys:subscription.keys});
  assert.deepEqual(await(await f.op(mallory,'unregister')).json(),{status:'disabled'});
  assert.equal(f.subscribers.has(bobID),true);
  assert.deepEqual(await(await f.op(bob,'unregister')).json(),{status:'disabled'});
  assert.equal(f.subscribers.has(bobID),false);
});

test('notify binds a hashed capability to the signed sender and sends generic metadata to claimed recipient',async()=>{
  const f=fixture();await subscribe(f);const id=await f.addLink(),idHash=await hashID(id);
  const before=JSON.stringify(f.links.get(idHash));
  const response=await f.op(alice,'notify',{id});assert.equal(response.status,200);
  assert.deepEqual(await response.json(),{status:'accepted'});
  assert.deepEqual(f.calls.find(c=>c[0]==='claim'),['claim',aliceID,idHash]);
  assert.deepEqual(f.sends[0].payload,{v:1,id,expires:NOW+3600000});
  assert.equal(f.sends[0].options.ttl,3600);
  assert.equal(JSON.stringify(f.links.get(idHash)),before,'Notification does not modify stored shortlink');
  assert.deepEqual(f.calls.find(c=>c[0]==='finish'),['finish',idHash,'accepted']);
  assert.deepEqual(await(await f.op(alice,'notify',{id})).json(),{status:'accepted'});
  assert.equal(f.sends.length,1,'A new signed retry cannot send the same link twice');
});

test('unavailable, unauthorized, expired and duplicate claims never dispatch',async()=>{
  const f=fixture();await subscribe(f);const id=await f.addLink();
  assert.deepEqual(await(await f.op(mallory,'notify',{id})).json(),{status:'unavailable'});
  assert.deepEqual(f.calls.find(c=>c[0]==='claim'),['claim',malloryID,await hashID(id)]);
  f.approved.delete(aliceID);
  assert.deepEqual(await(await f.op(alice,'notify',{id})).json(),{status:'unavailable'});
  f.approved.add(aliceID);
  f.subscribers.get(bobID).senders=[bobID];
  assert.deepEqual(await(await f.op(alice,'notify',{id})).json(),{status:'unavailable'});
  f.subscribers.get(bobID).senders=[aliceID];
  const expired=await f.addLink({expires:NOW-1});
  assert.deepEqual(await(await f.op(alice,'notify',{id:expired})).json(),{status:'unavailable'});
  assert.equal(f.sends.length,0);
  for(const status of ['accepted','already','gone','failed','unavailable','unknown']){
    const g=fixture({claimResult:{status}});
    assert.deepEqual(await(await g.op(alice,'notify',{id})).json(),{status:status==='unknown'?'unavailable':status});
    assert.equal(g.sends.length,0);
  }
});

test('notify rejects extra recipient fields and malformed/noncanonical capabilities before DB access',async()=>{
  for(const data of [{id:freshID(),recipient:malloryID},{id:'AAAA'},{id:'AAAAAAAAAAAAAAAAAAAAAB'}, {id:null},{}]){
    const f=fixture();assert.equal((await f.op(alice,'notify',data)).status,400);assert.equal(f.calls.length,0);
  }
});

test('a concurrent duplicate reports already while the first claimed notification is in flight',async()=>{
  let release;const gate=new Promise(resolve=>{release=resolve;});
  const f=fixture({sendGate:gate});await subscribe(f);const id=await f.addLink();
  const first=f.op(alice,'notify',{id});
  for(let i=0;i<100&&!f.sends.length;i++)await new Promise(resolve=>setTimeout(resolve,2));
  assert.equal(f.sends.length,1);
  const duplicate=await f.op(alice,'notify',{id});assert.deepEqual(await duplicate.json(),{status:'already'});
  assert.equal(f.sends.length,1);
  release();assert.deepEqual(await(await first).json(),{status:'accepted'});
});

test('invalid claimed expiry is recorded failed, and send failures never alter shortlink ciphertext',async()=>{
  for(const expires of [NOW-1,NOW,NOW+86400001,'later']){
    const f=fixture({claimResult:{status:'ready',subscription,expires}}),id=freshID();
    assert.deepEqual(await(await f.op(alice,'notify',{id})).json(),{status:'failed'});
    assert.equal(f.sends.length,0);assert.deepEqual(f.calls.find(c=>c[0]==='finish'),['finish',await hashID(id),'failed']);
  }
  for(const opts of [{sendResult:'failed'},{sendResult:'limited'},{sendResult:'gone'},{throwSend:true}]){
    const f=fixture(opts);await subscribe(f);const id=await f.addLink(),idHash=await hashID(id),before=JSON.stringify(f.links.get(idHash));
    const response=await f.op(alice,'notify',{id});
    assert.equal(response.status,opts.throwSend?503:200);
    assert.deepEqual(await response.json(),opts.throwSend?{error:'request_rejected'}:{status:opts.sendResult==='gone'?'gone':'failed'});
    assert.equal(f.deliveries.get(idHash),opts.sendResult==='gone'?'gone':'failed');
    assert.equal(JSON.stringify(f.links.get(idHash)),before);
  }
});

test('CORS, methods, body shape, JSON encoding and size are restricted before mutations',async()=>{
  const f=fixture();
  const forbidden=await f.handler(request({op:'config'},{origin:'https://evil.example'}));
  assert.equal(forbidden.status,403);assert.equal(forbidden.headers.get('access-control-allow-origin'),null);
  assert.equal((await f.handler(request({op:'config'},{method:'GET'}))).status,405);
  for(const url of [API+'?x=1',API+'#fragment'])assert.equal((await f.handler(request({op:'config'},{url}))).status,400);
  assert.equal((await f.handler(request({op:'config'},{headers:{'Content-Type':'text/plain'}}))).status,415);
  for(const body of [{op:'config',extra:true},{envelope:{}},{envelope:null},{envelope:{v:1}},[]])assert.equal((await f.handler(request(body))).status,400);
  assert.equal((await f.handler(request(null,{raw:'not JSON'}))).status,400);
  assert.equal((await f.handler(request(null,{raw:Uint8Array.of(0xff,0xfe)}))).status,400);
  assert.equal((await f.handler(request({op:'config'},{headers:{'Content-Length':'16385'}}))).status,413);
  assert.equal((await f.handler(request(null,{raw:' '.repeat(16385)}))).status,413);
  const preflight=await f.handler(request(null,{method:'OPTIONS',headers:{'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'content-type'}}));
  assert.equal(preflight.status,204);assert.equal(preflight.headers.get('access-control-allow-origin'),ORIGIN);
  assert.equal((await f.handler(request(null,{method:'OPTIONS',headers:{'Access-Control-Request-Method':'PUT'}}))).status,403);
  assert.equal((await f.handler(request(null,{method:'OPTIONS',headers:{'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization'}}))).status,403);
  assert.equal(f.calls.length,0);assert.equal(f.sends.length,0);
});
