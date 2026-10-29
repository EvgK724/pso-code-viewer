import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto, createECDH, hkdfSync, createDecipheriv, createPublicKey, verify} from 'node:crypto';
import {createVapidKeys, validateSubscription, encryptPushPayload, sendWebPush} from './web-push.mjs';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const NOW = 1792785600000;
const decode = value => Buffer.from(value, 'base64url');
const encode = value => Buffer.from(value).toString('base64url');
const recipient = createECDH('prime256v1'); recipient.generateKeys();
const subscription = {
  endpoint:'https://web.push.apple.com/QSyntheticEndpoint', expirationTime:null,
  keys:{p256dh:encode(recipient.getPublicKey()),auth:encode(webcrypto.getRandomValues(new Uint8Array(16)))}
};
const vapid = await createVapidKeys();
const payload = {v:1,id:encode(webcrypto.getRandomValues(new Uint8Array(16))),expires:NOW + 3600000};
const captured = status => {
  const calls = [];
  return {calls, fetch:async (url, options) => {
    calls.push({url,options});
    return new Response(null,{status});
  }};
};

// This decoder uses Node's native crypto APIs, not the production WebCrypto
// derivation helper, to test interoperability rather than matching its mistakes.
function decryptBody(body, auth = decode(subscription.keys.auth)) {
  const wire = Buffer.from(body), salt = wire.subarray(0, 16), rs = wire.readUInt32BE(16), keyLength = wire[20];
  assert.equal(rs,4096); assert.equal(keyLength,65);
  const sender = wire.subarray(21,21+keyLength), encrypted = wire.subarray(21+keyLength);
  const shared = recipient.computeSecret(sender);
  const ikm = hkdfSync('sha256', shared, auth, Buffer.concat([Buffer.from('WebPush: info\0'),recipient.getPublicKey(),sender]),32);
  const key = hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'),16);
  const iv = hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'),12);
  const aes = createDecipheriv('aes-128-gcm', key, iv);
  aes.setAuthTag(encrypted.subarray(-16));
  const plaintext = Buffer.concat([aes.update(encrypted.subarray(0,-16)),aes.final()]);
  assert.equal(plaintext[plaintext.length-1],2);
  return plaintext.subarray(0,-1).toString('utf8');
}

test('RFC 8291 section 5 complete ciphertext known-answer vector', async () => {
  const receiverPublic = 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4';
  const senderPublic = 'BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8';
  const senderRaw = decode(senderPublic);
  const privateKey = await webcrypto.subtle.importKey('jwk',{
    kty:'EC',crv:'P-256',d:'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw',
    x:encode(senderRaw.subarray(1,33)),y:encode(senderRaw.subarray(33))
  },{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
  const publicKey = await webcrypto.subtle.importKey('raw',senderRaw,{name:'ECDH',namedCurve:'P-256'},true,[]);
  const body = await encryptPushPayload({endpoint:subscription.endpoint,keys:{p256dh:receiverPublic,auth:'BTBZMqHH6r4Tts7J_aSIgg'}},
    new TextEncoder().encode('When I grow up, I want to be a watermelon'),{
      senderPair:{privateKey,publicKey},salt:new Uint8Array(decode('DGv6ra1nlYgDCS1FRnbzlw'))
    });
  assert.equal(encode(body), 'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN');
});

test('wire payload independently decrypts and JWT independently verifies with correct audience', async () => {
  const f = captured(201);
  assert.deepEqual(await sendWebPush(subscription,vapid,payload,{fetch:f.fetch,now:()=>NOW}),{status:'accepted'});
  const {url,options} = f.calls[0];
  assert.equal(url,subscription.endpoint);
  assert.equal(options.method,'POST'); assert.equal(options.redirect,'error'); assert.equal(options.credentials,'omit');
  assert.equal(options.headers['Content-Encoding'],'aes128gcm'); assert.equal(options.headers.TTL,'3600');
  assert.equal(options.headers.Urgency,'normal');
  assert.deepEqual(JSON.parse(decryptBody(options.body)),payload);
  assert.ok(!Buffer.from(options.body).includes(Buffer.from(payload.id)));
  const authorization = options.headers.Authorization.match(/^vapid t=([^, ]+), k=([^, ]+)$/);
  assert.ok(authorization); assert.equal(authorization[2],vapid.publicKey);
  const [header,claims,signature] = authorization[1].split('.');
  assert.deepEqual(JSON.parse(decode(header)),{typ:'JWT',alg:'ES256'});
  assert.deepEqual(JSON.parse(decode(claims)),{aud:'https://web.push.apple.com',exp:Math.floor(NOW/1000)+3600,sub:'https://evgk724.github.io/pso-code-viewer/'});
  const {d,...publicJWK} = vapid.privateKey;
  assert.ok(verify('sha256',Buffer.from(header+'.'+claims),{key:createPublicKey({key:publicJWK,format:'jwk'}),dsaEncoding:'ieee-p1363'},decode(signature)));
  assert.ok(!JSON.stringify(options.headers).includes(d));
});

test('subscriptions canonicalize browser expiry and validate provider hosts and EC keys', async () => {
  const expected = {endpoint:subscription.endpoint,keys:subscription.keys};
  assert.deepEqual(await validateSubscription(subscription),expected);
  for (const host of ['fcm.googleapis.com','updates.push.services.mozilla.com','web.push.apple.com','a.b.push.apple.com']) {
    assert.equal((await validateSubscription({...subscription,endpoint:'https://'+host+'/push/x'})).endpoint,'https://'+host+'/push/x');
  }
  for (const url of [
    'http://web.push.apple.com/x','https://web.push.apple.com.evil.example/x','https://push.apple.com/x',
    'https://127.0.0.1/x','https://[::1]/x','https://localhost/x','https://example.com/x',
    'https://fcm.googleapis.com:443/x','https://fcm.googleapis.com:8443/x','https://u:p@fcm.googleapis.com/x',
    'https://fcm.googleapis.com/x#fragment','https://fcm.googleapis.com/x?target=localhost','https://fcm.googleapis.com/',
    'https://fcm.googleapis.com\\@127.0.0.1/x','https://fcm.googleapis.com./x'
  ]) await assert.rejects(validateSubscription({...subscription,endpoint:url}),/invalid/);
  for (const changed of [
    {...subscription,keys:{...subscription.keys,p256dh:encode(new Uint8Array(65))}},
    {...subscription,keys:{...subscription.keys,p256dh:encode(Uint8Array.from({length:65},(_,i)=>i===0?4:0))}},
    {...subscription,keys:{...subscription.keys,auth:encode(new Uint8Array(15))}},
    {...subscription,keys:{...subscription.keys,auth:'AAAAAAAAAAAAAAAAAAAAAB'}},
    {...subscription,expirationTime:'tomorrow'}, {...subscription,extra:'ignored?'}
  ]) await assert.rejects(validateSubscription(changed),/invalid/);
});

test('no patient field or arbitrary payload is accepted; test notification is constrained', async () => {
  const f = captured(201);
  for (const changed of [
    {...payload,surname:'Тестов'},{...payload,v:3},{...payload,id:'short'},{...payload,id:'AAAAAAAAAAAAAAAAAAAAAB'},
    {...payload,expires:NOW},{...payload,expires:NOW+86400001},{...payload,id:null}
  ]) assert.deepEqual(await sendWebPush(subscription,vapid,changed,{fetch:f.fetch,now:NOW}),{status:'failed'});
  assert.equal(f.calls.length,0);
  const ownTest = {v:1,id:null,expires:NOW+300000};
  assert.deepEqual(await sendWebPush(subscription,vapid,ownTest,{fetch:f.fetch,now:NOW,ttl:60}),{status:'accepted'});
  assert.deepEqual(JSON.parse(decryptBody(f.calls[0].options.body)),ownTest);
  assert.equal(f.calls[0].options.headers.TTL,'60');
});

test('direct inbox notification preserves its version and contains only opaque routing data', async () => {
  const f=captured(201), direct={...payload,v:2};
  assert.deepEqual(await sendWebPush(subscription,vapid,direct,{fetch:f.fetch,now:NOW}),{status:'accepted'});
  assert.deepEqual(JSON.parse(decryptBody(f.calls[0].options.body)),direct);
  assert.deepEqual(await sendWebPush(subscription,vapid,{...direct,id:null,expires:NOW+10000},{fetch:f.fetch,now:NOW}),{status:'failed'});
  assert.equal(f.calls.length,1);
});

test('direct notifications support two days while legacy notifications retain their one-day bound', async () => {
  const f=captured(201), direct={...payload,v:2,expires:NOW+172800000};
  assert.deepEqual(await sendWebPush(subscription,vapid,direct,{fetch:f.fetch,now:NOW,ttl:172800}),{status:'accepted'});
  assert.equal(f.calls[0].options.headers.TTL,'172800');
  assert.deepEqual(JSON.parse(decryptBody(f.calls[0].options.body)),direct);
  for(const changed of [{...direct,expires:direct.expires+1},{...direct,v:1}])
    assert.deepEqual(await sendWebPush(subscription,vapid,changed,{fetch:f.fetch,now:NOW}),{status:'failed'});
  assert.equal(f.calls.length,1);
});

test('each notification gets fresh ephemeral ECDH material and salt', async () => {
  const f = captured(202);
  for (let i=0;i<2;i++) assert.deepEqual(await sendWebPush(subscription,vapid,payload,{fetch:f.fetch,now:NOW}),{status:'accepted'});
  const a = Buffer.from(f.calls[0].options.body), b = Buffer.from(f.calls[1].options.body);
  assert.notDeepEqual(a.subarray(0,16),b.subarray(0,16));
  assert.notDeepEqual(a.subarray(21,86),b.subarray(21,86));
  assert.equal(decryptBody(a),decryptBody(b));
});

test('provider status is sanitized and expired subscriptions are distinguishable', async () => {
  for (const [code,status] of [[201,'accepted'],[202,'accepted'],[404,'gone'],[410,'gone'],[429,'limited'],[400,'failed'],[401,'failed'],[403,'failed'],[500,'failed'],[301,'failed']]) {
    const f = captured(code);
    assert.deepEqual(await sendWebPush(subscription,vapid,payload,{fetch:f.fetch,now:NOW}),{status});
  }
});

test('timeout, provider errors and invalid VAPID keys fail without secret detail', async () => {
  const transport = () => { throw new Error('Sensitive endpoint/token/private detail'); };
  assert.deepEqual(await sendWebPush(subscription,vapid,payload,{fetch:transport,now:NOW}),{status:'failed'});
  let didAbort = false;
  const hanging = async (_url,options) => new Promise((resolve,reject) => {
    options.signal.addEventListener('abort',()=>{ didAbort=true; reject(new Error('Aborted sensitive endpoint')); });
  });
  assert.deepEqual(await sendWebPush(subscription,vapid,payload,{fetch:hanging,now:NOW,timeout:5}),{status:'failed'});
  assert.equal(didAbort,true);
  const f = captured(201), another = await createVapidKeys();
  assert.deepEqual(await sendWebPush(subscription,{...vapid,publicKey:another.publicKey},payload,{fetch:f.fetch,now:NOW}),{status:'failed'});
  assert.equal(f.calls.length,0);
});

test('wire authentication rejects tampering or a different auth secret', async () => {
  const f = captured(201);
  await sendWebPush(subscription,vapid,payload,{fetch:f.fetch,now:NOW});
  const body = Buffer.from(f.calls[0].options.body);
  assert.throws(()=>decryptBody(body,Buffer.alloc(16)));
  body[body.length-1] ^= 1;
  assert.throws(()=>decryptBody(body));
});

test('release notification wire decrypts to a fixed non-patient schema with a seven-day TTL',async()=>{
  const f=captured(201),notice={v:1,type:'release',version:18,expires:NOW+7*86400000};
  assert.deepEqual(await sendWebPush(subscription,vapid,notice,{fetch:f.fetch,now:NOW,ttl:604800}),{status:'accepted'});
  assert.equal(f.calls[0].options.headers.TTL,'604800');
  assert.deepEqual(JSON.parse(decryptBody(f.calls[0].options.body)),notice);
  for(const changed of [
    {...notice,url:'https://other.example/'},{...notice,title:'Arbitrary'},{...notice,surname:'Тестов'},
    {...notice,version:16},{...notice,version:18.5},{...notice,version:'18'},
    {...notice,type:'patient'},{...notice,v:2},{...notice,expires:NOW+7*86400000+1},
    {...notice,expires:NOW},{...payload,v:2,expires:NOW+7*86400000}
  ])assert.deepEqual(await sendWebPush(subscription,vapid,changed,{fetch:f.fetch,now:NOW,ttl:604800}),{status:'failed'});
  assert.equal(f.calls.length,1,'Unexpected content never reaches a push provider');
});
