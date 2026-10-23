import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {createShortlinkHandler, MAX_BODY_BYTES} from './shortlink-handler.mjs';
import {makeDevice, base64url} from '../docs/crypto.mjs';
import {deviceIdentity, exportPublicCard, importPublicCard, sealSurname, openSurname} from '../docs/exchange.mjs';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const ORIGIN = 'https://viewer.example', API = 'https://broker.example/messages', NOW = Date.now();
const sender = await makeDevice(), recipient = await makeDevice();
const recipientContact = {...await importPublicCard(await exportPublicCard(recipient, 'Тестовый получатель')), verified:true};
const senderContact = {...await importPublicCard(await exportPublicCard(sender, 'Тестовый отправитель')), verified:true};
const senderID = (await deviceIdentity(sender)).id;
const token = await sealSurname(sender, recipientContact, 'Тестов', {department:'ОРИТ',ttlMinutes:60});
const enc = new TextEncoder();
const freshID = () => base64url(webcrypto.getRandomValues(new Uint8Array(16)));
async function envelope(overrides = {}, signingDevice = sender) {
  const e = {v:1,id:freshID(),token,issued:NOW,expires:NOW+3600000,...overrides};
  const unsigned = JSON.stringify({v:e.v,id:e.id,token:e.token,issued:e.issued,expires:e.expires});
  const signature = base64url(await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'}, signingDevice.signing.privateKey, enc.encode('PSO-SHORT-LINK-v1\0' + unsigned)));
  return {...e,signature};
}
function fixture({enabled=true, approved=true, forcedPut, at=NOW} = {}) {
  const rows = new Map(), writes = [];
  let creates = 0;
  const store = {
    async getWriter(id) { return approved && id === senderID ? {signingPublicKey:sender.signing.publicKey,enabled} : null; },
    async put(row) {
      writes.push(row);
      if (forcedPut) return forcedPut;
      const existing = rows.get(row.idHash);
      if (existing) return existing.requestHash === row.requestHash && existing.senderID === row.senderID ? 'exists' : 'conflict';
      rows.set(row.idHash, row); creates++;
      return 'created';
    },
    async resolve(idHash) { return rows.get(idHash) || null; }
  };
  return {rows,writes,store,creates:() => creates,handler:createShortlinkHandler({store,allowedOrigin:ORIGIN,now:() => at,crypto:webcrypto})};
}
function request(data, {origin=ORIGIN,url=API,method='POST',headers={}}={}) {
  return new Request(url,{method,headers:{Origin:origin,'Content-Type':'application/json',...headers},
    ...(method === 'POST' ? {body:JSON.stringify(data)} : {})});
}
async function create(f, e) { return f.handler(request({op:'create',envelope:e})); }

// Only ciphertext crosses this boundary; use synthetic names and actual WebCrypto.
test('approved creation and capability resolution preserve exact ciphertext and recipient decryption', async () => {
  const f = fixture(), e = await envelope();
  const created = await create(f,e);
  assert.equal(created.status,200);
  assert.deepEqual(await created.json(),{id:e.id,expires:e.expires});
  const row = f.writes[0];
  assert.match(row.idHash,/^[0-9a-f]{64}$/);
  assert.match(row.requestHash,/^[0-9a-f]{64}$/);
  assert.equal(row.now,NOW);
  assert.equal(row.senderID,senderID);
  assert.ok(!JSON.stringify(row).includes(e.id),'Raw capability ID is not stored');
  assert.ok(!JSON.stringify(row).includes('Тестов'),'No plaintext patient field is stored');
  const resolved = await f.handler(request({op:'resolve',id:e.id}));
  assert.equal(resolved.status,200);
  assert.equal(resolved.headers.get('cache-control'),'no-store');
  assert.equal(resolved.headers.get('referrer-policy'),'no-referrer');
  assert.equal(resolved.headers.get('access-control-allow-origin'),ORIGIN);
  const result = await resolved.json();
  assert.deepEqual(result,{token,expires:e.expires});
  assert.equal((await openSurname(recipient,result.token,[senderContact])).surname,'Тестов');
});

test('unknown, disabled and concurrently revoked writers cannot store messages', async () => {
  for (const opts of [{approved:false},{enabled:false},{forcedPut:'denied'}]) {
    const f = fixture(opts), response = await create(f,await envelope());
    assert.equal(response.status,403);
    assert.equal(f.creates(),0);
  }
});

test('both creation envelope and inner PSO1 signature must verify', async () => {
  const f = fixture(), original = await envelope();
  const changedID = {...original,id:freshID()};
  assert.equal((await create(f,changedID)).status,403);
  const wrongWriter = await envelope({},recipient);
  assert.equal((await create(f,wrongWriter)).status,403);
  const parts = token.split('.');
  parts[3] = (parts[3][0] === 'A' ? 'B' : 'A') + parts[3].slice(1);
  const resignedOuter = await envelope({token:parts.join('.')});
  assert.equal((await create(f,resignedOuter)).status,403,'Fresh outer signature does not permit tampered ciphertext');
  assert.equal(f.writes.length,0);
});

test('idempotent retries do not consume another create; changed records cannot overwrite an ID', async () => {
  const f = fixture(), e = await envelope();
  assert.equal((await create(f,e)).status,200);
  assert.equal((await create(f,e)).status,200);
  const newSignature = await envelope({id:e.id,issued:e.issued,expires:e.expires});
  assert.equal((await create(f,newSignature)).status,200,'Signature randomness does not change request identity');
  assert.equal(f.creates(),1);
  assert.equal((await create(f,await envelope({id:e.id,expires:e.expires+1}))).status,409);
  assert.equal(f.creates(),1);
});

test('freshness, TTL and server-side expiration are enforced even if storage returns expired rows', async () => {
  for (const change of [
    {issued:NOW-60001},{issued:NOW+30001},{expires:NOW},{expires:NOW-1},
    {expires:NOW+86400001},{issued:NOW+1,expires:NOW+1}
  ]) {
    const f = fixture();
    assert.equal((await create(f,await envelope(change))).status,400);
    assert.equal(f.writes.length,0);
  }
  const f = fixture(), e = await envelope();
  await create(f,e);
  const expiredHandler = createShortlinkHandler({store:f.store,allowedOrigin:ORIGIN,now:() => e.expires,crypto:webcrypto});
  assert.equal((await expiredHandler(request({op:'resolve',id:e.id}))).status,404);
  assert.equal((await f.handler(request({op:'resolve',id:freshID()}))).status,404);
});

test('exact origin, JSON schema, POST-only routing and restricted preflight are enforced', async () => {
  const f = fixture(), e = await envelope();
  const forbidden = await f.handler(request({op:'create',envelope:e},{origin:'https://other.example'}));
  assert.equal(forbidden.status,403);
  assert.equal(forbidden.headers.get('access-control-allow-origin'),null);
  assert.equal((await f.handler(request(null,{method:'GET'}))).status,405);
  assert.equal((await f.handler(request({op:'list'}))).status,400);
  assert.equal((await f.handler(request({op:'resolve',id:freshID()},{url:API+'?id=anything'}))).status,400);
  assert.equal((await f.handler(request({op:'resolve',id:freshID(),extra:'ignored?'}))).status,400);
  assert.equal((await f.handler(request({op:'create',envelope:{...e,patient:'Тестов'}}))).status,400);
  assert.equal((await f.handler(request({op:'resolve',id:'123456'}))).status,400);
  assert.equal((await f.handler(request({op:'resolve',id:freshID()},{headers:{'Content-Type':'text/plain'}}))).status,415);
  const options = await f.handler(request(null,{method:'OPTIONS',headers:{'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'content-type'}}));
  assert.equal(options.status,204);
  assert.equal(options.headers.get('access-control-allow-methods'),'POST');
  assert.equal((await f.handler(request(null,{method:'OPTIONS',headers:{'Access-Control-Request-Method':'DELETE'}}))).status,403);
});

test('oversized content is rejected even without Content-Length and response contains no input data', async () => {
  const f = fixture();
  const body = new ReadableStream({start(controller) {
    controller.enqueue(new Uint8Array(MAX_BODY_BYTES));
    controller.enqueue(enc.encode('PRIVATE_MARKER'));
    controller.close();
  }});
  const response = await f.handler(new Request(API,{method:'POST',headers:{Origin:ORIGIN,'Content-Type':'application/json'},body,duplex:'half'}));
  assert.equal(response.status,413);
  assert.ok(!(await response.text()).includes('PRIVATE_MARKER'));
  assert.equal(f.writes.length,0);
  const declared = request({op:'resolve',id:freshID()},{headers:{'Content-Length':String(MAX_BODY_BYTES+1)}});
  assert.equal((await f.handler(declared)).status,413);
});

test('quota and store failures return generic controlled responses', async () => {
  const limited = fixture({forcedPut:'limited'});
  assert.equal((await create(limited,await envelope())).status,429);
  const failed = fixture();
  failed.store.put = async () => { throw new Error('Do not expose connection secrets'); };
  const response = await create(failed,await envelope());
  assert.equal(response.status,503);
  assert.deepEqual(await response.json(),{error:'request_rejected'});
});
