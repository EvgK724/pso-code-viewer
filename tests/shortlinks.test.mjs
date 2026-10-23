import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {ShortLinkClient, createEnvelope, shortLinkFor, shortIDFromInput} from '../docs/shortlinks.mjs';
import {makeDevice} from '../docs/crypto.mjs';
import {exportPublicCard, importPublicCard, sealSurname, openSurname} from '../docs/exchange.mjs';
if (!globalThis.crypto) globalThis.crypto=webcrypto;
const base='https://viewer.example/pso-code-viewer/', endpoint='https://relay.example/shortlinks';
const sender=await makeDevice(), recipient=await makeDevice();
const senderCard={...await importPublicCard(await exportPublicCard(sender,'Отправитель')),verified:true};
const recipientCard={...await importPublicCard(await exportPublicCard(recipient,'Получатель')),verified:true};
const encrypted=await sealSurname(sender,recipientCard,'Тестов',{ttlMinutes:60,department:'ОРИТ'});
const id='iR9wA12kxX6NubGJvNR7nQ';
const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});

test('default browser fetch preserves its global receiver for create and resolve',async()=>{
  const originalFetch=globalThis.fetch;
  let record, calls=0;
  // Browser fetch performs a receiver check that permissive Node fetch and the
  // arrow-function transports in earlier tests do not reproduce.
  globalThis.fetch=async function(url,options) {
    if(this!==globalThis) throw new TypeError('Illegal invocation');
    calls++;
    assert.equal(url,endpoint);
    const body=JSON.parse(options.body);
    if(body.op==='create') { record=body.envelope; return json({id:record.id,expires:record.expires}); }
    assert.equal(body.id,record.id);
    return json({token:record.token,expires:record.expires});
  };
  try {
    const client=new ShortLinkClient(endpoint);
    const url=await client.create(sender,encrypted,60,base);
    assert.match(new URL(url).hash,/^#r=[A-Za-z0-9_-]{22}$/);
    assert.equal(await client.resolve(url,base),encrypted);
    assert.equal(calls,2);
  } finally { globalThis.fetch=originalFetch; }
});

test('actual short URL is under 80 characters and accepts full pasted message without losing the URL',()=>{
  const url=shortLinkFor(id,base);
  assert.ok(url.length<80);
  assert.equal(url,base+'#r='+id);
  assert.equal(shortIDFromInput(url,base),id);
  assert.equal(shortIDFromInput('Новый пациент ОРИТ\n'+url,base),id);
  assert.equal(shortIDFromInput('Проверочная история\r\n'+url,base),id);
  assert.equal(shortIDFromInput('Новый пациент',base),null);
  assert.equal(shortIDFromInput('https://viewer.example/pso-code-viewer/#pso='+encrypted,base),null);
});
test('short URL rejects foreign origin/path, query leakage, credentials, extra fields and noncanonical IDs',()=>{
  for(const bad of ['https://other.example/pso-code-viewer/#r='+id,base.replace('/pso-code-viewer/','/other/')+'#r='+id,base+'?token=x#r='+id,'https://x:y@viewer.example/pso-code-viewer/#r='+id,base+'#r='+id+'&more=x',base+'#r='+id.slice(0,-1)+'R']) assert.throws(()=>shortIDFromInput(bad,base));
  assert.throws(()=>shortLinkFor('tiny',base));
  assert.throws(()=>shortLinkFor(id,'http://viewer.example/'));
});
test('signed envelope binds ciphertext, ID and expiry with existing nonexportable device key',async()=>{
  const e=await createEnvelope(sender,encrypted,60);
  const {signature,...unsigned}=e;
  const bytes=Buffer.from(signature,'base64url');
  const signed=value=>new TextEncoder().encode('PSO-SHORT-LINK-v1\0'+JSON.stringify(value));
  assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},sender.signing.publicKey,bytes,signed(unsigned)),true);
  assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},sender.signing.publicKey,bytes,signed({...unsigned,expires:e.expires+1})),false);
  assert.equal(e.token,encrypted);
  assert.equal(e.expires-e.issued,3600000);
  assert.equal(Buffer.from(e.id,'base64url').length,16);
  assert.ok(!JSON.stringify(e).includes('Тестов'));
  assert.equal(sender.signing.privateKey.extractable,false);
  await assert.rejects(createEnvelope(sender,'Тестов',60));
});
test('create then resolve transfers ciphertext only in POST body, preserves decryption and recipient restriction',async()=>{
  let record, calls=0;
  const client=new ShortLinkClient(endpoint,{fetch:async(url,options)=>{
    calls++;
    assert.equal(url,endpoint);
    assert.equal(options.method,'POST');
    assert.equal(options.credentials,'omit');
    assert.equal(options.cache,'no-store');
    assert.equal(options.redirect,'error');
    assert.equal(options.referrerPolicy,'no-referrer');
    assert.ok(!options.body.includes('Тестов'));
    const body=JSON.parse(options.body);
    if(body.op==='create') { record=body.envelope; return json({id:record.id,expires:record.expires}); }
    assert.equal(body.id,record.id);
    return json({token:record.token,expires:record.expires});
  }});
  const url=await client.create(sender,encrypted,60,base);
  assert.ok(url.length<80 && !url.includes(encrypted));
  const resolved=await client.resolve('Новый пациент ОРИТ\n'+url,base);
  assert.equal(resolved,encrypted);
  const opened=await openSurname(recipient,resolved,[senderCard]);
  assert.equal(opened.surname,'Тестов'); assert.equal(opened.department,'ОРИТ');
  await assert.rejects(openSurname(sender,resolved,[senderCard]),/другому получателю/);
  assert.equal(calls,2);
});
test('failed registration never returns a misleading link, and resolve rejects expired or malformed responses',async()=>{
  const client=new ShortLinkClient(endpoint,{fetch:async()=>json({id,expires:Date.now()+60000})});
  await assert.rejects(client.create(sender,encrypted,60,base),/не подтвердил/);
  for(const body of [{token:encrypted,expires:Date.now()-1},{token:'Тестов',expires:Date.now()+60000},{token:encrypted,expires:Date.now()+60000,extra:'x'}]) {
    const bad=new ShortLinkClient(endpoint,{fetch:async()=>json(body)});
    await assert.rejects(bad.resolve(shortLinkFor(id,base),base));
  }
});
test('missing, denied, limited, oversized and offline responses are explicit failures',async()=>{
  for(const [status,pattern] of [[403,/отклонил/],[404,/истёк/],[429,/Лимит/],[500,/недоступен/]]) {
    const client=new ShortLinkClient(endpoint,{fetch:async()=>json({},status)});
    await assert.rejects(client.resolve(shortLinkFor(id,base),base),pattern);
  }
  const oversized=new ShortLinkClient(endpoint,{fetch:async()=>json({junk:'x'.repeat(5000)})});
  await assert.rejects(oversized.resolve(shortLinkFor(id,base),base),/Некорректный/);
  const offline=new ShortLinkClient(endpoint,{fetch:async()=>{throw new TypeError('Network offline');}});
  await assert.rejects(offline.resolve(shortLinkFor(id,base),base),/интернет/);
  assert.throws(()=>new ShortLinkClient('http://relay.example/'));
  assert.throws(()=>new ShortLinkClient(endpoint+'?secret=value'));
});
