import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
import {makeDevice, demoPayload, sealDemo, openDemo, tokenFromInput, linkForToken, base64url} from '../docs/crypto.mjs';
const a = await makeDevice();
const b = await makeDevice();
test('round trip, individual device, non-exportable private keys', async () => {
  const token = await sealDemo(a);
  assert.equal((await openDemo(a, token)).surname, 'Иванов');
  await assert.rejects(openDemo(b, token), /другого/);
  await assert.rejects(crypto.subtle.exportKey('pkcs8', a.encryption.privateKey));
  await assert.rejects(crypto.subtle.exportKey('pkcs8', a.signing.privateKey));
  const restored = structuredClone(a);
  assert.equal((await openDemo(restored, token)).department, 'ОРИТ');
});
test('ciphertext tampering and bad signature are rejected', async () => {
  const token = await sealDemo(a);
  const raw = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
  raw.c = (raw.c[0] === 'A' ? 'B' : 'A') + raw.c.slice(1);
  const changed = 'PSO-DEMO1.' + base64url(new TextEncoder().encode(JSON.stringify(raw)));
  await assert.rejects(openDemo(a, changed), /проверить/);
});
test('prototype rejects real surname even when correctly signed', async () => {
  const payload = {...demoPayload(a), surname:'Петров'};
  await assert.rejects(openDemo(a, await sealDemo(a, payload)), /только вымышленный/);
});
test('expired and future-dated samples rejected', async () => {
  await assert.rejects(openDemo(a, await sealDemo(a, demoPayload(a, Date.now()-700000))), /истёк/);
  await assert.rejects(openDemo(a, await sealDemo(a, demoPayload(a, Date.now()+700000))), /истёк/);
});
test('link contains only ciphertext, no key or surname; origin validation', async () => {
  const token = await sealDemo(a);
  const link = linkForToken(token, 'https://viewer.example');
  assert.equal(tokenFromInput(link, 'https://viewer.example'), token);
  assert.equal(new URL(link).search, '');
  assert.ok(!link.includes('Иванов'));
  assert.ok(link.length <= 1024);
  assert.throws(() => tokenFromInput(link, 'https://other.example'));
  assert.throws(() => tokenFromInput('https://viewer.example/?key=x#pso='+token, 'https://viewer.example'));
});
test('invalid, oversized and incompatible payloads rejected', async () => {
  await assert.rejects(openDemo(a, 'PSO-DEMO1.@@@@'));
  await assert.rejects(openDemo(a, '12345'));
  await assert.rejects(sealDemo(a, {...demoPayload(a), surname:'А'.repeat(400)}), /размер/);
});
