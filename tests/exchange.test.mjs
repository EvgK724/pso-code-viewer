import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto=webcrypto;
import {makeDevice,sealDemo,openDemo} from '../docs/crypto.mjs';
import {deviceIdentity,exportPublicCard,importPublicCard,sealSurname,openSurname} from '../docs/exchange.mjs';

const a=await makeDevice(), b=await makeDevice(), stranger=await makeDevice();
const ac={...await importPublicCard(await exportPublicCard(a,'Врач А')),verified:true};
const bc={...await importPublicCard(await exportPublicCard(b,'Врач Б')),verified:true};
const sc={...await importPublicCard(await exportPublicCard(stranger,'Врач С')),verified:true};
function changedPart(token,index) {const p=token.split('.');p[index]=(p[index][0]==='A'?'B':'A')+p[index].slice(1);return p.join('.');}
function editCard(card,fn) {const data=JSON.parse(Buffer.from(card.split('.')[1],'base64url').toString());fn(data);return 'PSO-CARD1.'+Buffer.from(JSON.stringify(data)).toString('base64url');}

test('cross-device surname exchange, department and actual hosted URL length',async()=>{
  const token=await sealSurname(a,bc,'Петрова',{department:'ОРИТ'});
  const result=await openSurname(b,token,[ac]);
  assert.equal(result.surname,'Петрова');assert.equal(result.department,'ОРИТ');assert.equal(result.senderName,'Врач А');
  assert.match(result.code,/^ПСО-[A-Za-z0-9_-]{16}$/);
  const link='https://viewer.example/#pso='+token;
  assert.ok(link.length<1024);assert.ok(!link.includes('Петрова'));
  assert.equal((await openSurname(a,await sealSurname(a,ac,'Иванов'),[])).senderName,'Вы');
});
test('public contact cards bind both keys and never export private keys',async()=>{
  const card=await exportPublicCard(a,'Врач А');
  const raw=JSON.parse(Buffer.from(card.split('.')[1],'base64url').toString());
  assert.deepEqual(Object.keys(raw).sort(),['e','n','s','v']);
  assert.equal(ac.id,(await deviceIdentity(a)).id);assert.match(ac.fingerprint,/^(?:[A-F0-9]{4} ){15}[A-F0-9]{4}$/);
  const swapped=await importPublicCard(editCard(card,d=>d.s=JSON.parse(Buffer.from(sc.card.split('.')[1],'base64url').toString()).s));
  assert.notEqual(swapped.id,ac.id);
  await assert.rejects(crypto.subtle.exportKey('pkcs8',a.encryption.privateKey));
  await assert.rejects(crypto.subtle.exportKey('pkcs8',a.signing.privateKey));
});
test('requires verified recipient and sender; rejects substituted saved keys',async()=>{
  await assert.rejects(sealSurname(a,{...bc,verified:false},'Иванов'),/отпечаток/);
  const token=await sealSurname(a,bc,'Иванов');
  await assert.rejects(openSurname(b,token,[]),/Отправитель не подтверждён/);
  await assert.rejects(openSurname(b,token,[{...ac,verified:false}]),/Отправитель не подтверждён/);
  await assert.rejects(sealSurname(a,{...bc,signingPublicKey:sc.signingPublicKey},'Иванов'),/изменились/);
  await assert.rejects(openSurname(b,token,[{...ac,signingPublicKey:sc.signingPublicKey}]),/изменились/);
});
test('wrong recipient, ciphertext/signature/header tampering and malformed tokens rejected',async()=>{
  const token=await sealSurname(a,bc,'Иванов');
  await assert.rejects(openSurname(stranger,token,[ac]),/другому получателю/);
  await assert.rejects(openSurname(b,changedPart(token,3),[ac]),/подпись/);
  await assert.rejects(openSurname(b,changedPart(token,4),[ac]),/подпись/);
  const senderSwap=token.split('.');senderSwap[2]=sc.id;
  await assert.rejects(openSurname(b,senderSwap.join('.'),[sc]),/подпись/);
  for (const bad of [token+'.more','PSO1.a.b.c.d','x'.repeat(901),token.replace('PSO1.','PSO2.')]) await assert.rejects(openSurname(b,bad,[ac]));
});
test('strict public-card input and key parameters',async()=>{
  for(const bad of ['', 'x'.repeat(5001),editCard(ac.card,d=>d.v=2),editCard(ac.card,d=>d.extra=true),editCard(ac.card,d=>d.n='a\nb'),editCard(ac.card,d=>d.e='@@@'),editCard(ac.card,d=>d.s+='=')]) await assert.rejects(importPublicCard(bad));
  const rsa=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},false,['encrypt','decrypt']);
  const spki=Buffer.from(await crypto.subtle.exportKey('spki',rsa.publicKey)).toString('base64url');
  await assert.rejects(importPublicCard(editCard(ac.card,d=>d.e=spki)));
  await assert.rejects(exportPublicCard(a,'a'.repeat(61)));
});
test('Unicode names normalize safely and controls/invalid scripts/overlong names rejected',async()=>{
  for(const [input,expected] of [['Е\u0308лкин','Ёлкин'],["O’Neill","O’Neill"],['D\u2011Angelo','D-Angelo'],[' Де  ла Крус ','Де ла Крус']]) {
    assert.equal((await openSurname(b,await sealSurname(a,bc,input),[ac])).surname,expected);
  }
  for(const bad of ['','\nИванов','Иванов\n','Иванов\t','Ив\u202Eанов','Иванов 123','<script>','王','А'.repeat(81),'\u0301Иванов','Петров--Иванов']) await assert.rejects(sealSurname(a,bc,bad));
  await assert.rejects(sealSurname(a,bc,'А'+'\u{1D185}'.repeat(79)),/размер|80/);
});
test('expiry window, timestamps and TTL options',async()=>{
  const before=Date.now(),token=await sealSurname(a,bc,'Иванов',{ttlMinutes:1});
  await assert.rejects(openSurname(b,token,[ac],before+61000),/истёк/);
  await assert.rejects(openSurname(b,token,[ac],before-31000),/время/);
  for(const ttl of [0,1441,1.5,NaN,'5']) await assert.rejects(sealSurname(a,bc,'Иванов',{ttlMinutes:ttl}));
  await assert.rejects(sealSurname(a,bc,'Иванов',{department:'Другое'}));
});
test('legacy demo remains usable and exchange rejects its protocol',async()=>{
  const demo=await sealDemo(a);assert.equal((await openDemo(a,demo)).surname,'Иванов');
  await assert.rejects(openSurname(a,demo,[]));
});
