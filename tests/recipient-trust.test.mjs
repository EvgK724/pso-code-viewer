import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {makeDevice} from '../docs/crypto.mjs';
import {exportPublicCard,importPublicCard} from '../docs/exchange.mjs';
import {
  makeRecipientGrant,verifyRecipientGrant,verifyRecipientDirectory,
  pinOrganizerCard,loadOrganizerCard,trustedInvitationURL,parseTrustedInvitation,
  MAX_GRANT_TTL,RECIPIENT_GRANT_DOMAIN
} from '../docs/recipient-trust.mjs';

if(!globalThis.crypto) globalThis.crypto=webcrypto;
const now=1790000000000;
const [organizer,doctor,attacker]=await Promise.all([makeDevice(),makeDevice(),makeDevice()]);
const [rootCard,doctorCard,attackerCard]=await Promise.all([
  exportPublicCard(organizer,'Тестовый организатор'),exportPublicCard(doctor,'Устройство'),exportPublicCard(attacker,'Другое устройство')
]);
const [root,subject,other]=await Promise.all([rootCard,doctorCard,attackerCard].map(importPublicCard));
const member={id:subject.id,name:'Тестовый врач',role:'cardiologist',card:doctorCard};
const proof=await makeRecipientGrant(organizer,member,{now});
const authorized={...member,approvalProof:proof};
function store(){const data=new Map();return {data,getItem:k=>data.has(k)?data.get(k):null,setItem:(k,v)=>data.set(k,v)};}
const clone=value=>JSON.parse(JSON.stringify(value));

test('grant authorizes exact device keys, name and role under independently pinned root',async()=>{
  const result=await verifyRecipientGrant(authorized,rootCard,now);
  assert.equal(result.id,member.id);assert.equal(result.name,member.name);assert.equal(result.role,'cardiologist');assert.equal(result.verified,true);
  assert.deepEqual(Object.keys(proof.grant),['v','subjectId','role','name','issued','expires','issuerId']);
  assert.equal(proof.grant.expires-now,MAX_GRANT_TTL);
  const signature=Buffer.from(proof.signature,'base64url');assert.equal(signature.length,64);
  assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},root.signingPublicKey,signature,
    new TextEncoder().encode(RECIPIENT_GRANT_DOMAIN+JSON.stringify(proof.grant))),true);
});

test('directory substitution cannot replace either recipient key or organizer key',async()=>{
  await assert.rejects(verifyRecipientGrant({...authorized,id:other.id,card:attackerCard},rootCard,now));
  await assert.rejects(verifyRecipientGrant(authorized,attackerCard,now));
  const forged=await makeRecipientGrant(attacker,{...member,id:other.id,card:attackerCard},{now});
  await assert.rejects(verifyRecipientGrant({...member,id:other.id,card:attackerCard,approvalProof:forged},rootCard,now));
  const altered=clone(proof);altered.issuerCard=attackerCard;
  await assert.rejects(verifyRecipientGrant({...member,approvalProof:altered},rootCard,now));
});

test('changing signed role/name, metadata, signature or granting administrator to other device fails',async()=>{
  for(const delta of [{role:'intensivist'},{name:'Другой врач'}]){
    await assert.rejects(verifyRecipientGrant({...authorized,...delta},rootCard,now));
    const altered=clone(proof);Object.assign(altered.grant,delta);
    await assert.rejects(verifyRecipientGrant({...member,...delta,approvalProof:altered},rootCard,now));
  }
  const altered=clone(proof);altered.signature=(proof.signature[0]==='A'?'B':'A')+proof.signature.slice(1);
  await assert.rejects(verifyRecipientGrant({...member,approvalProof:altered},rootCard,now));
  await assert.rejects(makeRecipientGrant(organizer,{...member,role:'admin'},{now}));
  const self={id:root.id,name:'Организатор',role:'admin',card:rootCard};
  const selfProof=await makeRecipientGrant(organizer,self,{now});
  assert.equal((await verifyRecipientGrant({...self,approvalProof:selfProof},rootCard,now)).role,'admin');
});

test('grant expiry/future timestamps/schema/canonical input validation fail closed',async()=>{
  await assert.rejects(verifyRecipientGrant(authorized,rootCard,now+MAX_GRANT_TTL));
  await assert.rejects(verifyRecipientGrant(authorized,rootCard,now-30001));
  await assert.rejects(makeRecipientGrant(organizer,member,{now,ttlMs:MAX_GRANT_TTL+1}));
  await assert.rejects(makeRecipientGrant(organizer,member,{now,ttlMs:0}));
  for(const bad of [undefined,null,{}, {...proof,extra:true}, {...proof,grant:{...proof.grant,extra:true}}])
    await assert.rejects(verifyRecipientGrant({...member,approvalProof:bad},rootCard,now));
  for(const name of ['',' Test','Test\nName','Тест\u200b','x'.repeat(61),'e\u0301'])
    await assert.rejects(makeRecipientGrant(organizer,{...member,name},{now}));
  await assert.rejects(verifyRecipientGrant({...authorized,id:member.id+'='},rootCard,now));
  await assert.rejects(verifyRecipientGrant(authorized,null,now),/ключ организатора/);
});

test('directory verification rejects duplicate, uncertified and tampered entries',async()=>{
  assert.equal((await verifyRecipientDirectory([authorized],rootCard,now))[0].id,subject.id);
  await assert.rejects(verifyRecipientDirectory([authorized,authorized],rootCard,now));
  await assert.rejects(verifyRecipientDirectory([member],rootCard,now));
  await assert.rejects(verifyRecipientDirectory([{...authorized,role:'neurologist'}],rootCard,now));
  await assert.rejects(verifyRecipientDirectory({},rootCard,now));
});

test('pin requires explicit confirmation, persists only public card and rejects silent key replacement',async()=>{
  const storage=store();assert.equal(await loadOrganizerCard({storage}),null);
  await assert.rejects(pinOrganizerCard(rootCard,{storage,now}),/Подтвердите/);
  assert.equal(storage.data.size,0);
  const pinned=await pinOrganizerCard(rootCard,{confirmed:true,storage,now});
  assert.equal(pinned.id,root.id);assert.equal((await loadOrganizerCard({storage})).id,root.id);
  const raw=[...storage.data.values()][0];assert.deepEqual(Object.keys(JSON.parse(raw)),['v','card','pinnedAt']);assert.ok(!raw.includes('privateKey'));
  await assert.rejects(pinOrganizerCard(attackerCard,{confirmed:true,storage,now}),/изменился/);
  assert.equal((await loadOrganizerCard({storage})).id,root.id);
  await pinOrganizerCard(attackerCard,{confirmed:true,replace:true,storage,now});
  assert.equal((await loadOrganizerCard({storage})).id,other.id);
  storage.setItem([...storage.data.keys()][0],'{broken');await assert.rejects(loadOrganizerCard({storage}),/повреждён/);
});

test('known-origin invitation carries public organizer card, not a server-trusted identity',async()=>{
  const base='https://viewer.example/pso-code-viewer/',id=Buffer.alloc(16,8).toString('base64url');
  const url=await trustedInvitationURL(base,id,rootCard), parsed=await parseTrustedInvitation(url,base);
  assert.equal(parsed.id,id);assert.equal(parsed.organizerCard,rootCard);assert.equal(parsed.fingerprint,root.fingerprint);
  assert.equal(new URL(url).search,'');
  for(const bad of [url.replace('viewer.example','other.example'),url.replace('/pso-code-viewer/','/other/'),url+'&join='+id,url+'&extra=1',base+'#join='+id,base+'?other=1'+new URL(url).hash])
    assert.equal(await parseTrustedInvitation(bad,base),null);
  await assert.rejects(trustedInvitationURL('http://viewer.example/',id,rootCard));
});
