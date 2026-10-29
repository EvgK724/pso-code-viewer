import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {makeDevice} from '../docs/crypto.mjs';
import {exportPublicCard,importPublicCard} from '../docs/exchange.mjs';
import {
  makeRecipientGrant,verifyRecipientGrant,verifyRecipientDirectory,
  pinOrganizerCard,loadOrganizerCard,trustedInvitationURL,parseTrustedInvitation,
  shortTrustedInvitationURL,parseShortInvitation,verifyShortInvitation,
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

async function dualRoleMember() {
  const clinician={...member,role:'neurologist'};
  const approvalProof=await makeRecipientGrant(organizer,clinician,{now});
  const rehabProof=await makeRecipientGrant(organizer,{...clinician,role:'rehab1_physician'},{now});
  return {...clinician,approvalProof,roles:['neurologist','rehab1_physician'],roleProofs:[rehabProof]};
}

test('second clinical role needs its own v1 grant and preserves the original device and primary proof',async()=>{
  const dual=await dualRoleMember();
  const checked=await verifyRecipientGrant(dual,rootCard,now);
  assert.equal(checked.id,subject.id);assert.equal(checked.card,doctorCard);
  assert.equal(checked.role,'neurologist');assert.deepEqual(checked.roles,dual.roles);
  assert.strictEqual(checked.approvalProof,dual.approvalProof);
  assert.strictEqual(checked.roleProofs[0],dual.roleProofs[0]);
  assert.equal(checked.approvalProof.grant.v,1);assert.equal(checked.roleProofs[0].grant.v,1);
  const legacy={...dual};delete legacy.roles;delete legacy.roleProofs;
  const legacyChecked=await verifyRecipientGrant(legacy,rootCard,now);
  assert.equal(legacyChecked.id,checked.id);assert.equal(legacyChecked.role,checked.role);
  assert.equal(Object.hasOwn(legacyChecked,'roles'),false,'Legacy projection stays a single-role certificate');
  assert.equal((await verifyRecipientDirectory([dual],rootCard,now)).length,1,'Two roles identify one phone');
});

test('unsigned, omitted, duplicated and mismatched additional role capabilities fail closed',async()=>{
  const dual=await dualRoleMember();
  const badMembers=[
    {...dual,roles:undefined}, {...dual,roleProofs:undefined},
    {...dual,roles:['neurologist']}, {...dual,roles:['neurologist','neurologist']},
    {...dual,roles:['rehab1_physician','neurologist']},
    {...dual,roles:['neurologist','rehab2_physician']},
    {...dual,roles:['neurologist','rehab1_physician','psychologist']},
    {...dual,roleProofs:[]}, {...dual,roleProofs:[dual.approvalProof]},
    {...dual,roleProofs:[dual.roleProofs[0],dual.roleProofs[0]]}
  ];
  const missingRoles={...dual};delete missingRoles.roles;badMembers.push(missingRoles);
  const missingProofs={...dual};delete missingProofs.roleProofs;badMembers.push(missingProofs);
  for(const bad of badMembers) await assert.rejects(verifyRecipientGrant(bad,rootCard,now));
});

test('each extra role is bound to the same exact doctor, device, organizer and live validity period',async()=>{
  const dual=await dualRoleMember();
  const forgedRoles=[
    await makeRecipientGrant(attacker,{...member,role:'rehab1_physician'},{now}),
    await makeRecipientGrant(organizer,{...member,role:'rehab1_physician',id:other.id,card:attackerCard},{now}),
    await makeRecipientGrant(organizer,{...member,role:'rehab1_physician',name:'Другой врач'},{now}),
    await makeRecipientGrant(organizer,{...member,role:'rehab1_physician'},{now:now-60000,ttlMs:60000})
  ];
  const tampered=clone(dual.roleProofs[0]);tampered.grant.role='rehab2_physician';forgedRoles.push(tampered);
  for(const roleProof of forgedRoles)
    await assert.rejects(verifyRecipientGrant({...dual,roleProofs:[roleProof]},rootCard,now));
  await assert.rejects(verifyRecipientDirectory([dual,{...dual,id:other.id,card:attackerCard}],rootCard,now));
});

test('multiple rehabilitation roles are signed independently, while bot/admin/PSO specialist mixtures are rejected',async()=>{
  const dual=await dualRoleMember();
  const rehab2Proof=await makeRecipientGrant(organizer,{...member,role:'rehab2_physician'},{now});
  const triple={...dual,roles:[...dual.roles,'rehab2_physician'],roleProofs:[...dual.roleProofs,rehab2Proof]};
  assert.deepEqual((await verifyRecipientGrant(triple,rootCard,now)).roles,triple.roles);
  const rehabOnly={...dual,role:'rehab1_physician',approvalProof:dual.roleProofs[0],roles:['rehab1_physician','rehab2_physician'],roleProofs:[rehab2Proof]};
  assert.deepEqual((await verifyRecipientGrant(rehabOnly,rootCard,now)).roles,rehabOnly.roles);
  for(const role of ['bot','cardiologist','intensivist']) {
    const extra=await makeRecipientGrant(organizer,{...member,role},{now});
    await assert.rejects(verifyRecipientGrant({...dual,roles:['neurologist',role],roleProofs:[extra]},rootCard,now));
    await assert.rejects(verifyRecipientGrant({...dual,role,approvalProof:extra,roles:[role,'rehab1_physician']},rootCard,now));
    assert.equal((await verifyRecipientGrant({...member,role,approvalProof:extra},rootCard,now)).role,role);
  }
  const self={id:root.id,name:'Организатор',role:'admin',card:rootCard};
  const selfProof=await makeRecipientGrant(organizer,self,{now});
  const clinical=await makeRecipientGrant(organizer,{...self,role:'rehab1_physician'},{now});
  await assert.rejects(verifyRecipientGrant({...self,approvalProof:selfProof,roles:['admin','rehab1_physician'],roleProofs:[clinical]},rootCard,now));
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
  assert.match(new URL(url).hash,/^#invite=[A-Za-z0-9_-]+$/);
  assert.ok(!url.includes('PSO-CARD1.'));assert.ok(!url.includes('&'));
  for(const bad of [url.replace('viewer.example','other.example'),url.replace('/pso-code-viewer/','/other/'),url+'&join='+id,url+'&extra=1',base+'#join='+id,base+'?other=1'+new URL(url).hash])
    assert.equal(await parseTrustedInvitation(bad,base),null);
  await assert.rejects(trustedInvitationURL('http://viewer.example/',id,rootCard));
});

test('complete legacy invitations work but the two observed split fragments are rejected',async()=>{
  const base='https://viewer.example/pso-code-viewer/',id=Buffer.alloc(16,8).toString('base64url');
  const legacy=base+'#'+new URLSearchParams({join:id,organizer:rootCard});
  const parsed=await parseTrustedInvitation(legacy,base);
  assert.equal(parsed.id,id);assert.equal(parsed.organizerCard,rootCard);assert.equal(parsed.fingerprint,root.fingerprint);
  const split=legacy.indexOf('PSO-CARD1.')+'PSO-CARD1'.length;
  for(const bad of [legacy.slice(0,split),legacy.slice(split),legacy+'&organizer='+rootCard,legacy+'&join='+id])
    assert.equal(await parseTrustedInvitation(bad,base),null);
});

test('invitation envelope rejects truncation, malformed encoding, schema and public cards',async()=>{
  const base='https://viewer.example/pso-code-viewer/',id=Buffer.alloc(16,8).toString('base64url');
  const valid={v:1,id,organizer:rootCard};
  const envelope=value=>base+'#invite='+Buffer.from(JSON.stringify(value)).toString('base64url');
  const url=await trustedInvitationURL(base,id,rootCard);
  for(const bad of [url.slice(0,-1),url.slice(0,-20),url+'=',url+'&invite=A',url+'&organizer='+rootCard,
    base+'#invite=',base+'#invite=A',base+'#invite=@@@@',base+'#invite='+Buffer.from([0xff]).toString('base64url'),
    base+'#invite='+Buffer.from('{broken').toString('base64url')])
    assert.equal(await parseTrustedInvitation(bad,base),null);
  for(const payload of [null,[],{}, {...valid,v:2}, {...valid,extra:true}, {...valid,id:id+'='},
    {...valid,id:id.slice(0,-1)+'h'}, {...valid,organizer:'PSO-CARD1'}, {...valid,organizer:null},
    {id,organizer:rootCard},{v:1,id}])
    assert.equal(await parseTrustedInvitation(envelope(payload),base),null);
  assert.equal(await parseTrustedInvitation('x'.repeat(12001),base),null);
  assert.equal(await parseTrustedInvitation(null,base),null);
});

test('new invitation enforces origin, path, credentials and query restrictions',async()=>{
  const base='https://viewer.example/pso-code-viewer/',id=Buffer.alloc(16,8).toString('base64url');
  const url=await trustedInvitationURL(base,id,rootCard),fragment=new URL(url).hash;
  for(const bad of ['http://viewer.example/pso-code-viewer/'+fragment,
    'https://name:password@viewer.example/pso-code-viewer/'+fragment,
    'https://viewer.example:8443/pso-code-viewer/'+fragment,
    'https://viewer.example/pso-code-viewer/child/'+fragment,
    base+'?invite=other'+fragment])
    assert.equal(await parseTrustedInvitation(bad,base),null);
  assert.equal((await parseTrustedInvitation(base+'index.html'+fragment,base)).id,id);
});

test('short invitation encodes exactly 16 ID bytes and SHA-256 of the exact public card in one token',async()=>{
  const base='https://viewer.example/pso-code-viewer/',idBytes=Buffer.from(Array.from({length:16},(_,i)=>i*13+7));
  const id=idBytes.toString('base64url'),url=await shortTrustedInvitationURL(base,id,rootCard),hash=new URL(url).hash;
  assert.match(hash,/^#i=[A-Za-z0-9_-]{64}$/);assert.ok(!url.includes('PSO-CARD1.'));assert.ok(!url.includes('&'));
  const digest=Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(rootCard)));
  const bytes=Buffer.from(hash.slice(3),'base64url');assert.equal(bytes.length,48);
  assert.deepEqual(bytes.subarray(0,16),idBytes);assert.deepEqual(bytes.subarray(16),digest);
  assert.deepEqual(parseShortInvitation(url,base),{id,organizerHash:digest.toString('base64url')});
  assert.equal(parseShortInvitation(base+'index.html'+hash,base).id,id);
  const checked=await verifyShortInvitation(url,base,{id,expires:now+60000,organizerCard:rootCard},{now});
  assert.deepEqual(checked,{id,organizerCard:rootCard,fingerprint:root.fingerprint});
  assert.equal(hash.length,67,'No string-concatenation padding boundary is introduced');
});

test('short invitation rejects incomplete tokens, foreign origins, credentials and unexpected URL parts',async()=>{
  const base='https://viewer.example/pso-code-viewer/',id=Buffer.alloc(16,251).toString('base64url');
  const url=await shortTrustedInvitationURL(base,id,rootCard),hash=new URL(url).hash;
  for(const bad of [url.slice(0,-1),url+'A',url+'=',url+'&x=1',base+'#i=',base+'#i='+'!'.repeat(64),
    url.replace('viewer.example','other.example'),url.replace('https:','http:'),url.replace('/pso-code-viewer/','/other/'),
    'https://user:pass@viewer.example/pso-code-viewer/'+hash,base+'?x=1'+hash,null,'x'.repeat(12001)])
    assert.equal(parseShortInvitation(bad,base),null);
  await assert.rejects(shortTrustedInvitationURL(base,id+'=',rootCard));
  await assert.rejects(shortTrustedInvitationURL(base,id,' '+rootCard),/повреждена/);
});

test('server card lookup must match the committed exact card and live invitation schema before use',async()=>{
  const base='https://viewer.example/pso-code-viewer/',id=Buffer.alloc(16,199).toString('base64url');
  const url=await shortTrustedInvitationURL(base,id,rootCard),info={id,expires:now+60000,organizerCard:rootCard};
  for(const bad of [null,{}, {...info,extra:true}, {...info,id:Buffer.alloc(16,200).toString('base64url')},
    {...info,expires:now}, {...info,expires:now+0.5}, {...info,organizerCard:' '+rootCard},
    {...info,organizerCard:attackerCard}, {...info,organizerCard:'PSO-CARD1'}])
    await assert.rejects(verifyShortInvitation(url,base,bad,{now}));
  const renamed=await exportPublicCard(organizer,'Другое имя того же организатора');
  await assert.rejects(verifyShortInvitation(url,base,{...info,organizerCard:renamed},{now}),/не совпадает/);
  const storage=store();await verifyShortInvitation(url,base,info,{now});assert.equal(await loadOrganizerCard({storage}),null);
});
