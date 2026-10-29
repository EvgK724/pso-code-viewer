import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
import {makeDevice} from '../docs/crypto.mjs';
import {exportPublicCard,importPublicCard} from '../docs/exchange.mjs';
import {sealMessage,openMessage} from '../docs/messages.mjs';
import {makeRecipientGrant,verifyRecipientGrant} from '../docs/recipient-trust.mjs';
import {DirectClient,validatePending,newMessageID} from '../docs/direct.mjs';
import {REHAB_ROLES,canSendGroup} from '../docs/care-routing.mjs';
const devices=await Promise.all(Array.from({length:6},()=>makeDevice()));
const contacts=await Promise.all(devices.map(async(d,i)=>({...await importPublicCard(await exportPublicCard(d,'Тест '+i)),verified:true})));
const now=Date.now();
test('four early rehabilitation specialists decrypt one signed payload, OMR cannot',async()=>{
 const meta={id:newMessageID(),group:'rehab1',kind:'review',issued:now,expires:now+3600000};
 const sealed=await sealMessage(devices[0],contacts.slice(1,5),{surname:'Тестовый',comment:'Оценить восстановление'},meta);
 assert.equal(sealed.entries.length,4);
 assert.ok(!JSON.stringify(sealed).includes('Тестовый'));
 assert.ok(!JSON.stringify(sealed).includes('Оценить восстановление'));
 for(let i=1;i<=4;i++){
  const entry=sealed.entries.find(e=>e.recipientId===contacts[i].id);
  const opened=await openMessage(devices[i],entry.token,sealed.payload,[contacts[0]],now);
  assert.equal(opened.surname,'Тестовый');assert.equal(opened.comment,'Оценить восстановление');
  await assert.rejects(openMessage(devices[5],entry.token,sealed.payload,[contacts[0]],now));
  await assert.rejects(openMessage(devices[i],entry.token,{...sealed.payload,group:'rehab2'},[contacts[0]],now));
 }
 assert.equal(validatePending({...meta,...sealed},now).group,'rehab1');
});
test('rehab role grants are distinct and cannot be relabelled across specialties/stages',async()=>{
 for(const role of REHAB_ROLES){
  const member={...contacts[1],name:'Специалист',role};
  const approvalProof=await makeRecipientGrant(devices[0],member,{now});
  await verifyRecipientGrant({...member,approvalProof},contacts[0].card,now);
  for(const other of REHAB_ROLES.filter(r=>r!==role))await assert.rejects(verifyRecipientGrant({...member,role:other,approvalProof},contacts[0].card,now));
 }
});
test('rehab metadata forbids admissions and replies; bot and rehab roles cannot send',async()=>{
 for(const group of ['rehab1','rehab2']){
  const meta={id:newMessageID(),group,kind:'review',issued:now,expires:now+3600000};
  const sealed=await sealMessage(devices[0],[contacts[5]],{comment:'Проверка'},meta);
  const opened=await openMessage(devices[5],sealed.entries[0].token,sealed.payload,[contacts[0]],now);
  assert.equal(opened.comment,'Проверка');
  for(const kind of ['admission','reply'])await assert.rejects(sealMessage(devices[0],[contacts[5]],{surname:'Тест'},{...meta,kind,...(kind==='reply'?{replyTo:newMessageID()}:{})}));
  for(const role of ['bot','cardiologist','intensivist',...REHAB_ROLES])assert.equal(canSendGroup(role,group,'review'),false);
  for(const role of ['admin','neurologist'])assert.equal(canSendGroup(role,group,'review'),true);
  const raw={meta,payload:sealed.payload,token:sealed.entries[0].token,senderCard:contacts[0].card,senderName:'Тест',senderRole:'neurologist',senderApprovalProof:null};
  let body=raw;const client=new DirectClient('https://service.example/api',{now:()=>now,fetch:async()=>new Response(JSON.stringify(body),{headers:{'Content-Type':'application/json'}})});
  assert.equal((await client.open(devices[5],meta.id)).meta.group,group);
  for(const delta of [{senderRole:'bot'},{senderRole:'rehab1_physician'},{payload:null}]){body={...raw,...delta};await assert.rejects(client.open(devices[5],meta.id));}
 }
});
