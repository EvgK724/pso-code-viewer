import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
import {makeDevice} from '../docs/crypto.mjs';
import {exportPublicCard,importPublicCard,openSurname} from '../docs/exchange.mjs';
import {sealMessage,openMessage,openArchivedMessage,openBotArchivedMessage,inspectMessageToken,MAX_MESSAGE_TTL,HISTORY_TTL} from '../docs/messages.mjs';
import {DirectClient,newMessageID,validatePending} from '../docs/direct.mjs';
import {makeRecipientGrant} from '../docs/recipient-trust.mjs';
import {sealBoundBotToken,signBotPayload} from './helpers/bot-token.mjs';

const DAY=86400000;
const author=await makeDevice(),receiver=await makeDevice(),stranger=await makeDevice();
const contact=async(d,n)=>({...await importPublicCard(await exportPublicCard(d,n)),verified:true});
const ac=await contact(author,'Невролог'),rc=await contact(receiver,'Реаниматолог'),xc=await contact(stranger,'Другой врач');
const meta=()=>{const issued=Date.now();return{id:newMessageID(),group:'orit',kind:'review',issued,expires:issued+MAX_MESSAGE_TTL};};
const content={surname:'Тестов',comment:'Проверка архива, не пациент',department:'ПСО',photo:null};
const response=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});

test('sender copy shares signed ciphertext without joining recipient entries or exposing plaintext',async()=>{
  const m=meta(),sealed=await sealMessage(author,[rc,xc],content,m,{archive:true});
  assert.equal(MAX_MESSAGE_TTL,2*DAY);assert.equal(HISTORY_TTL,90*DAY);
  assert.equal(sealed.entries.length,2);
  assert.ok(sealed.entries.every(e=>e.recipientId!==ac.id));
  const token=inspectMessageToken(sealed.senderToken);
  assert.equal(token.recipientId,ac.id);assert.equal(token.senderId,ac.id);
  assert.ok(sealed.entries.every(e=>inspectMessageToken(e.token).payloadHash===token.payloadHash));
  assert.equal((await openArchivedMessage(author,sealed.senderToken,sealed.payload)).comment,content.comment);
  assert.equal((await openMessage(receiver,sealed.entries[0].token,sealed.payload,[ac],m.issued+47*3600000)).surname,content.surname);
  const wire=JSON.stringify({...m,...sealed});
  assert.ok(!wire.includes(content.surname));assert.ok(!wire.includes(content.comment));
  const legacy=await sealMessage(author,[rc],content,meta());
  assert.deepEqual(Object.keys(legacy).sort(),['entries','payload']);
});

test('recipient access stops at48h while sender archive expires exactly90days after signed issue',async()=>{
  const m=meta(),sealed=await sealMessage(author,[rc],content,m,{archive:true});
  await assert.rejects(openMessage(receiver,sealed.entries[0].token,sealed.payload,[ac],m.expires),/истёк/);
  for(const now of [m.issued+3*DAY,m.issued+HISTORY_TTL-1]){
    const opened=await openArchivedMessage(author,sealed.senderToken,sealed.payload,now);
    assert.equal(opened.comment,content.comment);assert.equal(opened.expires,m.expires);
  }
  for(const now of [m.issued-31000,m.issued+HISTORY_TTL,m.issued+HISTORY_TTL+1,NaN])await assert.rejects(openArchivedMessage(author,sealed.senderToken,sealed.payload,now));
  await assert.rejects(sealMessage(author,[rc],content,{...m,expires:m.issued+MAX_MESSAGE_TTL+1},{archive:true}));
});

test('archive path rejects ordinary recipients, other devices and tampered expiry/content/identity',async()=>{
  const m=meta(),sealed=await sealMessage(author,[rc],content,m,{archive:true}),later=m.issued+3*DAY;
  await assert.rejects(openArchivedMessage(receiver,sealed.entries[0].token,sealed.payload,later),/отправителя/);
  await assert.rejects(openArchivedMessage(receiver,sealed.senderToken,sealed.payload,later),/отправителя/);
  await assert.rejects(openArchivedMessage(stranger,sealed.senderToken,sealed.payload,later),/отправителя/);
  await assert.rejects(openArchivedMessage(author,sealed.entries[0].token,sealed.payload,later),/отправителя/);
  for(const patch of [{issued:m.issued+DAY,expires:m.expires+DAY},{expires:m.expires+1},{group:'cardiology'},{ciphertext:sealed.payload.ciphertext.slice(1)},{id:newMessageID()}])await assert.rejects(openArchivedMessage(author,sealed.senderToken,{...sealed.payload,...patch},later));
  const pieces=sealed.senderToken.split('.');pieces[5]=(pieces[5][0]==='A'?'B':'A')+pieces[5].slice(1);
  await assert.rejects(openArchivedMessage(author,pieces.join('.'),sealed.payload,later));
});

test('encrypted pending queue preserves exact self copy and rejects swapped sender/hash bindings',async()=>{
  const m=meta(),sealed=await sealMessage(author,[rc],content,m,{archive:true}),pending={...m,...sealed};
  assert.equal(validatePending(pending),pending);
  assert.equal(validatePending(JSON.parse(JSON.stringify(pending))).senderToken,sealed.senderToken);
  const other=await sealMessage(author,[rc],{comment:'Другое сообщение'},meta(),{archive:true});
  for(const patch of [{senderToken:sealed.entries[0].token},{senderToken:other.senderToken},{senderToken:null},{surname:'Тестов'},{entries:[{recipientId:rc.id,token:other.entries[0].token}]}])assert.throws(()=>validatePending({...pending,...patch}));
});

test('history client validates90day metadata and exact self-only encrypted contents afterlive expiry',async()=>{
  const m=meta(),sealed=await sealMessage(author,[rc],content,m,{archive:true}),now=m.issued+3*DAY;
  const item={...m,createdAt:m.issued+1,archiveUntil:m.issued+HISTORY_TTL,recipientCount:1,openedCount:1,hasContent:true};
  const record={meta:m,payload:sealed.payload,senderToken:sealed.senderToken,organizerToken:null,senderApprovalProof:null,createdAt:item.createdAt,archiveUntil:item.archiveUntil,recipients:[{id:rc.id,name:rc.name,role:'intensivist',openedAt:m.issued+60000,pushState:'accepted',pushAcceptedAt:m.issued+2000}],senderCard:ac.card,senderName:ac.name,senderRole:'neurologist'};
  let body={items:[item],next:null},lastEnvelope;
  const client=new DirectClient('https://viewer.example/api',{now:()=>now,fetch:async(_,options)=>{lastEnvelope=JSON.parse(options.body).envelope;return response(body);}});
  assert.equal((await client.history(author)).items[0].id,m.id);assert.equal(lastEnvelope.op,'history');
  for(const patch of [{archiveUntil:item.archiveUntil+1},{archiveUntil:now},{openedCount:2},{hasContent:'yes'},{surname:'Тестов'}]){body={items:[{...item,...patch}],next:null};await assert.rejects(client.history(author));}
  body=record;assert.equal((await client.historyOpen(author,m.id,{unlockToken:'token'})).senderToken,sealed.senderToken);assert.equal(lastEnvelope.op,'history_open');assert.equal(lastEnvelope.data.unlockToken,'token');
  const result=await client.historyOpen(author,m.id);assert.equal((await openArchivedMessage(author,result.senderToken,result.payload,now)).surname,content.surname);
  const badRecords=[{...record,senderCard:xc.card},{...record,senderToken:sealed.entries[0].token},{...record,payload:{...sealed.payload,id:newMessageID()}},{...record,payload:null},{...record,meta:{...m,expires:m.expires+1}},{...record,archiveUntil:record.archiveUntil+DAY},{...record,recipients:[{...record.recipients[0],pushAcceptedAt:null}]},{...record,recipients:[{...record.recipients[0],openedAt:m.expires}]},{...record,recipients:[record.recipients[0],record.recipients[0]]}];
  for(const invalid of badRecords){body=invalid;await assert.rejects(client.historyOpen(author,m.id));}
  body={...record,payload:null,senderToken:null};assert.equal((await client.historyOpen(author,m.id)).payload,null);
});

test('archive-full error does not suggest successful sending; history unlock remains explicit',async()=>{
  let status=507,code='history_full';
  const client=new DirectClient('https://viewer.example/api',{fetch:async()=>response({error:code},status)});
  await assert.rejects(client.history(author),e=>e.code==='history_full'&&e.message.includes('Сообщение не отправлено'));
  status=428;code='unlock_required';
  await assert.rejects(client.historyOpen(author,newMessageID()),e=>e.status===428&&e.code==='unlock_required');
});

test('bound bot PSO1 keeps48h recipient access and90day organizer-only archive with captured grant',async()=>{
  const m={...meta(),kind:'admission'},bot={...rc,name:'Бот',role:'bot'};
  bot.approvalProof=await makeRecipientGrant(author,bot,{now:m.issued-1000,ttlMs:DAY});
  const token=await sealBoundBotToken(receiver,ac,m),recipientToken=await sealBoundBotToken(receiver,xc,m);
  const live=await openSurname(stranger,recipientToken,[bot],m.issued+47*3600000);
  assert.equal(live.messageId,m.id);assert.equal(live.group,m.group);
  await assert.rejects(openSurname(stranger,recipientToken,[bot],m.expires));
  for(const at of [m.issued+3*DAY,m.issued+HISTORY_TTL-1]){
    const archived=await openBotArchivedMessage(author,token,m,bot,at);
    assert.equal(archived.surname,'Тестов');assert.equal(archived.kind,'admission');assert.equal(archived.messageId,m.id);
  }
  await assert.rejects(openBotArchivedMessage(author,token,m,bot,m.issued+HISTORY_TTL));
  await assert.rejects(openBotArchivedMessage(stranger,token,m,bot,m.issued+3*DAY));
  await assert.rejects(openBotArchivedMessage(stranger,recipientToken,m,bot,m.issued+3*DAY),/Допуск/);
  await assert.rejects(openBotArchivedMessage(author,token,m,{...bot,role:'neurologist'},m.issued+3*DAY));
  await assert.rejects(openBotArchivedMessage(author,token,m,{...bot,verified:false},m.issued+3*DAY));
});

test('bot archive refuses legacy tokens, forged organizer grant and mismatched signed record binding',async()=>{
  const m={...meta(),kind:'admission'},bot={...rc,name:'Бот',role:'bot'};
  bot.approvalProof=await makeRecipientGrant(author,bot,{now:m.issued-1000});
  const token=await sealBoundBotToken(receiver,ac,m),at=m.issued+3*DAY;
  for(const patch of [{id:newMessageID()},{group:'cardiology'},{issued:m.issued+1},{expires:m.expires-1},{kind:'review'}])await assert.rejects(openBotArchivedMessage(author,token,{...m,...patch},bot,at));
  const forgedGrant=await makeRecipientGrant(stranger,bot,{now:m.issued-1000});
  await assert.rejects(openBotArchivedMessage(author,token,m,{...bot,approvalProof:forgedGrant},at));
  const legacyMeta={...m,expires:m.issued+DAY},legacy=await signBotPayload(receiver,ac,{n:'Тестов',d:'ПСО',j:Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString('base64url'),i:m.issued,x:legacyMeta.expires});
  assert.equal((await openSurname(author,legacy,[bot],m.issued)).surname,'Тестов');
  await assert.rejects(openBotArchivedMessage(author,legacy,legacyMeta,bot,at),/не подтверждает/);
  const malformed=await signBotPayload(receiver,ac,{n:'Тестов',d:'ПСО',j:m.id,i:m.issued,x:m.expires,g:'rehab1'});
  await assert.rejects(openSurname(author,malformed,[bot],m.issued));
  const legacyOverlong=await signBotPayload(receiver,ac,{n:'Тестов',d:'ПСО',j:Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString('base64url'),i:m.issued,x:m.expires});
  await assert.rejects(openSurname(author,legacyOverlong,[bot],m.issued));
});

test('bot history client pins captured bot grant to current device organizer and validates signature',async()=>{
  const m={...meta(),kind:'admission'},now=m.issued+3*DAY,bot={...rc,name:'Бот',role:'bot'};
  bot.approvalProof=await makeRecipientGrant(author,bot,{now:m.issued-1000});
  const token=await sealBoundBotToken(receiver,ac,m);
  const item={...m,createdAt:m.issued,archiveUntil:m.issued+HISTORY_TTL,recipientCount:1,openedCount:0,hasContent:true};
  const record={meta:m,payload:null,senderToken:null,organizerToken:token,senderApprovalProof:bot.approvalProof,createdAt:item.createdAt,archiveUntil:item.archiveUntil,recipients:[{id:xc.id,name:xc.name,role:'intensivist',openedAt:null,pushState:'queued',pushAcceptedAt:null}],senderCard:bot.card,senderName:bot.name,senderRole:'bot'};
  let body={items:[item],next:null},envelope;
  const client=new DirectClient('https://viewer.example/api',{now:()=>now,fetch:async(_,options)=>{envelope=JSON.parse(options.body).envelope;return response(body);}});
  assert.equal((await client.botHistory(author)).items[0].id,m.id);assert.deepEqual(envelope.data,{cursor:null,source:'bot'});
  body={items:[{...item,kind:'review'}],next:null};await assert.rejects(client.botHistory(author));
  body=record;const fetched=await client.historyOpen(author,m.id);assert.equal(fetched.sender.role,'bot');assert.equal((await openBotArchivedMessage(author,fetched.organizerToken,fetched.meta,fetched.sender,now)).surname,'Тестов');
  await assert.rejects(client.historyOpen(stranger,m.id));
  const otherGrant=await makeRecipientGrant(stranger,bot,{now:m.issued-1000});
  const pieces=token.split('.');pieces[4]=(pieces[4][0]==='A'?'B':'A')+pieces[4].slice(1);
  for(const patch of [{senderApprovalProof:null},{senderApprovalProof:otherGrant},{senderRole:'neurologist'},{organizerToken:pieces.join('.')},{senderToken:'unexpected'},{payload:{}},{organizerToken:null}]){body={...record,...patch};await assert.rejects(client.historyOpen(author,m.id));}
});

test('group replies and first-stage discussions retain sender archive decryption and exact thread binding',async()=>{
  for(const kind of ['group_reply','discussion']){
    const m={...meta(),group:'rehab1',kind,...(kind==='group_reply'?{replyTo:newMessageID()}:{})};
    const sealed=await sealMessage(author,[rc,xc],{comment:'План группы'},m,{archive:true}),now=m.issued+3*DAY;
    const value=await openArchivedMessage(author,sealed.senderToken,sealed.payload,now);
    assert.equal(value.kind,kind);assert.equal(value.replyTo,m.replyTo);assert.equal(value.comment,'План группы');
    const item={id:m.id,group:m.group,kind,issued:m.issued,expires:m.expires,createdAt:m.issued,archiveUntil:m.issued+HISTORY_TTL,recipientCount:2,openedCount:0,hasContent:true};
    const record={meta:m,payload:sealed.payload,senderToken:sealed.senderToken,organizerToken:null,senderApprovalProof:null,createdAt:item.createdAt,archiveUntil:item.archiveUntil,recipients:[rc,xc].map(c=>({id:c.id,name:c.name,role:'neurologist',openedAt:null,pushState:'queued',pushAcceptedAt:null})),senderCard:ac.card,senderName:ac.name,senderRole:'psychologist'};
    let body={items:[item],next:null};const client=new DirectClient('https://viewer.example/api',{now:()=>now,fetch:async()=>response(body)});
    assert.equal((await client.history(author)).items[0].kind,kind);
    body=record;assert.equal((await client.historyOpen(author,m.id)).meta.kind,kind);
    body={...record,meta:{...m,...(kind==='group_reply'?{replyTo:newMessageID()}:{group:'rehab2'})}};
    await assert.rejects(client.historyOpen(author,m.id));
  }
});

test('manual and bot archives allow the same30second clock skew as live metadata, never31seconds',async()=>{
  const m=meta(),sealed=await sealMessage(author,[rc],content,m,{archive:true});
  assert.equal((await openArchivedMessage(author,sealed.senderToken,sealed.payload,m.issued-30000)).surname,content.surname);
  await assert.rejects(openArchivedMessage(author,sealed.senderToken,sealed.payload,m.issued-31000));
  const botMeta={...m,kind:'admission'},bot={...rc,name:'Бот',role:'bot'};
  bot.approvalProof=await makeRecipientGrant(author,bot,{now:m.issued-1000});
  const token=await sealBoundBotToken(receiver,ac,botMeta);
  assert.equal((await openBotArchivedMessage(author,token,botMeta,bot,m.issued-30000)).surname,'Тестов');
  await assert.rejects(openBotArchivedMessage(author,token,botMeta,bot,m.issued-31000));
  await assert.rejects(openArchivedMessage(author,sealed.senderToken,sealed.payload,m.issued+HISTORY_TTL));
  await assert.rejects(openBotArchivedMessage(author,token,botMeta,bot,m.issued+HISTORY_TTL));
});
