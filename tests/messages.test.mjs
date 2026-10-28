import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
import {makeDevice} from '../docs/crypto.mjs';
import {exportPublicCard,importPublicCard} from '../docs/exchange.mjs';
import {sealMessage,openMessage,verifyMessageEnvelope,inspectMessageToken,validateMessagePayload,validateMessagePhoto,messagePayloadHash,MAX_MESSAGE_CIPHERTEXT_CHARS} from '../docs/messages.mjs';
const sender=await makeDevice(),recipient=await makeDevice(),stranger=await makeDevice();
const contact=async(d,n)=>({...await importPublicCard(await exportPublicCard(d,n)),verified:true});
const sc=await contact(sender,'Отправитель'),rc=await contact(recipient,'Врач'),xc=await contact(stranger,'Посторонний');
const photo={mime:'image/jpeg',data:'_9j_4AAQSkZJRgABAQAAAQABAAD_2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj_2wBDAQcHBwoIChMKChMoGhYaKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj_wAARCAACAAMDASIAAhEBAxEB_8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL_8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4-Tl5ufo6erx8vP09fb3-Pn6_8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL_8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3-Pn6_9oADAMBAAIRAxEAPwDzSiiivpjwD__Z',width:3,height:2};
const meta=()=>({id:Buffer.from(webcrypto.getRandomValues(new Uint8Array(16))).toString('base64url'),group:'cardiology',kind:'review',issued:Date.now(),expires:Date.now()+3600000});
const content={surname:'Иванов',department:'ПСО',comment:'Посмотрите историю',photo:null};
const change=(s)=>((s[0]==='A'?'B':'A')+s.slice(1));

test('one encrypted content payload, separate RSA-wrapped recipient keys, correct decryption',async()=>{
  const record=await sealMessage(sender,[rc,xc],{...content,photo},meta());
  assert.equal(record.entries.length,2);assert.notEqual(record.entries[0].token,record.entries[1].token);
  for(const [device,index]of [[recipient,0],[stranger,1]]){
    const result=await openMessage(device,record.entries[index].token,record.payload,[sc]);
    assert.equal(result.surname,content.surname);assert.equal(result.comment,content.comment);assert.deepEqual(result.photo,photo);
    assert.equal(result.messageId,record.payload.id);assert.equal(result.senderName,'Отправитель');
  }
  const json=JSON.stringify(record);assert.ok(!json.includes(content.surname));assert.ok(!json.includes(content.comment));assert.ok(!json.includes(photo.data));
  assert.equal(inspectMessageToken(record.entries[0].token).recipientId,rc.id);
  assert.equal((await verifyMessageEnvelope(record.entries[0].token,record.payload,sc)).senderId,sc.id);
});
test('photo-only and comment-only reviews work; admission needs surname',async()=>{
  const a=await sealMessage(sender,[rc],{photo},meta());assert.deepEqual((await openMessage(recipient,a.entries[0].token,a.payload,[sc])).photo,photo);
  const b=await sealMessage(sender,[rc],{comment:'Проверка'},meta());assert.equal((await openMessage(recipient,b.entries[0].token,b.payload,[sc])).surname,'');
  await assert.rejects(sealMessage(sender,[rc],{},meta()));
  await assert.rejects(sealMessage(sender,[rc],{photo},{...meta(),kind:'admission'}));
});
test('wrong recipient, unapproved sender/recipient and substituted cards are rejected',async()=>{
  const r=await sealMessage(sender,[rc],content,meta());
  await assert.rejects(openMessage(stranger,r.entries[0].token,r.payload,[sc]),/другому/);
  await assert.rejects(openMessage(recipient,r.entries[0].token,r.payload,[]),/подтверждён/);
  await assert.rejects(openMessage(recipient,r.entries[0].token,r.payload,[{...sc,verified:false}]),/подтверждён/);
  await assert.rejects(sealMessage(sender,[{...rc,verified:false}],content,meta()));
  await assert.rejects(sealMessage(sender,[{...rc,card:xc.card}],content,meta()));
  await assert.rejects(sealMessage(sender,[rc,rc],content,meta()));
});
test('ciphertext, metadata, wrapped-key, signature and cross-record substitution fail',async()=>{
  const r=await sealMessage(sender,[rc],content,meta()),other=await sealMessage(sender,[rc],{...content,surname:'Петров'},meta());
  const token=r.entries[0].token;
  for(const modified of [{...r.payload,ciphertext:change(r.payload.ciphertext)},{...r.payload,id:meta().id},{...r.payload,group:'orit'},{...r.payload,kind:'admission'},{...r.payload,expires:r.payload.expires+1},{...r.payload,iv:change(r.payload.iv)},other.payload])await assert.rejects(openMessage(recipient,token,modified,[sc]));
  for(const index of [1,2,3,4,5]){const p=token.split('.');p[index]=change(p[index]);await assert.rejects(openMessage(recipient,p.join('.'),r.payload,[sc]));}
  await assert.rejects(verifyMessageEnvelope(token,r.payload,xc));
});
test('expired/future messages, invalid groups and overlong requests rejected',async()=>{
  const r=await sealMessage(sender,[rc],content,meta());
  await assert.rejects(openMessage(recipient,r.entries[0].token,r.payload,[sc],r.payload.expires),/истёк/);
  await assert.rejects(openMessage(recipient,r.entries[0].token,r.payload,[sc],r.payload.issued-31000),/время/);
  for(const patch of [{group:'public'},{kind:'photo'},{id:'a'},{issued:0},{expires:Date.now()-1},{expires:Date.now()+86400001*2}])await assert.rejects(sealMessage(sender,[rc],content,{...meta(),...patch}));
  assert.throws(()=>validateMessagePayload({...r.payload,ciphertext:'A'.repeat(MAX_MESSAGE_CIPHERTEXT_CHARS+1)}));
  for(const t of ['',r.entries[0].token+'.x',r.entries[0].token.replace('PSO2','PSO1')])assert.throws(()=>inspectMessageToken(t));
});
test('canonical metadata/hash and plaintext normalization with strict schema',async()=>{
  const r=await sealMessage(sender,[rc],{surname:' Е\u0308лкин ',comment:' Проверка ',department:'ОРИТ'},meta());
  const value=await openMessage(recipient,r.entries[0].token,r.payload,[sc]);assert.equal(value.surname,'Ёлкин');assert.equal(value.comment,'Проверка');
  assert.equal(await messagePayloadHash(r.payload),await messagePayloadHash(Object.fromEntries(Object.entries(r.payload).reverse())));
  for(const bad of [{surname:'Иванов123'},{comment:'a'.repeat(2001)},{comment:'Иванов\u202e'},{department:'Терапия'},{photo:{...photo,width:2}},{unexpected:'x'}])await assert.rejects(sealMessage(sender,[rc],{...content,...bad},meta()));
  assert.throws(()=>validateMessagePhoto({...photo,mime:'image/svg+xml'}));
  assert.throws(()=>validateMessagePhoto({...photo,data:'_9j_2Q'}));
});

test('reply body and parent binding are encrypted and signed for the exact recipient',async()=>{
  const parent=meta().id,m={...meta(),kind:'reply',replyTo:parent};
  const r=await sealMessage(recipient,[sc],{comment:'Ответ кардиолога'},m);
  const result=await openMessage(sender,r.entries[0].token,r.payload,[rc]);
  assert.equal(result.kind,'reply');assert.equal(result.replyTo,parent);assert.equal(result.comment,'Ответ кардиолога');
  assert.ok(!JSON.stringify(r).includes('Ответ кардиолога'));
  await assert.rejects(openMessage(stranger,r.entries[0].token,r.payload,[rc]));
  for(const patch of [{replyTo:meta().id},{kind:'review'},{replyTo:undefined}])await assert.rejects(openMessage(sender,r.entries[0].token,{...r.payload,...patch},[rc]));
  for(const patch of [{replyTo:undefined},{replyTo:m.id},{replyTo:'bad'},{kind:'review'}])await assert.rejects(sealMessage(recipient,[sc],{comment:'Ответ'},{...m,...patch}));
});
