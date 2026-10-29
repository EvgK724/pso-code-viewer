import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {createMemoryDatabase} from '../server/yandex/test-db.mjs';
import {createTeamStore} from '../server/yandex/team-store.mjs';
import {createDirectStore} from '../server/yandex/direct-store.mjs';
import {createTeamHandler} from '../server/team-handler.mjs';
import {createDirectHandler} from '../server/direct-handler.mjs';
import {makeDevice} from '../docs/crypto.mjs';
import {exportPublicCard,importPublicCard,deviceIdentity} from '../docs/exchange.mjs';
import {TeamClient} from '../docs/team.mjs';
import {DirectClient,newMessageID} from '../docs/direct.mjs';
import {makeRecipientGrant,verifyRecipientGrant} from '../docs/recipient-trust.mjs';
import {sealMessage,openMessage,openArchivedMessage} from '../docs/messages.mjs';
import {canSendGroup,inRecipientGroup,participatesInGroup} from '../docs/care-routing.mjs';

if(!globalThis.crypto)globalThis.crypto=webcrypto;
const origin='https://viewer.example';
const people=Object.fromEntries(await Promise.all([
  ['admin','admin'],['davydova','neurologist'],['rehab','rehab1_physician'],
  ['rehab2','rehab2_physician'],['intensivist','intensivist'],['bot','bot'],
].map(async([key,role])=>{
  const device=await makeDevice();
  const card=await importPublicCard(await exportPublicCard(device,'ТЕСТ '+key));
  return [key,{device,contact:{...card,role,verified:true}}];
})));
const dev=key=>people[key].device,contact=key=>people[key].contact,id=key=>contact(key).id;

async function fixture(){
  let clock=Date.now();
  const now=()=>clock,db=createMemoryDatabase({now});
  for(const [key,{device,contact:member}] of Object.entries(people)){
    const proof=key==='admin'?null:await makeRecipientGrant(dev('admin'),member,{now:now()});
    await db.seed('member:'+member.id,{device_id:member.id,name:member.name,role:member.role,
      state:'active',card:member.card,
      signing_spki:Buffer.from(await crypto.subtle.exportKey('spki',device.signing.publicKey)).toString('base64url'),
      approval_proof:proof,created_at:now(),approved_at:now(),revoked_at:null,invite_hash:null});
  }
  const teamStore=createTeamStore(db,{now}),directStore=createDirectStore(db,{now});
  const teamHandler=createTeamHandler({store:{...teamStore,keys:async()=>null},allowedOrigin:origin,now});
  const directHandler=createDirectHandler({store:{...directStore,keys:async()=>null,unlockCheck:async()=>true},allowedOrigin:origin,now});
  const fetcher=async(url,options)=>{
    const handler=url.endsWith('/pso-team')?teamHandler:directHandler;
    return handler(new Request(url,{...options,headers:{...options.headers,Origin:origin}}));
  };
  const options={fetch:fetcher,now,sleep:async()=>{},random:()=>0};
  const team=new TeamClient(origin+'/api/pso-team',options),direct=new DirectClient(origin+'/api/pso-direct',options);
  async function message(sender,recipients,{group='rehab1',kind='review',replyTo,archive=false,comment='Синтетический комментарий'}={}){
    const meta={id:newMessageID(),group,kind,issued:now(),expires:now()+2*86400000,...(replyTo?{replyTo}:{})};
    return {...meta,...await sealMessage(dev(sender),recipients,{surname:'ТестовыйПациент',comment},meta,{archive})};
  }
  async function member(key){return (await direct.directory(dev('admin'))).find(value=>value.id===id(key));}
  async function read(key,messageId){
    const record=await direct.open(dev(key),messageId);
    const sender=record.senderRole==='admin'?{...contact('admin'),verified:true}:
      await verifyRecipientGrant({id:record.sender.id,name:record.senderName,role:record.senderRole,
        ...(record.senderRoles?{roles:record.senderRoles}:{}),
        ...(record.senderRoleProofs?{roleProofs:record.senderRoleProofs}:{}),
        card:record.senderCard,approvalProof:record.senderApprovalProof},contact('admin'),now());
    assert.equal(canSendGroup(sender,record.meta.group,record.meta.kind),true);
    return openMessage(dev(key),record.token,record.payload,[sender],now());
  }
  return {db,now,team,direct,teamStore,directStore,message,member,read,advance:ms=>clock+=ms};
}

test('one existing neurologist phone adds a signed rehab role and keeps its key, old replies and encrypted history',async()=>{
  const f=await fixture(),before=f.db.dump().get('member:'+id('davydova'));
  const originalIdentity=await deviceIdentity(dev('davydova'));
  const oldReview=await f.message('davydova',[contact('intensivist')],{group:'orit',archive:true,comment:'История до второй роли'});
  await f.direct.create(dev('davydova'),oldReview);
  const oldReply=await f.message('intensivist',[contact('davydova')],{group:'orit',kind:'reply',replyTo:oldReview.id,comment:'Личный ответ до второй роли'});
  await f.direct.create(dev('intensivist'),oldReply);

  const invitation=await f.team.invite(dev('admin'),before.name,'rehab1_physician',contact('admin').card);
  assert.equal((await f.team.invitationInfo(dev('davydova'),invitation.id)).organizerCard,contact('admin').card);
  assert.equal((await f.team.claim(dev('davydova'),invitation.id)).state,'pending');
  assert.equal((await f.team.claim(dev('davydova'),invitation.id)).state,'pending','a retried claim does not replace the phone');
  const waiting=await f.team.status(dev('davydova'));
  assert.equal(waiting.state,'active');
  assert.equal(waiting.role,'neurologist');
  assert.equal(waiting.pendingRole,'rehab1_physician');
  assert.deepEqual(waiting.roles??[waiting.role],['neurologist']);
  const pendingMember=(await f.direct.members(dev('admin'))).find(value=>value.id===id('davydova'));
  assert.equal(pendingMember.state,'active');
  assert.equal(pendingMember.pendingRole,'rehab1_physician');
  const beforeApproval=await f.member('davydova');
  assert.equal(inRecipientGroup(await verifyRecipientGrant(beforeApproval,contact('admin'),f.now()),'rehab1'),false);
  assert.deepEqual(beforeApproval.approvalProof,before.approval_proof);
  const premature=await f.message('admin',[contact('rehab'),contact('davydova')]);
  await assert.rejects(f.direct.create(dev('admin'),premature),error=>error.status===409,'an unapproved requested role cannot receive a review');
  assert.equal((await f.read('davydova',oldReply.id)).comment,'Личный ответ до второй роли');

  const extraProof=await makeRecipientGrant(dev('admin'),{...beforeApproval,role:'rehab1_physician'},{now:f.now()});
  await assert.rejects(f.direct.certify(dev('davydova'),id('davydova'),extraProof),error=>error.status===403,'a doctor cannot approve their own extra role');
  await f.direct.certify(dev('admin'),id('davydova'),extraProof);
  await f.direct.certify(dev('admin'),id('davydova'),extraProof);
  assert.equal((await f.team.claim(dev('davydova'),invitation.id)).state,'active');
  const upgraded=await f.member('davydova'),verified=await verifyRecipientGrant(upgraded,contact('admin'),f.now());
  assert.deepEqual(verified.roles,['neurologist','rehab1_physician']);
  assert.deepEqual(upgraded.approvalProof,before.approval_proof,'primary v1 grant is preserved');
  assert.deepEqual(upgraded.roleProofs,[extraProof]);
  assert.equal(upgraded.card,before.card);
  assert.equal((await deviceIdentity(dev('davydova'))).id,originalIdentity.id);
  const saved=f.db.dump().get('member:'+id('davydova'));
  assert.equal(saved.signing_spki,before.signing_spki);
  assert.equal(saved.name,before.name);
  assert.equal(saved.created_at,before.created_at);
  assert.equal(saved.approved_at,before.approved_at);
  assert.equal((await f.direct.members(dev('admin'))).filter(value=>value.id===id('davydova')).length,1);
  assert.equal((await f.team.status(dev('davydova'))).pendingRole??null,null);

  // Delivery, decryption and receipts use the original device once, despite
  // eligibility as both a neurologist and a rehabilitation participant.
  const directory=await Promise.all((await f.direct.directory(dev('admin'))).map(value=>value.id===id('admin')?contact('admin'):verifyRecipientGrant(value,contact('admin'),f.now())));
  const recipients=await Promise.all(directory.filter(value=>inRecipientGroup(value,'rehab1')).map(value=>verifyRecipientGrant(value,contact('admin'),f.now())));
  assert.deepEqual(recipients.map(value=>value.id).sort(),[id('davydova'),id('rehab')].sort());
  const review=await f.message('admin',recipients,{comment:'Сообщение по реабилитации'});
  await f.direct.create(dev('admin'),review);
  await f.direct.create(dev('admin'),review);
  assert.equal((await f.read('davydova',review.id)).comment,'Сообщение по реабилитации');
  await f.direct.ack(dev('davydova'),review.id);
  await f.direct.ack(dev('davydova'),review.id);
  assert.equal(f.db.dump().get('directmsg:'+review.id).opened_count,1);

  const conversationRecipients=directory.filter(value=>value.id!==id('rehab')&&participatesInGroup(value,'rehab1'));
  assert.deepEqual(conversationRecipients.map(value=>value.id).sort(),[id('admin'),id('davydova')].sort());
  const discussion=await f.message('rehab',conversationRecipients,{kind:'discussion',comment:'Обсуждение команды'});
  await f.direct.create(dev('rehab'),discussion);
  assert.equal((await f.read('davydova',discussion.id)).comment,'Обсуждение команды');
  assert.equal(f.db.dump().get('directmsg:'+discussion.id).recipient_count,2);
  assert.equal([...f.db.dump().keys()].filter(key=>key==='directentry:'+discussion.id+':'+id('davydova')).length,1);

  // Both rehabilitation stages can ask encrypted follow-up questions using
  // the same reply action. A dual-role author is still included only once
  // when receiving, and is excluded altogether from her own reply audience.
  for(const [sender,group,parent,expected,excluded] of [
    ['davydova','rehab1',review,['admin','rehab'],['davydova','rehab2','intensivist','bot']],
    ['rehab2','rehab2',null,['admin','davydova'],['rehab2','rehab','intensivist','bot']],
  ]){
    const source=parent??await f.message('admin',[contact('rehab2')],{group,comment:'Направление на второй этап'});
    if(!parent)await f.direct.create(dev('admin'),source);
    const audience=directory.filter(value=>value.id!==id(sender)&&participatesInGroup(value,group));
    assert.deepEqual(audience.map(value=>value.id).sort(),expected.map(id).sort());
    const question=await f.message(sender,audience,{group,kind:'group_reply',replyTo:source.id,comment:'Уточняющий вопрос '+group});
    await f.direct.create(dev(sender),question);
    for(const recipient of expected)assert.equal((await f.read(recipient,question.id)).comment,'Уточняющий вопрос '+group);
    for(const outsider of excluded){
      assert.equal(f.db.dump().has('directentry:'+question.id+':'+id(outsider)),false);
      await assert.rejects(f.direct.open(dev(outsider),question.id),error=>error.status===403);
    }
    assert.equal(f.db.dump().get('directmsg:'+question.id).recipient_count,expected.length);
  }

  await f.db.seed('pushsub:'+id('davydova'),{refreshed_at:f.now(),endpoint_hash:'1'.repeat(64),subscription:{endpoint:'https://push.example/synthetic'}});
  f.advance(30001);
  const targets=(await f.directStore.pushClaim(id('rehab'),discussion.id)).targets;
  assert.equal(targets.filter(target=>target.recipientId===id('davydova')).length,1);

  assert.equal((await f.read('davydova',oldReply.id)).comment,'Личный ответ до второй роли');
  const archived=await f.direct.historyOpen(dev('davydova'),oldReview.id);
  assert.equal((await openArchivedMessage(dev('davydova'),archived.senderToken,archived.payload,f.now())).comment,'История до второй роли');
  assert.ok((await f.direct.history(dev('davydova'))).items.some(item=>item.id===oldReview.id));
  const anotherReview=await f.message('davydova',[contact('intensivist')],{group:'orit',comment:'Сохранился доступ невролога'});
  await f.direct.create(dev('davydova'),anotherReview);
  assert.equal((await f.read('intensivist',anotherReview.id)).comment,'Сохранился доступ невролога');
  const ownRehabReview=await f.message('davydova',[contact('rehab')],{comment:'Невролог направляет коллегам'});
  await f.direct.create(dev('davydova'),ownRehabReview);
  assert.equal((await f.read('rehab',ownRehabReview.id)).comment,'Невролог направляет коллегам');
  assert.equal(f.db.dump().has('directentry:'+ownRehabReview.id+':'+id('davydova')),false,'the author gets no duplicate inbox notification');

  // Existing bot installations and older phones keep their v1 projection.
  assert.deepEqual(await f.team.request(dev('davydova'),'status',{}),{state:'active',role:'neurologist',name:before.name});
  const legacyDirectory=await f.direct.request(dev('bot'),'directory',{});
  const legacyDoctor=legacyDirectory.members.find(value=>value.id===id('davydova'));
  assert.deepEqual(Object.keys(legacyDoctor).sort(),['approvalProof','card','id','name','role']);
  assert.deepEqual(legacyDoctor.approvalProof,before.approval_proof);
  assert.ok(legacyDirectory.members.every(value=>['admin','neurologist','intensivist','cardiologist','bot'].includes(value.role)));
  const serialized=JSON.stringify([...f.db.dump()]);
  for(const plaintext of ['ТестовыйПациент','Сообщение по реабилитации','История до второй роли'])assert.equal(serialized.includes(plaintext),false);
});

test('extra roles require an organizer signature for the same name and original device',async()=>{
  const f=await fixture(),doctor=await f.member('davydova');
  const extra=await makeRecipientGrant(dev('admin'),{...doctor,role:'rehab1_physician'},{now:f.now()});
  const valid={...doctor,roles:['neurologist','rehab1_physician'],roleProofs:[extra]};
  assert.deepEqual((await verifyRecipientGrant(valid,contact('admin'),f.now())).roles,valid.roles);
  const tampered=[
    {...valid,roleProofs:[]},
    {...valid,roles:['neurologist','rehab1_physician','rehab2_physician']},
    {...valid,roles:['neurologist','neurologist']},
    {...valid,roleProofs:[await makeRecipientGrant(dev('davydova'),{...doctor,role:'rehab1_physician'},{now:f.now()})]},
    {...valid,roleProofs:[await makeRecipientGrant(dev('admin'),{...doctor,name:'ТЕСТ другое имя',role:'rehab1_physician'},{now:f.now()})]},
    {...valid,roleProofs:[await makeRecipientGrant(dev('admin'),contact('rehab'),{now:f.now()})]},
    {...valid,roles:['neurologist','bot']},
  ];
  for(const value of tampered)await assert.rejects(verifyRecipientGrant(value,contact('admin'),f.now()));
  await assert.rejects(f.direct.certify(dev('admin'),id('davydova'),extra),error=>error.status===403||error.status===409,'a second grant without a pending request is rejected');
  const invitation=await f.team.invite(dev('admin'),contact('bot').name,'rehab1_physician',contact('admin').card);
  await assert.rejects(f.team.claim(dev('bot'),invitation.id),error=>error.status===403||error.status===409);
  assert.equal((await f.team.status(dev('bot'))).role,'bot');
});

test('a rehabilitation phone that adds neurologist access can read a newly addressed private reply',async()=>{
  const f=await fixture(),before=await f.member('rehab');
  const invitation=await f.team.invite(dev('admin'),before.name,'neurologist',contact('admin').card);
  await f.team.claim(dev('rehab'),invitation.id);
  await f.direct.certify(dev('admin'),id('rehab'),await makeRecipientGrant(dev('admin'),{...before,role:'neurologist'},{now:f.now()}));
  const verified=await verifyRecipientGrant(await f.member('rehab'),contact('admin'),f.now());
  assert.deepEqual(verified.roles,['rehab1_physician','neurologist']);
  const review=await f.message('rehab',[contact('intensivist')],{group:'orit'});
  await f.direct.create(dev('rehab'),review);
  assert.equal((await f.read('intensivist',review.id)).surname,'ТестовыйПациент');
  const reply=await f.message('intensivist',[verified],{group:'orit',kind:'reply',replyTo:review.id,comment:'Личный ответ неврологу с двумя ролями'});
  await f.direct.create(dev('intensivist'),reply);
  assert.equal((await f.read('rehab',reply.id)).comment,'Личный ответ неврологу с двумя ролями');
  for(const outsider of ['admin','davydova','rehab2','bot'])await assert.rejects(f.direct.open(dev(outsider),reply.id),error=>error.status===403);
});
