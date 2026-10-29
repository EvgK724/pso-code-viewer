import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {createMemoryDatabase} from './test-db.mjs';
import {createDirectStore} from './direct-store.mjs';
import {createDirectHandler} from '../direct-handler.mjs';
import {makeDevice} from '../../docs/crypto.mjs';
import {exportPublicCard,importPublicCard,sealSurname} from '../../docs/exchange.mjs';
import {makeRecipientGrant} from '../../docs/recipient-trust.mjs';
import {sealMessage,openMessage,openArchivedMessage} from '../../docs/messages.mjs';
import {DirectClient,directEnvelope,newMessageID} from '../../docs/direct.mjs';

if(!globalThis.crypto)globalThis.crypto=webcrypto;
const DAY=86400000,origin='https://viewer.example',endpoint=origin+'/direct';
const surname='Вымыслов',comment='Вымышленный пример для группового обсуждения';
const groupRoles={cardiology:['cardiologist'],orit:['intensivist'],rehab1:['rehab1_physician','psychologist','speech_therapist','exercise_therapist'],rehab2:['rehab2_physician']};
const roles={admin:'admin',admin2:'admin',neurologist:'neurologist',neurologist2:'neurologist',bot:'bot',cardiologist:'cardiologist',
  intensivist:'intensivist',intensivist2:'intensivist',rehab1_physician:'rehab1_physician',psychologist:'psychologist',
  speech_therapist:'speech_therapist',exercise_therapist:'exercise_therapist',rehab2_physician:'rehab2_physician',rehab2_colleague:'rehab2_physician'};
async function person(name,role){
  const device=await makeDevice(),card=await importPublicCard(await exportPublicCard(device,name));
  return {device,contact:{...card,role,verified:true},role};
}
const people=Object.fromEntries(await Promise.all(Object.entries(roles).map(async([key,role])=>[key,await person('Synthetic '+key,role)])));
const dev=key=>people[key].device,id=key=>people[key].contact.id;

async function fixture({exclude=[]}={}){
  let clock=Date.now();const now=()=>clock,db=createMemoryDatabase({now}),transactions=[],members=new Map();
  const monitored={transaction:callback=>db.transaction(async tx=>{
    const stats={operations:0,scanned:0},bounded=Object.fromEntries(Object.entries(tx).map(([key,fn])=>[key,async(...args)=>{
      assert.ok(++stats.operations<=512,'transaction exceeds the production operation budget');
      const result=await fn(...args);if(key==='scan')stats.scanned+=result.length;return result;
    }]));
    try{return await callback(bounded);}finally{transactions.push(stats);}
  })};
  const store=createDirectStore(monitored,{now});
  async function add(key,value=people[key]){
    members.set(key,value);const {device,contact,role}=value;
    const approval_proof=role==='admin'?null:await makeRecipientGrant(dev('admin2'),contact,{now:now()});
    await db.seed('member:'+contact.id,{device_id:contact.id,name:contact.name,role,state:'active',card:contact.card,
      signing_spki:Buffer.from(await crypto.subtle.exportKey('spki',device.signing.publicKey)).toString('base64url'),
      approval_proof,created_at:now(),approved_at:now(),revoked_at:null});
  }
  for(const key of Object.keys(people))if(!exclude.includes(key))await add(key);
  const sent=[],handler=createDirectHandler({store:{...store,
    keys:async()=>({publicKey:Buffer.alloc(65,1).toString('base64url'),privateKey:{}}),unlockCheck:async()=>true},allowedOrigin:origin,now,
    send:async(subscription,keys,payload)=>{sent.push({subscription,payload});return {status:'accepted'};}});
  const requests=[],client=new DirectClient(endpoint,{now,fetch:async(url,options)=>{
    requests.push(JSON.parse(options.body).envelope);
    return handler(new Request(url,{...options,headers:{...options.headers,Origin:origin}}));
  }});
  const row=key=>db.dump().get('member:'+members.get(key).contact.id);
  const audience=(group,sender,{specialistsOnly=false}={})=>[...members.keys()].filter(key=>{
    const m=row(key);return m?.state==='active'&&key!==sender&&(groupRoles[group].includes(m.role)||!specialistsOnly&&['admin','neurologist'].includes(m.role));
  });
  async function request(sender,group,kind='group_reply',replyTo,recipients=audience(group,sender),meta={},archive=true){
    const m={id:newMessageID(),group,kind,issued:now(),expires:now()+2*DAY,...(['reply','group_reply'].includes(kind)?{replyTo}:{}),...meta};
    return {...m,...await sealMessage(members.get(sender).device,recipients.map(key=>members.get(key).contact),{surname,comment},m,{archive})};
  }
  const review=(group,sender='neurologist',meta={})=>request(sender,group,'review',undefined,audience(group,sender,{specialistsOnly:true}),meta,false);
  async function op(sender,data,operation='create',tamper){
    const envelope=await directEnvelope(members.get(sender).device,operation,data,now());
    if(tamper)tamper(envelope);
    return handler(new Request(endpoint,{method:'POST',headers:{'Content-Type':'application/json',Origin:origin},body:JSON.stringify({envelope})}));
  }
  async function change(key,patch){await db.seed('member:'+members.get(key).contact.id,{...row(key),...patch});}
  async function recertify(key,role){
    const target={...members.get(key).contact,role};
    const approval_proof=role==='admin'?null:await makeRecipientGrant(dev('admin2'),target,{now:now()});
    await change(key,{role,approval_proof});
  }
  async function subscribe(key){await db.seed('pushsub:'+members.get(key).contact.id,{refreshed_at:now(),endpoint_hash:'1'.repeat(64),subscription:{endpoint:'https://push.example/'+key}});}
  const durable=()=>[...db.dump()].filter(([key])=>/^direct(?:msg:|entry:|payload:|in:|out:|archive:|history:|quota:|push:)/.test(key));
  return {now,db,store,client,members,add,audience,request,review,op,change,recertify,subscribe,durable,sent,requests,transactions,
    advance:ms=>clock+=ms,setNow:at=>clock=at};
}

test('every human participant can reply to all specialists and PSO clinicians of exactly one direction',async()=>{
  for(const group of Object.keys(groupRoles)){
    const f=await fixture(),parent=await f.review(group);assert.equal((await f.op('neurologist',parent)).status,200);
    const specialist=f.audience(group,'neurologist',{specialistsOnly:true})[0];
    const first=await f.request(specialist,group,'group_reply',parent.id);assert.equal((await f.op(specialist,first)).status,200);
    const participants=[specialist,...f.audience(group,specialist)];
    for(const sender of participants){
      const message=await f.request(sender,group,'group_reply',first.id),recipients=f.audience(group,sender);
      assert.equal((await f.op(sender,message)).status,200,group+' / '+sender);
      assert.equal(f.db.dump().get('directmsg:'+message.id).recipient_count,recipients.length);
      for(const recipient of recipients){
        const opened=await f.client.open(dev(recipient),message.id);
        const value=await openMessage(dev(recipient),opened.token,opened.payload,[people[sender].contact],f.now());
        assert.equal(value.surname,surname);assert.equal(value.comment,comment);assert.equal(value.replyTo,first.id);
        assert.equal(opened.meta.kind,'group_reply');assert.equal(opened.meta.group,group);
      }
      for(const outsider of Object.keys(people).filter(key=>!recipients.includes(key)))
        await assert.rejects(f.client.open(dev(outsider),message.id),e=>e.status===403,group+' / '+sender+' / '+outsider);
    }
    const serialized=JSON.stringify(f.durable());assert.ok(!serialized.includes(surname));assert.ok(!serialized.includes(comment));
  }
});

test('original parent author can continue without a self-entry but an uninvited or newly added member cannot',async()=>{
  const f=await fixture({exclude:['psychologist']}),parent=await f.review('rehab1');
  assert.equal((await f.op('neurologist',parent)).status,200);
  assert.equal(f.db.dump().has('directentry:'+parent.id+':'+id('neurologist')),false);
  const original=await f.request('neurologist','rehab1','group_reply',parent.id);
  assert.equal((await f.op('neurologist',original)).status,200);
  const uninvited=await f.request('neurologist2','rehab1','group_reply',parent.id);
  assert.equal((await f.op('neurologist2',uninvited)).status,403);
  await f.add('psychologist');
  const newcomer=await f.request('psychologist','rehab1','group_reply',parent.id);
  assert.equal((await f.op('psychologist',newcomer)).status,403);
  const authorized=await f.request('neurologist2','rehab1','group_reply',original.id);
  assert.equal((await f.op('neurologist2',authorized)).status,200);
  assert.equal((await f.client.open(dev('psychologist'),authorized.id)).meta.replyTo,original.id);
});

test('group answers to a legacy bot admission reach humans and never deliver back to the bot',async()=>{
  const f=await fixture();for(const key of Object.keys(people))await f.subscribe(key);
  const meta={id:newMessageID(),group:'orit',kind:'admission',issued:f.now(),expires:f.now()+DAY};
  const entries=await Promise.all(['intensivist','intensivist2'].map(async key=>({recipientId:id(key),token:await sealSurname(dev('bot'),people[key].contact,surname)})));
  assert.equal((await f.op('bot',{...meta,entries})).status,200);f.sent.length=0;
  const reply=await f.request('intensivist','orit','group_reply',meta.id);
  assert.equal((await f.op('intensivist',reply)).status,200);
  const expected=f.audience('orit','intensivist');
  assert.deepEqual(f.sent.map(item=>item.subscription.endpoint).sort(),expected.map(key=>'https://push.example/'+key).sort());
  assert.ok(!reply.entries.some(entry=>entry.recipientId===id('bot')));
  await assert.rejects(f.client.open(dev('bot'),reply.id),e=>e.status===403);
  const botReply=await f.request('bot','orit','group_reply',meta.id);
  assert.equal((await f.op('bot',botReply)).status,403);
});

test('wrong direction, missing or expired parent and invalid encrypted binding cannot create group replies',async t=>{
  const f=await fixture();t.mock.method(Date,'now',f.now);
  const parent=await f.review('rehab1','neurologist',{expires:f.now()+60000});assert.equal((await f.op('neurologist',parent)).status,200);
  const before=f.durable();
  for(const [sender,group,target,status] of [['rehab2_physician','rehab2',parent.id,403],['psychologist','rehab1',newMessageID(),404],['cardiologist','rehab1',parent.id,403]]){
    const message=await f.request(sender,group,'group_reply',target);assert.equal((await f.op(sender,message)).status,status);
    assert.deepEqual(f.durable(),before);
  }
  const good=await f.request('psychologist','rehab1','group_reply',parent.id);
  const {payload,...noPayload}=good,{replyTo,...noParent}=good;
  for(const message of [noPayload,noParent,{...good,replyTo:good.id},{...good,payload:{...good.payload,replyTo:newMessageID()}},{...good,comment}]){
    assert.equal((await f.op('psychologist',message)).status,400);assert.deepEqual(f.durable(),before);
  }
  assert.equal((await f.op('psychologist',good)).status,200);
  f.advance(60001);
  assert.equal((await f.op('psychologist',good)).status,200,'saved reply remains idempotent after its parent expires');
  const expired=await f.request('psychologist','rehab1','group_reply',parent.id);
  assert.equal((await f.op('psychologist',expired)).status,404);
});

test('group roster omissions, extras and changes are rejected atomically without partial delivery',async()=>{
  const f=await fixture(),parent=await f.review('rehab1');assert.equal((await f.op('neurologist',parent)).status,200);
  const exact=f.audience('rehab1','psychologist'),before=f.durable();
  for(const recipients of [exact.slice(1),[...exact,'rehab2_physician'],[...exact,'psychologist'],[...exact,'bot']]){
    const message=await f.request('psychologist','rehab1','group_reply',parent.id,recipients);
    assert.equal((await f.op('psychologist',message)).status,409);assert.deepEqual(f.durable(),before);
  }
  const stale=await f.request('psychologist','rehab1','group_reply',parent.id);
  await f.change('neurologist2',{state:'revoked'});
  assert.equal((await f.op('psychologist',stale)).status,403);assert.deepEqual(f.durable(),before);
  const current=await f.request('psychologist','rehab1','group_reply',parent.id);
  assert.equal((await f.op('psychologist',current)).status,200);
  await assert.rejects(f.client.open(dev('neurologist2'),current.id),e=>e.status===403);
});

test('every rehab1 participant can start a discussion and all other roles are excluded',async()=>{
  const f=await fixture(),participants=['admin','admin2','neurologist','neurologist2',...groupRoles.rehab1];
  for(const sender of participants){
    const message=await f.request(sender,'rehab1','discussion');assert.equal((await f.op(sender,message)).status,200);
    assert.ok(!Object.hasOwn(message,'replyTo'));
    for(const recipient of f.audience('rehab1',sender))assert.equal((await f.client.open(dev(recipient),message.id)).meta.kind,'discussion');
  }
  const before=f.durable();
  for(const sender of ['bot','cardiologist','intensivist','rehab2_physician']){
    const message=await f.request(sender,'rehab1','discussion');assert.equal((await f.op(sender,message)).status,403);assert.deepEqual(f.durable(),before);
  }
  const good=await f.request('admin','rehab1','discussion');
  for(const group of ['cardiology','orit','rehab2']){
    const bad={...good,group,payload:{...good.payload,group}};
    assert.equal((await f.op('admin',bad)).status,403);
    assert.equal(await f.store.create(id('admin'),'0'.repeat(64),bad),'denied');
    assert.deepEqual(f.durable(),before);
  }
  const {payload,...noPayload}=good;
  for(const bad of [noPayload,{...good,replyTo:newMessageID()}])assert.equal((await f.op('admin',bad)).status,400);
});

test('25-recipient conversations deliver completely while 26-recipient audiences fail explicitly',async()=>{
  const f=await fixture();
  const extra=await Promise.all(Array.from({length:19},(_,n)=>person('Synthetic additional '+n,'rehab1_physician')));
  for(let n=0;n<18;n++)await f.add('extra'+n,extra[n]);
  assert.equal(f.audience('rehab1','psychologist').length,25);
  const good=await f.request('psychologist','rehab1','discussion');assert.equal((await f.op('psychologist',good)).status,200);
  assert.equal(f.db.dump().get('directmsg:'+good.id).recipient_count,25);
  for(const recipient of f.audience('rehab1','psychologist')){
    const target=f.members.get(recipient),opened=await f.client.open(target.device,good.id);
    assert.equal((await openMessage(target.device,opened.token,opened.payload,[people.psychologist.contact],f.now())).comment,comment);
  }
  await f.add('extra18',extra[18]);assert.equal(f.audience('rehab1','psychologist').length,26);
  const before=f.durable(),truncated=await f.request('psychologist','rehab1','discussion',undefined,f.audience('rehab1','psychologist').slice(0,25));
  const response=await f.op('psychologist',truncated);assert.equal(response.status,409);assert.deepEqual(await response.json(),{error:'group_too_large'});
  assert.deepEqual(f.durable(),before);
  const oversize={...truncated,entries:[...truncated.entries,truncated.entries[0]]};
  const tooMany=await f.op('psychologist',oversize);assert.equal(tooMany.status,409);assert.deepEqual(await tooMany.json(),{error:'group_too_large'});
  assert.deepEqual(f.durable(),before);
});

test('revocation or any recipient role change removes conversation access and reply entitlement',async()=>{
  const f=await fixture(),discussion=await f.request('rehab1_physician','rehab1','discussion');
  assert.equal((await f.op('rehab1_physician',discussion)).status,200);
  for(const [key,role] of [['psychologist','speech_therapist'],['admin','neurologist'],['neurologist','cardiologist']]){
    assert.equal((await f.client.open(dev(key),discussion.id)).meta.id,discussion.id);
    await f.recertify(key,role);
    assert.ok(!(await f.client.list(dev(key))).items.some(item=>item.id===discussion.id));
    await assert.rejects(f.client.open(dev(key),discussion.id),e=>e.status===403);
    await assert.rejects(f.client.ack(dev(key),discussion.id),e=>e.status===403);
    const reply=await f.request(key,'rehab1','group_reply',discussion.id);
    assert.equal((await f.op(key,reply)).status,403);
  }
  await f.change('exercise_therapist',{state:'revoked'});
  await assert.rejects(f.client.open(dev('exercise_therapist'),discussion.id),e=>e.status===403);
  await f.recertify('rehab1_physician','rehab2_physician');
  const originalAuthor=await f.request('rehab1_physician','rehab1','group_reply',discussion.id);
  assert.equal((await f.op('rehab1_physician',originalAuthor)).status,403);
});

test('discussion and group-reply archives preserve parent metadata, receipts and 90-day sender access',async()=>{
  const f=await fixture(),discussion=await f.request('psychologist','rehab1','discussion');
  assert.equal((await f.op('psychologist',discussion)).status,200);
  const reply=await f.request('neurologist','rehab1','group_reply',discussion.id);assert.equal((await f.op('neurologist',reply)).status,200);
  const openedAt=(await f.client.ack(dev('speech_therapist'),reply.id)).openedAt;
  f.setNow(reply.expires);
  await assert.rejects(f.client.open(dev('speech_therapist'),reply.id),e=>e.status===404);
  for(const [sender,message] of [['psychologist',discussion],['neurologist',reply]]){
    const history=await f.client.historyOpen(dev(sender),message.id),plain=await openArchivedMessage(dev(sender),history.senderToken,history.payload,f.now());
    assert.equal(history.meta.kind,message.kind);assert.equal(history.meta.replyTo,message.replyTo);assert.equal(plain.comment,comment);
    assert.equal((await f.client.history(dev(sender))).items[0].kind,message.kind);
    if(message.kind==='group_reply')assert.equal(history.recipients.find(row=>row.id===id('speech_therapist')).openedAt,openedAt);
  }
  f.setNow(reply.issued+90*DAY);
  assert.deepEqual((await f.client.history(dev('neurologist'))).items,[]);
  await assert.rejects(f.client.historyOpen(dev('neurologist'),reply.id),e=>e.status===404);
});

test('new inbox and outbox clients opt into conversations with a signed flag while old clients see legacy kinds',async()=>{
  const f=await fixture(),parent=await f.review('rehab1');assert.equal((await f.op('neurologist',parent)).status,200);
  const discussion=await f.request('psychologist','rehab1','discussion');assert.equal((await f.op('psychologist',discussion)).status,200);
  const reply=await f.request('neurologist','rehab1','group_reply',parent.id);assert.equal((await f.op('neurologist',reply)).status,200);
  const modernInbox=await f.client.list(dev('speech_therapist'));
  assert.deepEqual(modernInbox.items.map(m=>m.id).sort(),[parent.id,discussion.id,reply.id].sort());
  assert.equal(f.requests.at(-1).data.includeConversations,true);
  const modernOutbox=await f.client.list(dev('neurologist'),'outbox');
  assert.deepEqual(modernOutbox.items.map(m=>m.id).sort(),[parent.id,reply.id].sort());
  assert.equal(f.requests.at(-1).data.includeConversations,true);
  for(const [sender,operation,expected] of [['speech_therapist','inbox',[parent.id]],['neurologist','outbox',[parent.id]],['psychologist','outbox',[]]]){
    const response=await f.op(sender,{},operation);assert.equal(response.status,200);
    assert.deepEqual((await response.json()).items.map(m=>m.id),expected);
  }
  assert.deepEqual((await f.store.list(id('speech_therapist'),false)).items.map(m=>m.id),[parent.id]);
  for(const value of [false,'true',1,null])for(const operation of ['inbox','outbox'])
    assert.equal((await f.op('admin',{includeConversations:value},operation)).status,400);
  assert.equal((await f.op('admin',{includeConversations:true,extra:true},'inbox')).status,400);
  for(const operation of ['directory','admin_members','history','retry'])
    assert.equal((await f.op('admin',{includeConversations:true},operation)).status,400);
  assert.equal((await f.op('admin',{id:reply.id,includeConversations:true},'open')).status,400);
  assert.equal((await f.op('admin',{},'inbox',envelope=>{envelope.data.includeConversations=true;})).status,403);
});

test('legacy inbox and outbox paginate across over 100 hidden conversations within the transaction budget',async()=>{
  const f=await fixture(),parent=await f.review('rehab1');assert.equal((await f.op('neurologist',parent)).status,200);
  const original=f.db.dump().get('directmsg:'+parent.id),entry=f.db.dump().get('directentry:'+parent.id+':'+id('psychologist'));
  const newest=(issued,messageId)=>String(9999999999999999n-BigInt(issued)).padStart(16,'0')+':'+[...messageId].map(c=>(127-c.charCodeAt(0)).toString(16).padStart(2,'0')).join('');
  // Seed only listing metadata: encryption and authorization are covered above.
  // Some indices intentionally omit kind to cover migration from older rows.
  for(let n=0;n<130;n++){
    const messageId=newMessageID(),issued=parent.issued+1000+n,kind=n%2?'discussion':'group_reply';
    await f.db.seed('directmsg:'+messageId,{...original,id:messageId,kind,issued,recipient_count:1,
      ...(kind==='group_reply'?{reply_to:parent.id}:{})},parent.expires);
    await f.db.seed('directentry:'+messageId+':'+id('psychologist'),{...entry,message_id:messageId,recipient_role:'psychologist'},parent.expires);
    const index={message_id:messageId,...(n%3?{kind}:{})};
    await f.db.seed('directout:'+id('neurologist')+':'+newest(issued,messageId),index,parent.expires);
    await f.db.seed('directin:'+id('psychologist')+':'+newest(issued,messageId),{...index,group_name:'rehab1'},parent.expires);
  }
  f.advance(10000);
  for(const [sender,operation] of [['psychologist','inbox'],['neurologist','outbox']]){
    f.transactions.length=0;
    const firstResponse=await f.op(sender,{},operation);assert.equal(firstResponse.status,200);
    const first=await firstResponse.json();assert.deepEqual(first.items,[]);assert.ok(first.next);
    const found=[],cursors=new Set([JSON.stringify(first.next)]);let cursor=first.next;
    for(let page=0;cursor&&page<5;page++){
      const response=await f.op(sender,{cursor},operation);assert.equal(response.status,200);
      const result=await response.json();found.push(...result.items.map(m=>m.id));cursor=result.next;
      if(cursor){const encoded=JSON.stringify(cursor);assert.ok(!cursors.has(encoded),'pagination must advance past hidden rows');cursors.add(encoded);}
    }
    assert.equal(cursor,null);assert.deepEqual(found,[parent.id]);
    assert.ok(f.transactions.every(stats=>stats.operations<=512&&stats.scanned<=100));
  }
  const modern=await f.client.list(dev('psychologist'));assert.equal(modern.items.length,50);
  assert.ok(modern.items.every(item=>['discussion','group_reply'].includes(item.kind)));assert.ok(modern.next);
});

test('bot push retries skip all conversation kinds while legacy admissions and human retries still work',async()=>{
  const f=await fixture(),conversations=[];
  const admissionMeta={id:newMessageID(),group:'orit',kind:'admission',issued:f.now(),expires:f.now()+DAY};
  const entries=await Promise.all(['intensivist','intensivist2'].map(async key=>({recipientId:id(key),token:await sealSurname(dev('bot'),people[key].contact,surname)})));
  assert.equal((await f.op('bot',{...admissionMeta,entries})).status,200);
  for(const group of Object.keys(groupRoles)){
    const parent=group==='orit'?admissionMeta:await f.review(group);
    if(group!=='orit')assert.equal((await f.op('neurologist',parent)).status,200);
    const sender=f.audience(group,'neurologist',{specialistsOnly:true})[0],message=await f.request(sender,group,'group_reply',parent.id);
    assert.equal((await f.op(sender,message)).status,200);conversations.push({sender,message});
  }
  const discussion=await f.request('psychologist','rehab1','discussion');assert.equal((await f.op('psychologist',discussion)).status,200);
  conversations.push({sender:'psychologist',message:discussion});
  for(const key of Object.keys(people))await f.subscribe(key);
  f.advance(30001);
  const messageIds=new Set(conversations.map(({message})=>message.id));
  const rows=()=>[...f.db.dump()].filter(([key,value])=>
    messageIds.has(value.message_id)||key.startsWith('directarchive:')&&messageIds.has(value.id));
  const before=rows();
  for(const {message} of conversations)assert.deepEqual((await f.store.pushClaim(id('bot'),message.id)).targets,[]);
  for(let n=0;n<3;n++)await f.client.retry(dev('bot'));
  assert.ok(f.sent.some(item=>item.payload.id===admissionMeta.id));
  assert.ok(f.sent.every(item=>!messageIds.has(item.payload.id)));
  assert.deepEqual(rows(),before,'bot retries must not mutate conversation leases, queues or receipts');
  for(const [n,{sender,message}] of conversations.entries()){
    const actor=n%2?'admin':sender,claimed=await f.store.pushClaim(id(actor),message.id);
    assert.deepEqual(claimed.targets.map(target=>target.recipientId).sort(),message.entries.map(entry=>entry.recipientId).sort());
  }
});

test('legacy replies remain private and immutable before a new group reply deliberately reaches the full audience',async()=>{
  const f=await fixture(),parent=await f.review('orit');assert.equal((await f.op('neurologist',parent)).status,200);
  const privateReply=await f.request('intensivist','orit','reply',parent.id,['neurologist']);
  assert.equal((await f.op('intensivist',privateReply)).status,200);
  const archivedBefore=f.db.dump().get('directarchive:'+privateReply.id);
  assert.deepEqual(archivedBefore.recipients.map(recipient=>recipient.id),[id('neurologist')]);
  for(const outsider of ['admin','admin2','neurologist2','intensivist2'])
    await assert.rejects(f.client.open(dev(outsider),privateReply.id),e=>e.status===403);
  const conversation=await f.request('intensivist','orit','group_reply',privateReply.id);
  assert.equal((await f.op('intensivist',conversation)).status,200);
  for(const recipient of f.audience('orit','intensivist')){
    const opened=await f.client.open(dev(recipient),conversation.id);
    assert.equal(opened.meta.kind,'group_reply');assert.equal(opened.meta.replyTo,privateReply.id);
  }
  assert.deepEqual(f.db.dump().get('directarchive:'+privateReply.id),archivedBefore);
  assert.deepEqual((await f.client.historyOpen(dev('intensivist'),privateReply.id)).recipients.map(recipient=>recipient.id),[id('neurologist')]);
  const oldInbox=await f.op('neurologist',{},'inbox');assert.equal(oldInbox.status,200);
  assert.deepEqual((await oldInbox.json()).items.map(item=>item.id),[privateReply.id]);
  const colleagueInbox=await f.op('intensivist2',{},'inbox');assert.equal(colleagueInbox.status,200);
  assert.deepEqual((await colleagueInbox.json()).items.map(item=>item.id),[parent.id]);
});

test('more than 30 small encrypted discussion messages from one sender fit the same-day byte budget',async()=>{
  const f=await fixture(),issued=f.now(),messages=[];
  for(let n=0;n<31;n++){
    const message=await f.request('psychologist','rehab1','discussion');
    assert.equal(message.issued,issued);
    const response=await f.op('psychologist',message);assert.equal(response.status,200,'discussion '+(n+1));
    messages.push(message);
  }
  assert.equal((await f.client.list(dev('psychologist'),'outbox')).items.length,31);
  const last=messages.at(-1),opened=await f.client.open(dev('neurologist'),last.id);
  const value=await openMessage(dev('neurologist'),opened.token,opened.payload,[people.psychologist.contact],f.now());
  assert.equal(value.surname,surname);assert.equal(value.comment,comment);assert.equal(value.kind,'discussion');
  assert.equal(f.db.dump().get('directmsg:'+last.id).recipient_count,f.audience('rehab1','psychologist').length);
});
