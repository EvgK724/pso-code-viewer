// Requires private-function IAM access and explicit setup mode. A context token
// authenticates the function to YDB, NOT the invoking caller. Bootstrap identity
// comes only from operator configuration, never from an invocation body.
import {randomBytes} from 'node:crypto';
import {importPublicCard} from '../../docs/exchange.mjs';
import {createTeamStore} from './team-store.mjs';
import {createDirectStore} from './direct-store.mjs';
import {validName} from './team-store.mjs';
import {validateOrigin} from './http.mjs';
const DAY=86400000;
function assert(value){if(!value)throw new Error('Self-test failed');}
export function scopedDatabase(db,prefix){
 const key=k=>prefix+k;
 return {transaction:callback=>db.transaction(tx=>callback({
  get:k=>tx.get(key(k)),put:(k,v,e=0)=>tx.put(key(k),v,Math.min(e||Infinity,Date.now()+3600000)),delete:k=>tx.delete(key(k)),
  scan:async(p,o={})=>(await tx.scan(key(p),{...o,...(o.after?{after:key(o.after)}:{})})).map(r=>({...r,key:r.key.slice(prefix.length)}))
 }))};
}
export async function runDatabaseSelfTest(db){
 const run=randomBytes(12).toString('hex'),prefix=`selftest:${run}:`,test=scopedDatabase(db,prefix);
 const checks=[];let stage='write_read';
 try{
  await test.transaction(async tx=>{await tx.put('probe:a',{value:1});assert((await tx.get('probe:a'))?.value===1);});checks.push(stage);
  stage='rollback';
  try{await test.transaction(async tx=>{await tx.put('probe:rollback',{value:1});throw new Error('intentional');});}catch{}
  assert(await test.transaction(tx=>tx.get('probe:rollback'))===null);checks.push(stage);
  stage='expiry_and_cursor';
  await test.transaction(async tx=>{await tx.put('probe:expired',{value:1},Date.now()-1000);await tx.put('probe:b',{value:2});});
  await test.transaction(async tx=>{assert(await tx.get('probe:expired')===null);const rows=await tx.scan('probe:',{after:'probe:a',limit:1});assert(rows.length===1&&rows[0].key==='probe:b');});checks.push(stage);
  stage='concurrent_transactions';
  await test.transaction(tx=>tx.put('counter:1',{value:0}));
  await Promise.all([1,2,3].map(()=>test.transaction(async tx=>{const r=await tx.get('counter:1');await tx.put('counter:1',{value:r.value+1});})));
  assert((await test.transaction(tx=>tx.get('counter:1'))).value===3);checks.push(stage);
  stage='recipient_and_revocation';
  const at=Date.now(),id=n=>Buffer.alloc(32,n).toString('base64url'),admin=id(1),sender=id(2),recipient=id(3),wrong=id(4);
  const member=(n,role)=>({device_id:id(n),name:'ТЕСТ',role,state:'active',card:'PSO-CARD1.'+'A'.repeat(150),signing_spki:'A'.repeat(122),invite_hash:null,created_at:at,approved_at:at,revoked_at:null,approval_proof:role==='admin'?null:{grant:{issuerId:admin,subjectId:id(n),name:'ТЕСТ',role,expires:at+DAY}}});
  await test.transaction(async tx=>{await tx.put('member:'+admin,member(1,'admin'));await tx.put('member:'+sender,member(2,'bot'));await tx.put('member:'+recipient,member(3,'cardiologist'));await tx.put('member:'+wrong,member(4,'intensivist'));});
  const direct=createDirectStore(test,{now:()=>at}),team=createTeamStore(test,{now:()=>at});
  const messageId=Buffer.alloc(16,5).toString('base64url');
  const data={id:messageId,group:'cardiology',kind:'admission',issued:at,expires:at+600000,entries:[{recipientId:recipient,token:`PSO1.${recipient}.${sender}.${'A'.repeat(512)}.${'A'.repeat(86)}`}],senderProof:(await test.transaction(tx=>tx.get('member:'+sender))).approval_proof};
  const hash='a'.repeat(64);
  const created=await direct.create(sender,hash,data);assert(['created','exists'].includes(created?.status||created));
  const repeated=await direct.create(sender,hash,data);assert((repeated?.status||repeated)==='exists');
  const incorrect=await direct.open(wrong,messageId,false);assert(['missing','denied'].includes(incorrect?.status));
  const opened=await direct.open(recipient,messageId,false);assert(opened&&!opened.status);
  assert(await team.revoke(admin,recipient)==='revoked');
  const denied=await direct.open(recipient,messageId,false);assert(['denied','missing'].includes(denied?.status));checks.push(stage);
  return {ok:true,checks,message:'Проверки записи, транзакций и разграничения доступа пройдены. Это ещё не проверка телефонов и push-уведомлений.'};
 }catch{return {ok:false,stage,checks,message:'Проверка не пройдена. Отправьте этот результат для диагностики.'};}
 finally{
  // Only synthetic rows from this random namespace can be deleted here.
  // A one-hour expiry bounds leftovers if cleanup itself is interrupted.
  try{await db.transaction(async tx=>{for(;;){const rows=await tx.scan(prefix,{limit:1000});for(const row of rows)await tx.delete(row.key);if(rows.length<1000)break;}});}catch{}
 }
}
export async function bootstrapOrganizer(db,card,allowedOrigin){
 const origin=validateOrigin(allowedOrigin),owner=await importPublicCard(card);
 if(!validName(owner.name))throw new Error('Invalid organizer name');
 const signing_spki=Buffer.from(await crypto.subtle.exportKey('spki',owner.signingPublicKey)).toString('base64url');
 return db.transaction(async tx=>{
  const current=await tx.get('config:organizer'),members=await tx.scan('member:',{limit:101});
  if(current){if(current.device_id!==owner.id||current.origin!==origin||current.card!==owner.card)throw new Error('Organizer already set');return {ok:true,alreadyConfigured:true};}
  if(members.length)throw new Error('Nonempty team needs manual review');
  const at=Date.now();
  await tx.put('member:'+owner.id,{device_id:owner.id,name:owner.name,role:'admin',state:'active',card:owner.card,signing_spki,invite_hash:null,created_at:at,approved_at:at,revoked_at:null,approval_proof:null});
  await tx.put('config:organizer',{device_id:owner.id,origin,card:owner.card,created_at:at});
  return {ok:true,message:'Организатор подключён. Теперь выключите режим настройки.',fingerprint:owner.fingerprint};
 });
}
export async function runMaintenance(db,event,{allowedOrigin,organizerCard}={}){
 if(!event||typeof event!=='object'||Array.isArray(event))throw new Error('Invalid action');
 const action=event.action;
 if(action==='initialize'&&Object.keys(event).join(',')==='action'){await db.ensureSchema();return {ok:true,message:'Таблица pso_state создана или проверена. Следующий тест: selftest.'};}
 if(action==='selftest'&&Object.keys(event).join(',')==='action')return runDatabaseSelfTest(db);
 if(action==='bootstrap'&&Object.keys(event).join(',')==='action'&&organizerCard)return bootstrapOrganizer(db,organizerCard,allowedOrigin);
 throw new Error('Unknown action');
}
