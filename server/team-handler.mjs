// Role-bound, device-signed team workflow. Patient plaintext never reaches here.
// The database rechecks roles and the exact active recipient set atomically.
import {importPublicCard} from '../docs/exchange.mjs';
import {createVapidKeys, sendWebPush} from './web-push.mjs';

export const MAX_TEAM_BODY_BYTES = 32768;
const DOMAIN = 'PSO-TEAM-v1\0', TOKEN_DOMAIN = 'PSO-SURNAME-LINK-v1\0';
const MAX_TTL = 86400000, MAX_RECIPIENTS = 25;
const OPS = ['status','directory','invite','claim','pending','approve','revoke','create','resolve'];
const ROLES = ['admin','neurologist','cardiologist','intensivist','bot'];
const enc = new TextEncoder();
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;
const b64 = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
class Rejected extends Error {
  constructor(status=400, code='request_rejected') { super('Request rejected'); this.status=status; this.code=code; }
}
function bytes(value, length) {
  if (typeof value !== 'string' || value.length !== Math.ceil(length*4/3) || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Rejected();
  let result;
  try { const text=value.replace(/-/g,'+').replace(/_/g,'/'); result=Uint8Array.from(atob(text+'='.repeat((4-text.length%4)%4)),c=>c.charCodeAt(0)); }
  catch { throw new Rejected(); }
  if(result.length!==length || b64(result)!==value)throw new Rejected();
  return result;
}
function name(value) {
  if(typeof value!=='string'||!value||value!==value.normalize('NFC').trim()||[...value].length>60||/[\p{Cc}\p{Cf}]/u.test(value))throw new Rejected();
  return value;
}
async function readJSON(request) {
  if(!/^application\/json(?:\s*;|$)/i.test(request.headers.get('content-type')||''))throw new Rejected(415);
  const declared=request.headers.get('content-length');
  if(declared&&(!/^\d+$/.test(declared)||Number(declared)>MAX_TEAM_BODY_BYTES))throw new Rejected(413);
  if(!request.body)throw new Rejected();
  const reader=request.body.getReader(), decoder=new TextDecoder('utf-8',{fatal:true});let size=0,text='';
  try {
    for(;;){const{done,value}=await reader.read();if(done)break;size+=value.byteLength;
      if(size>MAX_TEAM_BODY_BYTES){await reader.cancel().catch(()=>{});throw new Rejected(413);}
      text+=decoder.decode(value,{stream:true});}
    text+=decoder.decode();return JSON.parse(text);
  } catch(error){if(error instanceof Rejected)throw error;throw new Rejected();}
  finally{reader.releaseLock();}
}
const hash = async(crypto,value)=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',value))].map(n=>n.toString(16).padStart(2,'0')).join('');
function tokenParts(token) {
  if(typeof token!=='string'||token.length>900)throw new Rejected();
  const p=token.split('.');if(p.length!==5||p[0]!=='PSO1')throw new Rejected();
  bytes(p[1],32);bytes(p[2],32);bytes(p[3],384);bytes(p[4],64);
  return p;
}
function member(value) {
  if(!exact(value,'card,id,name,role')||!ROLES.includes(value.role)||typeof value.card!=='string'||!value.card.startsWith('PSO-CARD1.')||value.card.length>5000)throw new Error('Invalid team storage response');
  bytes(value.id,32);name(value.name);return {id:value.id,name:value.name,role:value.role,card:value.card};
}
function members(value) {
  if(!Array.isArray(value)||value.length>100)throw new Error('Invalid team storage response');
  return value.map(member);
}
function failure(status) {
  if(status==='limited')throw new Rejected(429);
  if(status==='replay')throw new Rejected(409,'replay');
  if(status==='roster_changed')throw new Rejected(409,'roster_changed');
  if(status==='conflict')throw new Rejected(409,'id_conflict');
  if(status==='invalid')throw new Rejected(400);
  if(status==='missing')throw new Rejected(404);
  if(status==='denied')throw new Rejected(403);
  throw new Error('Team storage unavailable');
}

export function createTeamHandler({store,allowedOrigin,crypto=globalThis.crypto,now=Date.now,send=sendWebPush}) {
  const origin=new URL(allowedOrigin);
  if(origin.protocol!=='https:'||origin.origin!==allowedOrigin)throw new Error('Configure one HTTPS origin');
  for(const method of ['accept','status','directory','invite','claim','pending','approve','revoke','create','resolve','pushClaim','pushFinish','keys'])
    if(typeof store?.[method]!=='function')throw new Error('Team store missing');
  let keysPromise;
  function keys() {
    if(!keysPromise)keysPromise=(async()=>{
      const result=await store.keys(null)||await store.keys(await createVapidKeys({crypto}));
      bytes(result?.publicKey,65);if(!result?.privateKey)throw new Error('Push service unavailable');return result;
    })().catch(error=>{keysPromise=null;throw error;});
    return keysPromise;
  }
  function response(status,body,cors=true) {
    const headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','Vary':'Origin'};
    if(cors)headers['Access-Control-Allow-Origin']=allowedOrigin;
    if(status===204)Object.assign(headers,{'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Content-Type','Access-Control-Max-Age':'600'});
    else headers['Content-Type']='application/json; charset=utf-8';
    return new Response(status===204?null:JSON.stringify(body),{status,headers});
  }
  async function notify(senderID,id,idHash,at,expectedRecipients) {
    // Notification failure never changes or rolls back the committed ciphertext.
    // Claims are made once and per recipient, including when an HTTP reply is lost.
    try {
      const claimed=await store.pushClaim(senderID,idHash);
      if(!exact(claimed,'targets')||!Array.isArray(claimed.targets)||claimed.targets.length>MAX_RECIPIENTS)throw new Error('Invalid push claim');
      if(!claimed.targets.length)return'unavailable';
      const seen=new Set();
      for(const target of claimed.targets){
        if(!exact(target,'expires,recipientId,subscription')||!expectedRecipients.includes(target.recipientId)||seen.has(target.recipientId))throw new Error('Unexpected push recipient');
        seen.add(target.recipientId);
      }
      const outcomes=await Promise.all(claimed.targets.map(async target=>{
        let status='failed';
        try {
          bytes(target.recipientId,32);
          if(!Number.isSafeInteger(target.expires)||target.expires<=at||target.expires>at+MAX_TTL)throw new Error('Expired push');
          const result=await send(target.subscription,await keys(),{v:1,id,expires:target.expires},{now:at,ttl:Math.max(0,Math.floor((target.expires-at)/1000)),crypto});
          if(['accepted','gone'].includes(result?.status))status=result.status;
        } catch { /* Provider details and subscription endpoints stay private. */ }
        finally {try{await store.pushFinish(idHash,target.recipientId,status);}catch{/* Claim remains spent; never resend on ambiguity. */}}
        return status;
      }));
      const accepted=outcomes.filter(s=>s==='accepted').length;
      return accepted===expectedRecipients.length?'accepted':accepted>0?'partial':'unavailable';
    } catch {return'unavailable';}
  }
  return async function handle(request) {
    if(request.headers.get('origin')!==allowedOrigin)return response(403,{error:'request_rejected'},false);
    try {
      const url=new URL(request.url);
      if(url.search||url.hash||url.username||url.password)throw new Rejected();
      if(request.method==='OPTIONS') {
        const requested=(request.headers.get('access-control-request-headers')||'').split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
        if(request.headers.get('access-control-request-method')!=='POST'||requested.some(s=>s!=='content-type'))throw new Rejected(403);
        return response(204,null);
      }
      if(request.method!=='POST')throw new Rejected(405);
      const body=await readJSON(request),at=now();
      if(!Number.isSafeInteger(at))throw new Error('Clock unavailable');
      if(!exact(body,'envelope')||!exact(body.envelope,'card,data,issued,nonce,op,signature,v'))throw new Rejected();
      const e=body.envelope;
      if(e.v!==1||!OPS.includes(e.op)||!Number.isSafeInteger(e.issued)||e.issued<at-60000||e.issued>at+30000)throw new Rejected();
      bytes(e.nonce,16);const signature=bytes(e.signature,64);
      let owner;try{owner=await importPublicCard(e.card);}catch{throw new Rejected();}
      const unsigned={v:1,op:e.op,issued:e.issued,nonce:e.nonce,card:e.card,data:e.data};
      if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},owner.signingPublicKey,signature,enc.encode(DOMAIN+JSON.stringify(unsigned))))throw new Rejected(403);
      const data=e.data;let idHash,normalizedCreate;
      if(['status','directory','pending'].includes(e.op)) {
        if(!exact(data,''))throw new Rejected();
      } else if(e.op==='invite') {
        if(!exact(data,'id,name,role')||!['neurologist','cardiologist','intensivist','bot'].includes(data.role))throw new Rejected();
        name(data.name);idHash=await hash(crypto,bytes(data.id,16));
      } else if(['claim','resolve'].includes(e.op)) {
        if(!exact(data,'id'))throw new Rejected();idHash=await hash(crypto,bytes(data.id,16));
      } else if(['approve','revoke'].includes(e.op)) {
        if(!exact(data,'deviceId'))throw new Rejected();bytes(data.deviceId,32);
      } else {
        if(!exact(data,'entries,expires,group,id,issued,kind')||!['cardiology','orit'].includes(data.group)||!['admission','review'].includes(data.kind)||
          !Number.isSafeInteger(data.issued)||!Number.isSafeInteger(data.expires)||data.issued<=0||data.expires<=at||data.expires<=data.issued||
          data.expires-data.issued>MAX_TTL||data.issued>at+30000||!Array.isArray(data.entries)||data.entries.length<1||data.entries.length>MAX_RECIPIENTS)throw new Rejected();
        idHash=await hash(crypto,bytes(data.id,16));const seen=new Set(),entries=[];
        for(const entry of data.entries) {
          if(!exact(entry,'recipientId,token'))throw new Rejected();bytes(entry.recipientId,32);
          if(seen.has(entry.recipientId))throw new Rejected();seen.add(entry.recipientId);
          const parts=tokenParts(entry.token);
          if(parts[1]!==entry.recipientId||parts[2]!==owner.id)throw new Rejected(403);
          if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},owner.signingPublicKey,bytes(parts[4],64),enc.encode(TOKEN_DOMAIN+parts.slice(0,4).join('.'))))throw new Rejected(403);
          entries.push({recipientId:entry.recipientId,token:entry.token});
        }
        entries.sort((a,b)=>a.recipientId<b.recipientId?-1:a.recipientId>b.recipientId?1:0);
        normalizedCreate={id:data.id,group:data.group,kind:data.kind,issued:data.issued,expires:data.expires,entries};
      }
      const signingSPKI=b64(await crypto.subtle.exportKey('spki',owner.signingPublicKey));
      const accepted=await store.accept(owner.id,e.nonce,e.op,e.issued,e.card,signingSPKI);
      if(accepted!=='ok')failure(accepted);
      if(e.op==='status') {
        const result=await store.status(owner.id);
        if(!exact(result,'name,role,state')||!['unregistered','pending','active','revoked'].includes(result.state)||
          !(result.role===null||ROLES.includes(result.role))||!(result.name===null||typeof result.name==='string'))throw new Error('Invalid status');
        return response(200,{state:result.state,role:result.role,name:result.name});
      }
      if(e.op==='directory'||e.op==='pending') {
        const result=await store[e.op](owner.id);if(result?.status&&result.status!=='ok')failure(result.status);
        return response(200,{members:members(result?.members)});
      }
      if(e.op==='invite') {
        const result=await store.invite(owner.id,idHash,data.name,data.role);
        if(!['created','exists'].includes(result?.status))failure(result?.status);
        if(!Number.isSafeInteger(result.expires)||result.expires<=at)throw new Error('Invalid invitation');
        return response(200,{id:data.id,expires:result.expires});
      }
      if(e.op==='claim') {
        const state=await store.claim(owner.id,idHash,e.card,signingSPKI);if(!['pending','active'].includes(state))failure(state);
        return response(200,{state});
      }
      if(e.op==='approve'||e.op==='revoke') {
        const state=await store[e.op](owner.id,data.deviceId),expected=e.op==='approve'?'active':'revoked';
        if(state!==expected)failure(state);return response(200,{state});
      }
      if(e.op==='resolve') {
        const result=await store.resolve(owner.id,idHash);if(result?.status!=='ok')failure(result?.status);
        if(!Number.isSafeInteger(result.expires)||result.expires<=at)throw new Rejected(404);
        let parts;try{parts=tokenParts(result.token);}catch{throw new Error('Invalid stored token');}
        if(parts[1]!==owner.id)throw new Error('Wrong recipient from storage');
        let sender;try{sender=await importPublicCard(result.senderCard);}catch{throw new Error('Invalid stored sender');}
        if(sender.id!==parts[2]||!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},sender.signingPublicKey,bytes(parts[4],64),enc.encode(TOKEN_DOMAIN+parts.slice(0,4).join('.'))))throw new Error('Invalid stored token');
        name(result.senderName);
        return response(200,{token:result.token,expires:result.expires,senderCard:result.senderCard,senderName:result.senderName});
      }
      const result=await store.create(owner.id,idHash,await hash(crypto,enc.encode(JSON.stringify(normalizedCreate))),normalizedCreate.group,normalizedCreate.kind,normalizedCreate.issued,normalizedCreate.expires,normalizedCreate.entries);
      if(!['created','exists'].includes(result))failure(result);
      // Existing identical requests are safe retries, never another notification.
      const push=result==='created'?await notify(owner.id,data.id,idHash,at,normalizedCreate.entries.map(entry=>entry.recipientId)):'unavailable';
      return response(200,{id:data.id,expires:data.expires,push});
    } catch(error) {
      return response(error instanceof Rejected?error.status:503,{error:error instanceof Rejected?error.code:'request_rejected'});
    }
  };
}
