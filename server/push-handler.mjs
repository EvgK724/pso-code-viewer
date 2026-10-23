// Device-signed notification operations. Public cards establish key ownership,
// not staff membership; only the existing approved writers may notify a link.
import {importPublicCard} from '../docs/exchange.mjs';
import {validateSubscription, createVapidKeys, sendWebPush} from './web-push.mjs';

const DOMAIN = 'PSO-PUSH-v1\0';
const enc = new TextEncoder();
const exact = (v, keys) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join(',') === keys;
class Rejected extends Error { constructor(status=400) { super('Rejected'); this.status=status; } }
function bytes(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) || value.length !== Math.ceil(length*4/3)) throw new Rejected();
  let result;
  try { const s=value.replace(/-/g,'+').replace(/_/g,'/'); result=Uint8Array.from(atob(s+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0)); } catch { throw new Rejected(); }
  const canonical=btoa(String.fromCharCode(...result)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  if (result.length!==length || canonical!==value) throw new Rejected();
  return result;
}
async function json(request) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get('content-type')||'')) throw new Rejected(415);
  const declared=request.headers.get('content-length');
  if (declared && (!/^\d+$/.test(declared)||Number(declared)>16384)) throw new Rejected(413);
  if (!request.body) throw new Rejected();
  const reader=request.body.getReader(), decoder=new TextDecoder('utf-8',{fatal:true}); let size=0,text='';
  try { for (;;) { const {done,value}=await reader.read(); if(done)break; size+=value.byteLength;
    if(size>16384) { await reader.cancel().catch(()=>{}); throw new Rejected(413); } text+=decoder.decode(value,{stream:true}); }
    text+=decoder.decode(); return JSON.parse(text);
  } catch(error) { if(error instanceof Rejected)throw error; throw new Rejected(); } finally { reader.releaseLock(); }
}
const hash = async (crypto, input) => [...new Uint8Array(await crypto.subtle.digest('SHA-256',input))].map(n=>n.toString(16).padStart(2,'0')).join('');

export function createPushHandler({store,allowedOrigin,crypto=globalThis.crypto,now=Date.now,send=sendWebPush}) {
  const origin=new URL(allowedOrigin);
  if(origin.protocol!=='https:' || origin.origin!==allowedOrigin)throw new Error('Configure one HTTPS origin.');
  for(const name of ['keys','accept','register','unregister','status','testSubscription','claim','finish']) if(typeof store?.[name]!=='function')throw new Error('Push store missing.');
  let keysPromise;
  function keys() {
    if(!keysPromise) keysPromise=(async()=>{
      const existing=await store.keys(null);
      const result=existing||await store.keys(await createVapidKeys({crypto}));
      bytes(result?.publicKey,65);
      if(!result?.privateKey)throw new Error('Push service unavailable.');
      return result;
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
  const rejected=(status,cors=true)=>response(status,{error:'request_rejected'},cors);
  return async request=>{
    if(request.headers.get('origin')!==allowedOrigin)return rejected(403,false);
    try {
      const url=new URL(request.url);
      if(url.search||url.hash||url.username||url.password)throw new Rejected();
      if(request.method==='OPTIONS') {
        const headers=(request.headers.get('access-control-request-headers')||'').split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
        if(request.headers.get('access-control-request-method')!=='POST'||headers.some(s=>s!=='content-type'))throw new Rejected(403);
        return response(204,null);
      }
      if(request.method!=='POST')throw new Rejected(405);
      const body=await json(request),at=now();
      if(!Number.isSafeInteger(at))throw new Error('Clock unavailable.');
      if(exact(body,'op')&&body.op==='config')return response(200,{v:1,publicKey:(await keys()).publicKey});
      if(!exact(body,'envelope')||!exact(body.envelope,'card,data,issued,nonce,op,signature,v'))throw new Rejected();
      const e=body.envelope;
      if(e.v!==1||!['register','unregister','status','test','notify'].includes(e.op)||!Number.isSafeInteger(e.issued)||e.issued<at-60000||e.issued>at+30000)throw new Rejected();
      bytes(e.nonce,16); const signature=bytes(e.signature,64);
      let owner;
      try { owner=await importPublicCard(e.card); } catch { throw new Rejected(); }
      const unsigned={v:1,op:e.op,issued:e.issued,nonce:e.nonce,card:e.card,data:e.data};
      if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},owner.signingPublicKey,signature,enc.encode(DOMAIN+JSON.stringify(unsigned))))throw new Rejected(403);
      let subscription, senders, idBytes;
      if(e.op==='register') {
        if(!exact(e.data,'senders,subscription')||!Array.isArray(e.data.senders)||e.data.senders.length>100)throw new Rejected();
        for(const id of e.data.senders)bytes(id,32);
        senders=[...new Set([owner.id,...e.data.senders])].sort();
        if(senders.length>100)throw new Rejected();
        try { subscription=await validateSubscription(e.data.subscription,{crypto}); } catch { throw new Rejected(); }
      } else if(e.op==='notify') {
        if(!exact(e.data,'id'))throw new Rejected();
        idBytes=bytes(e.data.id,16);
      } else if(!exact(e.data,''))throw new Rejected();
      const accepted=await store.accept(owner.id,e.nonce,e.op,e.issued);
      if(accepted!=='ok')throw new Rejected(accepted==='limited'?429:accepted==='replay'?409:400);
      if(e.op==='register') {
        const result=await store.register(owner.id,subscription,senders);
        if(result!=='ok')throw new Rejected(result==='limited'?429:409);
        return response(200,{status:'enabled'});
      }
      if(e.op==='unregister') { await store.unregister(owner.id); return response(200,{status:'disabled'}); }
      if(e.op==='status')return response(200,{status:await store.status(owner.id)?'enabled':'disabled'});
      if(e.op==='test') {
        const own=await store.testSubscription(owner.id);
        if(!own)return response(200,{status:'unavailable'});
        const result=await send(own,await keys(),{v:1,id:null,expires:at+120000},{now:at,ttl:120,crypto});
        // Do not remove a subscription here: it may have been replaced since read.
        return response(200,{status:['accepted','gone'].includes(result?.status)?result.status:'failed'});
      }
      const idHash=await hash(crypto,idBytes),claimed=await store.claim(owner.id,idHash);
      if(claimed?.status!=='ready')return response(200,{status:['accepted','failed','gone','already'].includes(claimed?.status)?claimed.status:'unavailable'});
      if(!Number.isSafeInteger(claimed.expires)||claimed.expires<=at||claimed.expires>at+86400000) {
        await store.finish(idHash,'failed');return response(200,{status:'failed'});
      }
      let status='failed';
      try {
        const result=await send(claimed.subscription,await keys(),{v:1,id:e.data.id,expires:claimed.expires},{now:at,ttl:Math.min(86400,Math.max(0,Math.floor((claimed.expires-at)/1000))),crypto});
        status=['accepted','gone'].includes(result?.status)?result.status:'failed';
      } finally { await store.finish(idHash,status); }
      return response(200,{status});
    } catch(error) { return rejected(error instanceof Rejected?error.status:503); }
  };
}
