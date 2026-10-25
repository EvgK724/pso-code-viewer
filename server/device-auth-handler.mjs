// Custom device signatures authenticate the account; WebAuthn verifies its holder.
// The FIDO verifier is injected from the pinned, maintained SimpleWebAuthn package.
import {importPublicCard} from '../docs/exchange.mjs';
const DOMAIN='PSO-TEAM-v1\0',enc=new TextEncoder(),MAX_BODY=131072;
const OPS=['status','enroll_begin','enroll_finish','unlock_begin','unlock_finish','reset'];
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===k;
const b64=x=>btoa(String.fromCharCode(...new Uint8Array(x))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function bytes(s,n){if(typeof s!=='string'||!/^[A-Za-z0-9_-]+$/.test(s)||s.length>131072)throw new Denied(400);const t=s.replace(/-/g,'+').replace(/_/g,'/');const r=Uint8Array.from(atob(t+'='.repeat((4-t.length%4)%4)),c=>c.charCodeAt(0));if((n&&r.length!==n)||b64(r)!==s)throw new Denied(400);return r;}
class Denied extends Error{constructor(status=403){super('Request rejected');this.status=status;}}
const sha=async(c,s)=>[...new Uint8Array(await c.subtle.digest('SHA-256',enc.encode(s)))].map(x=>x.toString(16).padStart(2,'0')).join('');
async function read(request){
  if(!/^application\/json(?:\s*;|$)/i.test(request.headers.get('content-type')||''))throw new Denied(415);
  if(Number(request.headers.get('content-length'))>MAX_BODY)throw new Denied(413);
  const r=request.body?.getReader();if(!r)throw new Denied(400);let n=0,text='';const d=new TextDecoder('utf-8',{fatal:true});
  try{for(;;){const{done,value}=await r.read();if(done)break;n+=value.byteLength;if(n>MAX_BODY){await r.cancel();throw new Denied(413);}text+=d.decode(value,{stream:true});}text+=d.decode();return JSON.parse(text);}catch(e){if(e instanceof Denied)throw e;throw new Denied(400);}finally{r.releaseLock();}
}
export function createDeviceAuthHandler({store,webauthn,allowedOrigin,crypto=globalThis.crypto,now=Date.now}){
  const origin=new URL(allowedOrigin);if(origin.protocol!=='https:'||origin.origin!==allowedOrigin)throw new Error('Configure HTTPS origin');const rpID=origin.hostname;
  for(const name of ['accept','status','credential','challengePut','challengeTake','enroll','unlock','reset'])if(typeof store?.[name]!=='function')throw new Error('Auth store missing');
  for(const name of ['generateRegistrationOptions','verifyRegistrationResponse','generateAuthenticationOptions','verifyAuthenticationResponse'])if(typeof webauthn?.[name]!=='function')throw new Error('WebAuthn verifier missing');
  const response=(status,value,cors=true)=>new Response(status===204?null:JSON.stringify(value),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','Vary':'Origin',...(cors?{'Access-Control-Allow-Origin':allowedOrigin}:{}),...(status===204?{'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Content-Type','Access-Control-Max-Age':'600'}:{})}});
  function check(result){if(result==='ok')return;if(result==='conflict')throw new Denied(409);if(result==='limited')throw new Denied(429);if(result==='locked')throw new Denied(428);throw new Denied();}
  async function makeSession(owner,credential,oldCounter,registration){
    const token=b64(crypto.getRandomValues(new Uint8Array(32))),at=now(),expires=at+600000;
    const result=registration?await store.enroll(owner.id,credential,await sha(crypto,token),expires):await store.unlock(owner.id,credential.id,oldCounter,credential.counter,await sha(crypto,token),expires);
    check(result);return{token,expires};
  }
  return async request=>{
    if(request.headers.get('origin')!==allowedOrigin)return response(403,{error:'request_rejected'},false);
    try{
      const u=new URL(request.url);if(u.hash||u.search||u.username||u.password)throw new Denied(400);
      if(request.method==='OPTIONS'){if(request.headers.get('access-control-request-method')!=='POST'||(request.headers.get('access-control-request-headers')||'').split(',').map(x=>x.trim().toLowerCase()).some(x=>x&&x!=='content-type'))throw new Denied();return response(204,null);}
      if(request.method!=='POST')throw new Denied(405);
      const body=await read(request),e=body?.envelope,at=now();
      if(!exact(body,'envelope')||!exact(e,'card,data,issued,nonce,op,signature,v')||e.v!==1||!OPS.includes(e.op)||!Number.isSafeInteger(e.issued)||e.issued<at-60000||e.issued>at+30000)throw new Denied(400);
      bytes(e.nonce,16);const signature=bytes(e.signature,64);let owner;try{owner=await importPublicCard(e.card);}catch{throw new Denied(400);}
      const unsigned={v:1,op:e.op,issued:e.issued,nonce:e.nonce,card:e.card,data:e.data};
      if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},owner.signingPublicKey,signature,enc.encode(DOMAIN+JSON.stringify(unsigned))))throw new Denied();
      if(e.op.endsWith('_finish')){if(!exact(e.data,'credential')||!e.data.credential||typeof e.data.credential!=='object')throw new Denied(400);}
      else if(e.op==='reset'){if(!exact(e.data,'targetId,unlockToken'))throw new Denied(400);bytes(e.data.targetId,32);if(e.data.unlockToken!=='')bytes(e.data.unlockToken,32);}
      else if(!exact(e.data,''))throw new Denied(400);
      check(await store.accept(owner.id,e.nonce,e.issued,e.card,b64(await crypto.subtle.exportKey('spki',owner.signingPublicKey))));
      if(e.op==='status'){const r=await store.status(owner.id);if(!exact(r,'enabled')||typeof r.enabled!=='boolean')throw new Denied();return response(200,r);}
      if(e.op==='reset'){check(await store.reset(owner.id,e.data.targetId,e.data.unlockToken));return response(200,{reset:true});}
      const current=await store.credential(owner.id);
      if(e.op==='enroll_begin'){
        if(current)throw new Denied(409);
        const options=await webauthn.generateRegistrationOptions({rpName:'ПСО Просмотрщик',rpID,userID:bytes(owner.id,32),userName:'Телефон '+owner.id.slice(0,8),userDisplayName:'Телефон врача ПСО',attestationType:'none',supportedAlgorithmIDs:[-7,-257],authenticatorSelection:{authenticatorAttachment:'platform',residentKey:'preferred',userVerification:'required'},timeout:120000});
        check(await store.challengePut(owner.id,'enroll',options.challenge,at+300000));return response(200,{options});
      }
      if(e.op==='unlock_begin'){
        if(!current)throw new Denied(409);
        const options=await webauthn.generateAuthenticationOptions({rpID,userVerification:'required',allowCredentials:[{id:current.id,transports:current.transports||[]}],timeout:120000});
        check(await store.challengePut(owner.id,'unlock',options.challenge,at+300000));return response(200,{options});
      }
      const registration=e.op==='enroll_finish';if(registration?!!current:!current)throw new Denied(409);
      const challenge=await store.challengeTake(owner.id,registration?'enroll':'unlock');if(typeof challenge!=='string'||!challenge)throw new Denied(409);
      let verified;
      try{
        if(registration){
          verified=await webauthn.verifyRegistrationResponse({response:e.data.credential,expectedChallenge:challenge,expectedOrigin:allowedOrigin,expectedRPID:rpID,requireUserVerification:true,supportedAlgorithmIDs:[-7,-257]});
          if(!verified.verified||!verified.registrationInfo?.userVerified)throw new Error('verification');
          const c=verified.registrationInfo.credential;
          const credential={id:c.id,publicKey:b64(c.publicKey),counter:c.counter,transports:(c.transports||[]).filter(x=>['usb','nfc','ble','smart-card','hybrid','internal'].includes(x))};
          bytes(credential.id);bytes(credential.publicKey);if(!Number.isSafeInteger(credential.counter)||credential.counter<0)throw new Error('counter');
          return response(200,await makeSession(owner,credential,null,true));
        }
        if(e.data.credential.id!==current.id)throw new Error('wrong credential');
        verified=await webauthn.verifyAuthenticationResponse({response:e.data.credential,expectedChallenge:challenge,expectedOrigin:allowedOrigin,expectedRPID:rpID,credential:{id:current.id,publicKey:bytes(current.publicKey),counter:current.counter,transports:current.transports||[]},requireUserVerification:true});
        if(!verified.verified||!verified.authenticationInfo?.userVerified)throw new Error('verification');
      }catch(error){if(error instanceof Denied)throw error;throw new Denied();}
      return response(200,await makeSession(owner,{id:current.id,counter:verified.authenticationInfo.newCounter},current.counter,false));
    }catch(error){return response(error instanceof Denied?error.status:503,{error:error instanceof Denied&&error.status===428?'unlock_required':'request_rejected'});}
  };
}
