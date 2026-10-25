// Real SimpleWebAuthn verification against a synthetic ES256 authenticator.
// Run with PSO_WEBAUTHN_TEST_MODULE=/absolute/path/to/@simplewebauthn/server/esm/index.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {makeDevice} from '../docs/crypto.mjs';
import {deviceIdentity} from '../docs/exchange.mjs';
import {deviceAuthEnvelope} from '../docs/device-unlock.mjs';
import {createDeviceAuthHandler} from './device-auth-handler.mjs';
const modulePath=process.env.PSO_WEBAUTHN_TEST_MODULE;
const webauthn=modulePath?await import(pathToFileURL(modulePath).href):null;
const origin='https://viewer.example',rpID='viewer.example',enc=new TextEncoder();
const b64=x=>Buffer.from(x).toString('base64url'),unb64=x=>Buffer.from(x,'base64url');
const hash=async x=>Buffer.from(await crypto.subtle.digest('SHA-256',x));
// CBOR is test fixture encoding only. Production decoding is SimpleWebAuthn.
function cbor(v){
 const head=(m,n)=>n<24?Buffer.from([(m<<5)|n]):n<256?Buffer.from([(m<<5)|24,n]):Buffer.from([(m<<5)|25,n>>8,n&255]);
 if(typeof v==='number')return head(v>=0?0:1,v>=0?v:-1-v);
 if(typeof v==='string'){const b=Buffer.from(v);return Buffer.concat([head(3,b.length),b]);}
 if(v instanceof Uint8Array)return Buffer.concat([head(2,v.length),Buffer.from(v)]);
 const entries=v instanceof Map?[...v]:Object.entries(v);return Buffer.concat([head(5,entries.length),...entries.flatMap(([k,x])=>[cbor(k),cbor(x)])]);
}
function der(raw){const b=Buffer.from(raw);const integer=x=>{let y=x;while(y.length>1&&y[0]===0)y=y.subarray(1);if(y[0]&128)y=Buffer.concat([Buffer.from([0]),y]);return Buffer.concat([Buffer.from([2,y.length]),y]);};const r=integer(b.subarray(0,32)),s=integer(b.subarray(32));return Buffer.concat([Buffer.from([0x30,r.length+s.length]),r,s]);}
async function fixture(){
 const device=await makeDevice(),id=(await deviceIdentity(device)).id,key=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const jwk=await crypto.subtle.exportKey('jwk',key.publicKey),credentialId=crypto.getRandomValues(new Uint8Array(32));
 const pub=cbor(new Map([[1,2],[3,-7],[-1,1],[-2,unb64(jwk.x)],[-3,unb64(jwk.y)]]));
 let current=null,challenge=null,revoked=false,counter=0;const used=new Set();
 const store={
  accept:async(owner,nonce)=>{if(owner!==id||revoked)return'denied';if(used.has(nonce))return'conflict';used.add(nonce);return'ok';},status:async()=>({enabled:!!current}),credential:async()=>current,
  challengePut:async(owner,purpose,value,expires)=>{challenge={purpose,value,expires};return'ok';},challengeTake:async(owner,purpose)=>{const c=challenge;challenge=null;return c?.purpose===purpose&&c.expires>Date.now()?c.value:null;},
  enroll:async(owner,credential)=>{current=credential;return'ok';},unlock:async(owner,credential,old,next)=>{assert.equal(old,current.counter);current.counter=next;return'ok';},reset:async()=>{current=null;return'ok';}
 };
 const handler=createDeviceAuthHandler({store,webauthn,allowedOrigin:origin});
 const call=async(op,data={})=>handler(new Request('https://api.example/auth',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:JSON.stringify({envelope:await deviceAuthEnvelope(device,op,data)})}));
 async function registration(ch,settings={}){
  const client=enc.encode(JSON.stringify({type:'webauthn.create',challenge:ch,origin:settings.origin||origin,crossOrigin:false}));
  const auth=Buffer.concat([await hash(enc.encode(settings.rpID||rpID)),Buffer.from([settings.noUV?0x41:0x45]),Buffer.alloc(4),Buffer.alloc(16),Buffer.from([0,credentialId.length]),Buffer.from(credentialId),pub]);
  return{id:b64(credentialId),rawId:b64(credentialId),type:'public-key',clientExtensionResults:{},response:{clientDataJSON:b64(client),attestationObject:b64(cbor({fmt:'none',attStmt:{},authData:auth})),transports:['internal']}};
 }
 async function authentication(ch,settings={}){
  const client=enc.encode(JSON.stringify({type:'webauthn.get',challenge:ch,origin:settings.origin||origin,crossOrigin:false}));
  const num=Buffer.alloc(4);num.writeUInt32BE(++counter);
  const auth=Buffer.concat([await hash(enc.encode(settings.rpID||rpID)),Buffer.from([settings.noUV?1:5]),num]);
  const sig=der(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key.privateKey,Buffer.concat([auth,await hash(client)])));
  if(settings.badSignature)sig[sig.length-1]^=1;
  return{id:b64(credentialId),rawId:b64(credentialId),type:'public-key',clientExtensionResults:{},response:{clientDataJSON:b64(client),authenticatorData:b64(auth),signature:b64(sig),userHandle:id}};
 }
 return{call,registration,authentication,revoke(){revoked=true;}};
}
test('real verifier: registration, authentication, origin/RP/challenge/UV/signature checks',{skip:!webauthn},async()=>{
 const h=await fixture();
 for(const settings of [{origin:'https://evil.example'},{rpID:'evil.example'},{noUV:true}]){
  const {options}=await(await h.call('enroll_begin')).json();assert.equal((await h.call('enroll_finish',{credential:await h.registration(options.challenge,settings)})).status,403);
 }
 const {options}=await(await h.call('enroll_begin')).json();const cred=await h.registration(options.challenge);const registered=await h.call('enroll_finish',{credential:cred});assert.equal(registered.status,200,JSON.stringify(await registered.clone().json()));
 assert.equal((await h.call('enroll_finish',{credential:cred})).status,409);
 for(const settings of [{origin:'https://evil.example'},{rpID:'evil.example'},{noUV:true},{badSignature:true},{badChallenge:true}]){
  const {options:o}=await(await h.call('unlock_begin')).json();const response=await h.authentication(settings.badChallenge?'wrongChallenge':o.challenge,settings);assert.equal((await h.call('unlock_finish',{credential:response})).status,403);
 }
 const {options:o}=await(await h.call('unlock_begin')).json();const valid=await h.authentication(o.challenge);const unlocked=await h.call('unlock_finish',{credential:valid});assert.equal(unlocked.status,200,JSON.stringify(await unlocked.clone().json()));
 assert.equal((await h.call('unlock_finish',{credential:valid})).status,409);
 h.revoke();assert.equal((await h.call('status')).status,403);assert.equal((await h.call('unlock_begin')).status,403);
});
