import test from 'node:test';
import assert from 'node:assert/strict';
import {makeDevice} from '../docs/crypto.mjs';
import {deviceIdentity} from '../docs/exchange.mjs';
import {deviceAuthEnvelope} from '../docs/device-unlock.mjs';
import {createDeviceAuthHandler} from './device-auth-handler.mjs';
const origin='https://viewer.example',at=1800000000000;
const device=await makeDevice(),other=await makeDevice(),id=(await deviceIdentity(device)).id;
const b64=n=>Buffer.alloc(n,3).toString('base64url');
function setup(){
 const state={enabled:false,revoked:false,challenge:null,consumed:0,counter:0,calls:0};
 const store={accept:async(id,n,issued,card,spki)=>state.revoked?'denied':'ok',status:async()=>({enabled:state.enabled}),credential:async()=>state.enabled?{id:b64(32),publicKey:b64(77),counter:state.counter,transports:['internal']}:null,
 challengePut:async(id,p,c)=>{state.challenge=c;return'ok';},challengeTake:async()=>{const c=state.challenge;state.challenge=null;state.consumed++;return c;},
 enroll:async(id,c,hash,expires)=>{state.enabled=true;state.calls++;return'ok';},unlock:async(id,c,old,next)=>{state.counter=next;state.calls++;return'ok';},reset:async()=>{state.enabled=false;return'ok';}};
 const webauthn={generateRegistrationOptions:async options=>{assert.equal(options.authenticatorSelection.userVerification,'required');return{challenge:b64(32),...options};},generateAuthenticationOptions:async options=>{assert.equal(options.userVerification,'required');return{challenge:b64(32),...options};},verifyRegistrationResponse:async options=>{assert.equal(options.expectedRPID,'viewer.example');assert.equal(options.expectedOrigin,origin);assert.equal(options.requireUserVerification,true);if(options.response.bad)throw new Error('bad');return {verified:true,registrationInfo:{userVerified:!options.response.noUV,credential:{id:b64(32),publicKey:new Uint8Array(77),counter:0,transports:['internal']}}};},verifyAuthenticationResponse:async options=>{assert.equal(options.requireUserVerification,true);if(options.response.bad)throw new Error('bad');return{verified:true,authenticationInfo:{userVerified:true,newCounter:1}};}};
 const handler=createDeviceAuthHandler({store,webauthn,allowedOrigin:origin,now:()=>at});
 const call=async(op,data={},who=device,headers={})=>handler(new Request('https://api.example/auth',{method:'POST',headers:{'Content-Type':'application/json',Origin:origin,...headers},body:JSON.stringify({envelope:await deviceAuthEnvelope(who,op,data,at)})}));
 return{state,store,handler,call};
}
test('passkey enrollment requires UV and consumes challenge before verification',async()=>{
 const h=setup();assert.equal((await h.call('enroll_begin')).status,200);
 assert.equal((await h.call('enroll_finish',{credential:{noUV:true}})).status,403);assert.equal(h.state.enabled,false);assert.equal(h.state.consumed,1);
 assert.equal((await h.call('enroll_finish',{credential:{}})).status,409);
 await h.call('enroll_begin');const r=await h.call('enroll_finish',{credential:{}});assert.equal(r.status,200);const body=await r.json();assert.equal(body.expires,at+600000);assert.equal(Buffer.from(body.token,'base64url').length,32);
 assert.equal((await h.call('enroll_begin')).status,409,'enrollment cannot replace an existing passkey');
});
test('wrong origin, wrong signature, revoked device and malformed data never reach verifier',async()=>{
 const h=setup();assert.equal((await h.call('status',{},device,{Origin:'https://evil.example'})).status,403);
 const e=await deviceAuthEnvelope(device,'status',{},at);e.data={injected:true};assert.equal((await h.handler(new Request('https://api.example/auth',{method:'POST',headers:{'Content-Type':'application/json',Origin:origin},body:JSON.stringify({envelope:e})}))).status,403);
 h.state.revoked=true;assert.equal((await h.call('status')).status,403);assert.equal(h.state.calls,0);
});
test('authentication validates credential ID and cannot replay consumed challenge',async()=>{
 const h=setup();h.state.enabled=true;
 await h.call('unlock_begin');assert.equal((await h.call('unlock_finish',{credential:{id:b64(33)}})).status,403);assert.equal(h.state.calls,0);
 assert.equal((await h.call('unlock_finish',{credential:{id:b64(32)}})).status,409);
 await h.call('unlock_begin');assert.equal((await h.call('unlock_finish',{credential:{id:b64(32)}})).status,200);assert.equal(h.state.counter,1);
 assert.equal((await h.call('unlock_finish',{credential:{id:b64(32)}})).status,409);
});
test('body and CORS are bounded and only exact operations accepted',async()=>{
 const h=setup();const req=(body,headers={})=>h.handler(new Request('https://api.example/auth',{method:'POST',headers:{'Content-Type':'application/json',Origin:origin,...headers},body}));
 assert.equal((await req('x'.repeat(131073))).status,413);assert.equal((await req('{}',{'Content-Type':'text/plain'})).status,415);
 assert.equal((await h.handler(new Request('https://api.example/auth',{method:'OPTIONS',headers:{Origin:origin,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'Content-Type'}}))).status,204);
 assert.equal((await h.call('status',{extra:true})).status,400);
});
