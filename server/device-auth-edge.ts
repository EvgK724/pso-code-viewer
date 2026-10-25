// Pin the audited WebAuthn implementation; no custom FIDO signature/CBOR parser.
import * as webauthn from 'npm:@simplewebauthn/server@14.0.3';
import {createDeviceAuthHandler} from './device-auth-handler.mjs';
const url=Deno.env.get('SUPABASE_URL'),key=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
const allowedOrigin=Deno.env.get('PSO_VIEWER_ORIGIN')||'https://evgk724.github.io';
if(!url||!key)throw new Error('Device verification is not configured');
const base=new URL('/rest/v1/rpc/',url);if(base.protocol!=='https:')throw new Error('HTTPS required');
async function rpc(name:string,body:Record<string,unknown>){
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),8000);
 try{const r=await fetch(new URL(name,base),{method:'POST',headers:{'Content-Type':'application/json','apikey':key!,'Authorization':'Bearer '+key!},body:JSON.stringify(body),signal:controller.signal,redirect:'error',cache:'no-store'});if(!r.ok)throw new Error('Device verification unavailable');return await r.json();}finally{clearTimeout(timer);}
}
const store={
 accept:(id:string,nonce:string,issued:number,card:string,spki:string)=>rpc('pso_device_auth_accept',{p_device_id:id,p_nonce:nonce,p_issued:issued,p_card:card,p_signing_spki:spki}),
 status:(id:string)=>rpc('pso_device_auth_status',{p_device_id:id}),
 credential:(id:string)=>rpc('pso_device_auth_credential',{p_device_id:id}),
 challengePut:(id:string,purpose:string,challenge:string,expires:number)=>rpc('pso_device_auth_challenge_put',{p_device_id:id,p_purpose:purpose,p_challenge:challenge,p_expires:expires}),
 challengeTake:(id:string,purpose:string)=>rpc('pso_device_auth_challenge_take',{p_device_id:id,p_purpose:purpose}),
 enroll:(id:string,credential:unknown,hash:string,expires:number)=>rpc('pso_device_auth_enroll',{p_device_id:id,p_credential:credential,p_token_hash:hash,p_expires:expires}),
 unlock:(id:string,credentialId:string,oldCounter:number,newCounter:number,hash:string,expires:number)=>rpc('pso_device_auth_unlock',{p_device_id:id,p_credential_id:credentialId,p_old_counter:oldCounter,p_new_counter:newCounter,p_token_hash:hash,p_expires:expires}),
 reset:(adminId:string,id:string,token:string)=>rpc('pso_device_unlock_reset',{p_admin_id:adminId,p_device_id:id,p_token:token})
};
Deno.serve(createDeviceAuthHandler({store,webauthn,allowedOrigin}));
