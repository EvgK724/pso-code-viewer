// Device signatures authenticate each request; no patient plaintext or browser secret.
import {createDirectHandler} from './direct-handler.mjs';
const projectURL=Deno.env.get('SUPABASE_URL');
const key=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
if(!projectURL||!key)throw new Error('Direct service is not configured');
const rpcBase=new URL('/rest/v1/rpc/',projectURL);
if(rpcBase.protocol!=='https:')throw new Error('HTTPS required');
async function rpc(name:string,body:Record<string,unknown>={}){
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),12000);
 try{const r=await fetch(new URL(name,rpcBase),{method:'POST',headers:{'Content-Type':'application/json','apikey':key!,'Authorization':'Bearer '+key!},body:JSON.stringify(body),signal:controller.signal,redirect:'error',cache:'no-store'});if(!r.ok)throw new Error('Direct storage unavailable');return await r.json();}finally{clearTimeout(timer);}
}
const store={
 accept:(id:string,nonce:string,op:string,issued:number,card:string,spki:string)=>rpc('pso_direct_accept',{p_device_id:id,p_nonce:nonce,p_op:op,p_issued:issued,p_card:card,p_signing_spki:spki}),
 create:(id:string,hash:string,data:unknown)=>rpc('pso_direct_create',{p_sender_id:id,p_request_hash:hash,p_data:data}),
 list:(id:string,outbox:boolean,cursor:unknown)=>rpc('pso_direct_list',{p_device_id:id,p_outbox:outbox,p_cursor:cursor}),
 open:(id:string,message:string,ack:boolean)=>rpc('pso_direct_open',{p_device_id:id,p_id:message,p_ack:ack}),
 members:(id:string)=>rpc('pso_direct_members',{p_admin_id:id}),
 update:(id:string,target:string,name:string,role:string,state:string,proof:unknown)=>rpc('pso_direct_update',{p_admin_id:id,p_id:target,p_name:name,p_role:role,p_state:state,p_proof:proof}),
 replace:(id:string,oldId:string,newId:string,proof:unknown)=>rpc('pso_direct_replace',{p_admin_id:id,p_old_id:oldId,p_new_id:newId,p_proof:proof}),
 pushClaim:(id:string,message:string|null)=>rpc('pso_direct_push_claim',{p_actor_id:id,p_message_id:message}),
 pushFinish:(id:string,recipient:string,lease:number,status:string)=>rpc('pso_direct_push_finish',{p_id:id,p_recipient_id:recipient,p_lease:lease,p_status:status}),
 directory:(id:string)=>rpc('pso_direct_directory',{p_device_id:id}),
 certify:(id:string,target:string,proof:unknown)=>rpc('pso_direct_certify',{p_admin_id:id,p_id:target,p_proof:proof}),
 keys:(candidate:unknown)=>rpc('pso_push_keys',{p_candidate:candidate}),
 unlockCheck:(id:string,token:string)=>rpc('pso_device_unlock_check',{p_device_id:id,p_token:token})
};
Deno.serve(createDirectHandler({store,allowedOrigin:Deno.env.get('PSO_VIEWER_ORIGIN')||Deno.env.get('PSO_ALLOWED_ORIGIN')||'https://evgk724.github.io'}));
