// pso-team: custom device signatures and server-enforced roles; no browser secrets.
import {createTeamHandler} from './team-handler.mjs';
const projectURL=Deno.env.get('SUPABASE_URL');
const key=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
if(!projectURL||!key)throw new Error('Team service is not configured');
const rpcBase=new URL('/rest/v1/rpc/',projectURL);
if(rpcBase.protocol!=='https:')throw new Error('HTTPS required');
async function rpc(name:string,body:Record<string,unknown>={}) {
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),8000);
  try {
    const response=await fetch(new URL(name,rpcBase),{method:'POST',headers:{'Content-Type':'application/json','apikey':key!,'Authorization':'Bearer '+key!},body:JSON.stringify(body),signal:controller.signal,redirect:'error',cache:'no-store'});
    if(!response.ok)throw new Error('Team storage unavailable');
    return await response.json();
  } finally {clearTimeout(timer);}
}
const store={
  accept:(id:string,nonce:string,op:string,issued:number,card:string,spki:string)=>rpc('pso_team_accept',{p_device_id:id,p_nonce:nonce,p_op:op,p_issued:issued,p_card:card,p_signing_spki:spki}),
  status:(id:string)=>rpc('pso_team_status',{p_device_id:id}),
  directory:(id:string)=>rpc('pso_team_directory',{p_device_id:id}),
  invite:(id:string,hash:string,name:string,role:string)=>rpc('pso_team_invite',{p_admin_id:id,p_id_hash:hash,p_name:name,p_role:role}),
  claim:(id:string,hash:string,card:string,spki:string)=>rpc('pso_team_claim',{p_device_id:id,p_id_hash:hash,p_card:card,p_signing_spki:spki}),
  pending:(id:string)=>rpc('pso_team_pending',{p_admin_id:id}),
  approve:(id:string,target:string)=>rpc('pso_team_approve',{p_admin_id:id,p_device_id:target}),
  revoke:(id:string,target:string)=>rpc('pso_team_revoke',{p_admin_id:id,p_device_id:target}),
  create:(id:string,hash:string,requestHash:string,group:string,kind:string,issued:number,expires:number,entries:unknown)=>rpc('pso_team_create',{p_sender_id:id,p_id_hash:hash,p_request_hash:requestHash,p_group:group,p_kind:kind,p_issued:issued,p_expires:expires,p_entries:entries}),
  resolve:(id:string,hash:string)=>rpc('pso_team_resolve',{p_device_id:id,p_id_hash:hash}),
  pushClaim:(id:string,hash:string)=>rpc('pso_team_push_claim',{p_sender_id:id,p_id_hash:hash}),
  pushFinish:(hash:string,recipient:string,status:string)=>rpc('pso_team_push_finish',{p_id_hash:hash,p_recipient_id:recipient,p_status:status}),
  keys:(candidate:unknown)=>rpc('pso_push_keys',{p_candidate:candidate})
};
// Gateway JWT verification is disabled only for this function. Every operation
// authenticates its existing device key before touching role-controlled RPCs.
Deno.serve(createTeamHandler({store,allowedOrigin:'https://evgk724.github.io'}));
