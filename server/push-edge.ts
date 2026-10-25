// Dedicated notification endpoint: signed device requests, no browser API secrets.
import {createPushHandler} from './push-handler.mjs';
const projectURL=Deno.env.get('SUPABASE_URL');
const key=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
if(!projectURL||!key)throw new Error('Push service is not configured.');
const rpcBase=new URL('/rest/v1/rpc/',projectURL);
if(rpcBase.protocol!=='https:')throw new Error('HTTPS required.');
async function rpc(name:string,body:Record<string,unknown>={}) {
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),8000);
  try {
    const response=await fetch(new URL(name,rpcBase),{method:'POST',headers:{'Content-Type':'application/json','apikey':key!,'Authorization':'Bearer '+key!},body:JSON.stringify(body),signal:controller.signal,redirect:'error',cache:'no-store'});
    if(!response.ok)throw new Error('Push storage unavailable.');
    return await response.json();
  } finally {clearTimeout(timer);}
}
const store={
  keys:(candidate:unknown)=>rpc('pso_push_keys',{p_candidate:candidate}),
  accept:(id:string,nonce:string,op:string,issued:number)=>rpc('pso_push_accept',{p_device_id:id,p_nonce:nonce,p_op:op,p_issued:issued}),
  register:(id:string,subscription:unknown,senders:string[])=>rpc('pso_push_register',{p_device_id:id,p_subscription:subscription,p_senders:senders}),
  unregister:(id:string)=>rpc('pso_push_unregister',{p_device_id:id}),
  status:(id:string)=>rpc('pso_push_status',{p_device_id:id}),
  testSubscription:(id:string)=>rpc('pso_push_test_subscription',{p_device_id:id}),
  claim:(id:string,hash:string)=>rpc('pso_push_claim',{p_sender_id:id,p_id_hash:hash}),
  finish:(hash:string,status:string)=>rpc('pso_push_finish',{p_id_hash:hash,p_status:status})
};
// JWT verification is disabled only because requests are authenticated here
// using the existing device signature. Anonymous clients have no database grants.
Deno.serve(createPushHandler({store,allowedOrigin:Deno.env.get('PSO_VIEWER_ORIGIN')||'https://evgk724.github.io'}));
