import {httpHandler,withDatabase} from './runtime.mjs';
import {runMaintenance} from './maintenance.mjs';
import {jsonReply} from './http.mjs';
export async function handler(event,context){
 // Defense in depth for gateway HTTP events. IAM private invocation policy is
 // still required: Cloud Functions raw integration can forward an unwrapped body.
 if(event && ['httpMethod','requestContext','rawPath','version','path','headers','body'].some(k=>Object.hasOwn(event,k)))return httpHandler(event,context);
 if(process.env.PSO_SETUP_MODE!=='on')return jsonReply(403,{error:'setup_disabled'});
 if(!context?.token?.access_token)return jsonReply(403,{error:'service_account_required'});
 try{
  const result=await withDatabase(context,db=>runMaintenance(db,event,{allowedOrigin:process.env.PSO_VIEWER_ORIGIN,organizerCard:process.env.PSO_ORGANIZER_CARD}));
  return jsonReply(result.ok?200:503,result);
 }catch(error){return jsonReply(503,{ok:false,code:typeof error?.code==='string'&&/^[a-z_]{1,60}$/.test(error.code)?error.code:'setup_failed',status:Number.isSafeInteger(error?.status)?error.status:null,message:'Настройка не выполнена. Проверьте действие, права pso-runtime и параметры подключения.'});}
}
