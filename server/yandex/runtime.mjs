import {createRequire} from 'node:module';
import {readFile} from 'node:fs/promises';
import {createYdbDatabase} from './ydb-database.mjs';
import {createTeamStore} from './team-store.mjs';
import {createDirectStore} from './direct-store.mjs';
import {createPushStore} from './push-store.mjs';
import {createDeviceAuthStore} from './device-auth-store.mjs';
import {createTeamHandler} from '../team-handler.mjs';
import {createDirectHandler} from '../direct-handler.mjs';
import {createPushHandler} from '../push-handler.mjs';
import {createDeviceAuthHandler} from '../device-auth-handler.mjs';
import {createHttpRouter,jsonReply,validateOrigin} from './http.mjs';
const require=createRequire(import.meta.url);
const sdk=require('ydb-sdk');
const silentLogger=Object.fromEntries(['trace','debug','info','warn','error','fatal'].map(k=>[k,()=>{}]));
export async function withDatabase(context,callback){
 const token=context?.token?.access_token;
 if(typeof token!=='string'||!token)throw new Error('Service account required');
 const config=JSON.parse(await readFile(new URL('../../connection.json',import.meta.url),'utf8'));
 const driver=new sdk.Driver({endpoint:config.endpoint,database:config.database,authService:new sdk.TokenAuthService(token),logger:silentLogger,poolSettings:{minLimit:1,maxLimit:2}});
 try{if(!await driver.ready(10000))throw new Error('Database unavailable');return await callback(createYdbDatabase({driver}));}
 finally{
  let timer;
  try{await Promise.race([driver.destroy().catch(()=>{}),new Promise(resolve=>{timer=setTimeout(resolve,1500);})]);}
  finally{clearTimeout(timer);}
 }
}
export function composeStores(db){
 const push=createPushStore(db),auth=createDeviceAuthStore(db);
 const team={...createTeamStore(db),keys:candidate=>push.keys(candidate)};
 const direct={...createDirectStore(db),keys:candidate=>push.keys(candidate),unlockCheck:(id,token)=>auth.unlockCheck(id,token)};
 return {team,direct,push,auth};
}
export async function httpHandler(event,context){
 try{
  if(process.env.PSO_SETUP_MODE!=='off')return jsonReply(503,{error:'setup_required'});
  const allowedOrigin=validateOrigin(process.env.PSO_VIEWER_ORIGIN);
  // Static shell requests need neither YDB nor a database session.
  if(!event?.path?.startsWith('/api/'))return createHttpRouter({allowedOrigin,handlers:{}})(event);
  return await withDatabase(context,async db=>{
   const pinned=await db.transaction(tx=>tx.get('config:organizer'));
   if(!pinned||pinned.origin!==allowedOrigin)return jsonReply(503,{error:'organizer_setup_required'});
   const webauthn=await import('@simplewebauthn/server'),{team,direct,push,auth}=composeStores(db);
   const handlers={
    'pso-team':createTeamHandler({store:team,allowedOrigin}),
    'pso-direct':createDirectHandler({store:direct,allowedOrigin}),
    'pso-push':createPushHandler({store:push,allowedOrigin}),
    'pso-device-auth':createDeviceAuthHandler({store:auth,webauthn,allowedOrigin})
   };
   return createHttpRouter({allowedOrigin,handlers})(event);
  });
 }catch{return jsonReply(503,{error:'service_unavailable'});}
}
