// Release notices are separate from encrypted patient messages. Only a signed
// release_status request may call status(); the direct handler authenticates it.
import {APP_RELEASE} from '../../docs/release-info.mjs';
import {memberRoles} from '../../docs/care-routing.mjs';
import {validId} from './team-store.mjs';
import {createPushStore,deletePushSubscriptionTx} from './push-store.mjs';
import {sendWebPush} from '../web-push.mjs';

const DAY=86400000,CLIENT_TTL=90*DAY,NOTICE_TTL=7*DAY,BATCH=5,SCAN=30;
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===k;
const validVersion=v=>Number.isSafeInteger(v)&&v>=1&&v<=1000000;
const human=row=>row?.state==='active'&&validId(row.device_id)&&memberRoles(row).length>0&&!memberRoles(row).includes('bot');
const fresh=(row,at)=>row&&Number.isSafeInteger(row.refreshed_at)&&row.refreshed_at>=at-CLIENT_TTL&&row.refreshed_at<=at+30000;
const noticeKey=(version,id)=>`release-notice:${version}:${id}`;

export function createReleaseNotifications(db,{now=Date.now,version=APP_RELEASE,keys,send=sendWebPush}={}) {
  if(typeof db?.transaction!=='function'||typeof now!=='function'||typeof send!=='function'||!validVersion(version))throw new Error('Release notification configuration missing');
  const getKeys=keys||(()=>createPushStore(db,{now}).keys());
  if(typeof getKeys!=='function')throw new Error('Release keys missing');
  async function claim(actor,at) {
    return db.transaction(async tx=>{
      // Recheck the caller inside the claim transaction. A revoked caller cannot
      // use a racing status request to initiate a team-wide notification.
      if(!human(await tx.get('member:'+actor)))return [];
      const dispatchKey=`release-dispatch:${version}`,previous=await tx.get(dispatchKey);
      if(previous?.checked_at>at-60000)return [];
      const rows=await tx.scan('release-client:',{limit:SCAN,...(previous?.after?{after:previous.after}:{})});
      const targets=[];let after=null,processed=0;
      for(const {key,value:client} of rows){
        after=key;processed++;
        if(!fresh(client,at)||client.notifications_version!==1||!validVersion(client.version)||client.version>=version||!validId(client.device_id))continue;
        const id=client.device_id,member=await tx.get('member:'+id);
        if(!human(member)||await tx.get(noticeKey(version,id)))continue;
        const sub=await tx.get('pushsub:'+id);
        if(!fresh(sub,at)||sub.device_id!==id||typeof sub.endpoint_hash!=='string'||!sub.subscription)continue;
        // At most one send attempt per release/device. Ambiguous push outcomes
        // are not retried: the next signed status check still shows the banner.
        await tx.put(noticeKey(version,id),{version,device_id:id,state:'sending',created_at:at,endpoint_hash:sub.endpoint_hash});
        targets.push({id,subscription:sub.subscription,endpointHash:sub.endpoint_hash});
        if(targets.length===BATCH)break;
      }
      // Rotate bounded scans so late subscribers are discovered. Completed
      // receipts persist across rotations and deployments of the same version.
      if(processed===rows.length&&rows.length<SCAN)after=null;
      await tx.put(dispatchKey,{checked_at:at,after},at+CLIENT_TTL);
      return targets;
    });
  }
  async function dispatch(actor,at) {
    // Do not consume a delivery receipt when push keys have not been configured.
    const vapid=await getKeys();if(!vapid)return;
    const targets=await claim(actor,at),expires=at+NOTICE_TTL;
    for(let offset=0;offset<targets.length;offset+=5){
      await Promise.all(targets.slice(offset,offset+5).map(async target=>{
        let state='failed';
        try{
          // A clinical role can be revoked while another recipient is sending.
          const allowed=await db.transaction(async tx=>{
            const member=await tx.get('member:'+target.id),sub=await tx.get('pushsub:'+target.id);
            return human(member)&&fresh(sub,now())&&sub.endpoint_hash===target.endpointHash;
          });
          if(allowed){
            const result=await send(target.subscription,vapid,{v:1,type:'release',version,expires},{now:at,ttl:NOTICE_TTL/1000,timeout:3000});
            if(['accepted','gone'].includes(result?.status))state=result.status;
          }else state='cancelled';
        }catch{/* Neither endpoints nor provider responses are exposed. */}
        try{await db.transaction(async tx=>{
          const key=noticeKey(version,target.id),receipt=await tx.get(key);
          if(receipt?.state!=='sending'||receipt.endpoint_hash!==target.endpointHash)return;
          await tx.put(key,{...receipt,state});
          if(state==='gone')await deletePushSubscriptionTx(tx,target.id,target.endpointHash);
        });}catch{/* Spent receipt remains final; in-app notice remains available. */}
      }));
    }
  }
  return {
    async status(actor,data){
      if(!validId(actor)||!exact(data,'clientVersion,notificationsVersion')||!validVersion(data.clientVersion)||![0,1].includes(data.notificationsVersion))return {status:'invalid'};
      const at=now();if(!Number.isSafeInteger(at)||at<=0)throw new Error('Clock unavailable');
      const result=await db.transaction(async tx=>{
        if(!human(await tx.get('member:'+actor)))return {status:'denied'};
        const previous=await tx.get('release-client:'+actor);
        // A suspended older tab must not downgrade an already updated client.
        const clientVersion=fresh(previous,at)&&validVersion(previous.version)?Math.max(previous.version,data.clientVersion):data.clientVersion;
        await tx.put('release-client:'+actor,{device_id:actor,version:clientVersion,notifications_version:data.notificationsVersion,refreshed_at:at},at+CLIENT_TTL);
        const updateAvailable=data.clientVersion<version;
        if(updateAvailable&&!await tx.get(noticeKey(version,actor)))await tx.put(noticeKey(version,actor),{version,device_id:actor,state:'shown',created_at:at});
        return {version,updateAvailable};
      });
      if(!result.status){try{await dispatch(actor,at);}catch{/* A broadcast cannot block the update notice. */}}
      return result;
    }
  };
}
