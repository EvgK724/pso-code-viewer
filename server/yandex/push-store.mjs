// Push envelopes never contain patient data. Endpoint credentials and VAPID
// private keys remain private server state and must not be logged or returned.
import {createHash} from 'node:crypto';
import {validId,validNonce,validHash} from './team-store.mjs';

const MINUTE = 60000, DAY = 86400000, SUB_TTL = 90*DAY;
const sha = value => createHash('sha256').update(value,'utf8').digest('hex');
const exact = (value,keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;
const jsonSize = value => Buffer.byteLength(JSON.stringify(value),'utf8');
const fresh = (row,at) => row && Number.isSafeInteger(row.refreshed_at) && row.refreshed_at >= at-SUB_TTL;
const validSubscription = sub => exact(sub,'endpoint,keys') && exact(sub.keys,'auth,p256dh') &&
  typeof sub.keys.p256dh === 'string' && /^B[A-Za-z0-9_-]{85}[AEIMQUYcgkosw048]$/.test(sub.keys.p256dh) &&
  validNonce(sub.keys.auth) && typeof sub.endpoint === 'string' && sub.endpoint.length <= 2048 &&
  /^https:\/\/(([a-z0-9-]+\.)+push\.apple\.com|fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com)\/[^\s#]+$/.test(sub.endpoint) && jsonSize(sub) <= 4096;

// The expected hash pins deletion to the endpoint actually used for an HTTP
// send. A replacement registered while a request was in flight must survive.
export async function deletePushSubscriptionTx(tx,id,expectedEndpointHash=null) {
  if (!validId(id)) return false;
  const key = `pushsub:${id}`, row = await tx.get(key);
  if (!row || (expectedEndpointHash !== null && row.endpoint_hash !== expectedEndpointHash)) return false;
  await tx.delete(key);
  const indexKey = `pushendpoint:${row.endpoint_hash}`;
  if ((await tx.get(indexKey))?.device_id === id) await tx.delete(indexKey);
  return true;
}

function validVapid(candidate) {
  const jwk = candidate?.privateKey;
  return exact(candidate,'privateKey,publicKey') && typeof candidate.publicKey === 'string' &&
    /^[A-Za-z0-9_-]{86}[AEIMQUYcgkosw048]$/.test(candidate.publicKey) &&
    jwk && typeof jwk === 'object' && !Array.isArray(jwk) && jwk.kty === 'EC' && jwk.crv === 'P-256' &&
    validId(jwk.x) && validId(jwk.y) && validId(jwk.d) && jsonSize(candidate) <= 2048;
}

export function createPushStore(db,{now=Date.now}={}) {
  if (typeof db?.transaction !== 'function' || typeof now !== 'function') throw new Error('Push store configuration missing');
  const transaction = action => db.transaction(tx => {
    const at = now();
    if (!Number.isSafeInteger(at) || at <= 0) throw new Error('Clock unavailable');
    return action(tx,at);
  });
  return {
    keys(candidate=null) {
      return transaction(async tx => {
        const existing = await tx.get('config:vapid');
        if (existing) return existing;
        if (candidate === null) return null;
        if (!validVapid(candidate)) throw new Error('Invalid VAPID configuration');
        await tx.put('config:vapid',candidate);
        return candidate;
      });
    },
    accept(id,nonce,op,issued) {
      return transaction(async (tx,at) => {
        if (!validId(id) || !validNonce(nonce) || !['register','unregister','status','test','notify'].includes(op) ||
            !Number.isSafeInteger(issued) || issued < at-MINUTE || issued > at+30000) return 'invalid';
        const nonceKey = `nonce:push:${id}:${nonce}`;
        if (await tx.get(nonceKey)) return 'replay';
        const specifications = [
          {subject:'global',period:'day',window:DAY,limit:10000},
          {subject:id,period:'minute',window:MINUTE,limit:20},
          {subject:id,period:'day',window:DAY,limit:500},
          ...(op === 'test' ? [{subject:id,period:'test-minute',window:MINUTE,limit:3}] : []),
        ];
        const updates = [];
        // No per-device writes occur before every cap, including global, passes.
        for (const specification of specifications) {
          const {subject,period,window,limit} = specification, bucket = Math.floor(at/window);
          const key = `quota:push:${period}:${subject}:${bucket}`, row = await tx.get(key), used = row?.used ?? 0;
          if (!Number.isSafeInteger(used) || used < 0) throw new Error('Invalid quota state');
          if (used >= limit) return 'limited';
          updates.push({key,value:{subject,period,bucket,used:used+1},expires:(bucket+1)*window+2*DAY});
        }
        for (const {key,value,expires} of updates) await tx.put(key,value,expires);
        await tx.put(nonceKey,{device_id:id,nonce,created_at:at},at+2*MINUTE);
        return 'ok';
      });
    },
    register(id,subscription,senders) {
      return transaction(async (tx,at) => {
        if (!validId(id) || !validSubscription(subscription) || !Array.isArray(senders) || senders.length > 100 || !senders.every(validId)) return 'conflict';
        const normalized = [...new Set([...senders,id])].sort();
        if (normalized.length > 100) return 'conflict';
        const hash = sha(subscription.endpoint), indexKey = `pushendpoint:${hash}`, endpointOwner = await tx.get(indexKey);
        if (endpointOwner && endpointOwner.device_id !== id) {
          const ownerSub = await tx.get(`pushsub:${endpointOwner.device_id}`);
          if (fresh(ownerSub,at) && ownerSub.endpoint_hash === hash) return 'conflict';
        }
        const previous = await tx.get(`pushsub:${id}`);
        if (!fresh(previous,at)) {
          let live = 0, after;
          for (;;) {
            const rows = await tx.scan('pushsub:',{limit:1000,...(after ? {after} : {})});
            for (const {value} of rows) if (fresh(value,at)) live++;
            if (live >= 500) return 'limited';
            if (rows.length < 1000) break;
            after = rows.at(-1).key;
          }
        }
        if (previous && previous.endpoint_hash !== hash) await deletePushSubscriptionTx(tx,id);
        await tx.put(`pushsub:${id}`,{device_id:id,endpoint_hash:hash,subscription,senders:normalized,refreshed_at:at},at+SUB_TTL);
        await tx.put(indexKey,{device_id:id,refreshed_at:at},at+SUB_TTL);
        return 'ok';
      });
    },
    unregister(id) {
      return transaction(async tx => { await deletePushSubscriptionTx(tx,id); return 'ok'; });
    },
    status(id) {
      return transaction(async (tx,at) => validId(id) && !!fresh(await tx.get(`pushsub:${id}`),at));
    },
    testSubscription(id) {
      return transaction(async (tx,at) => {
        const row = validId(id) ? await tx.get(`pushsub:${id}`) : null;
        return fresh(row,at) ? row.subscription : null;
      });
    },
    // Legacy short links are read-only on this new origin. No legacy records are
    // fabricated from team memberships: absent writer/link means unavailable.
    claim(senderId,idHash) {
      return transaction(async (tx,at) => {
        if (!validId(senderId) || !validHash(idHash)) return {status:'unavailable'};
        const writer = await tx.get(`legacywriter:${senderId}`);
        if (writer?.enabled !== true) return {status:'unavailable'};
        const link = await tx.get(`legacy:${idHash}`), parts = typeof link?.token === 'string' ? link.token.split('.') : [];
        if (!link || link.sender_id !== senderId || link.expires <= at || parts[2] !== senderId || !validId(parts[1])) return {status:'unavailable'};
        const key = `pushclaim:${idHash}`, old = await tx.get(key);
        if (old) return {status:old.status === 'sending' ? 'already' : old.status};
        const recipientId = parts[1], sub = await tx.get(`pushsub:${recipientId}`);
        if (!fresh(sub,at) || !sub.senders.includes(senderId)) return {status:'unavailable'};
        await tx.put(key,{id_hash:idHash,sender_id:senderId,recipient_id:recipientId,endpoint_hash:sub.endpoint_hash,status:'sending',created_at:at},at+2*DAY);
        return {status:'ready',subscription:sub.subscription,recipient_id:recipientId,expires:link.expires};
      });
    },
    finish(idHash,status) {
      return transaction(async tx => {
        if (!validHash(idHash) || !['accepted','gone','failed'].includes(status)) return 'invalid';
        const key = `pushclaim:${idHash}`, claim = await tx.get(key);
        if (claim?.status !== 'sending') return 'unchanged';
        await tx.put(key,{...claim,status},claim.created_at+2*DAY);
        if (status === 'gone') await deletePushSubscriptionTx(tx,claim.recipient_id,claim.endpoint_hash);
        return 'ok';
      });
    },
  };
}
