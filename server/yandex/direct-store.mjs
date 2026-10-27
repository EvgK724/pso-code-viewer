// Native YDB port of direct-schema.sql. All authorization and recipient roster
// reads are repeated in the same serializable transaction as the mutation.
// Large encrypted photos live separately from metadata and queue indices.
import { randomUUID } from 'node:crypto';
import { acceptTeamRequest, isAdmin, teamMembers, validId, validNonce, validHash, validName } from './team-store.mjs';
import { deletePushSubscriptionTx } from './push-store.mjs';
import { revokeDeviceAuthTx } from './device-auth-store.mjs';

const DAY = 86400000, OPS = new Set(['create','inbox','outbox','open','ack','retry','admin_members','admin_update','admin_replace','directory','admin_certify']);
// 32 candidates bound the worst case below the adapter's 512-operation cap:
// current membership/subscription reads plus three queue index updates each.
const PUSH_SCAN_LIMIT = 32, PUSH_SKIP_BACKOFF = 30000;
const EDIT_ROLES = new Set(['neurologist','cardiologist','intensivist','bot']);
const cmp = (a,b) => a < b ? -1 : a > b ? 1 : 0;
const bytes = x => Buffer.byteLength(JSON.stringify(x),'utf8');
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const memberKey = id => `member:${id}`;
const roleFor = group => group === 'cardiology' ? 'cardiologist' : 'intensivist';
const HUMAN_ROLES = new Set(['admin','neurologist','cardiologist','intensivist']);
const senderAllowed = (m,kind) => m?.state === 'active' && (kind === 'reply' ? HUMAN_ROLES.has(m.role) : kind === 'admission' ? m.role === 'bot' : kind === 'review' && ['admin','neurologist'].includes(m.role));
// Replies are private to one original sender. A later role change must not
// turn an old reply entry into access under another role.
const recipientAllowed = (actor,m,e) => actor?.state === 'active' && !!e && (m.kind === 'reply' ? HUMAN_ROLES.has(actor.role) && e.recipient_role === actor.role : actor.role === roleFor(m.group_name));
const padded = n => String(n).padStart(16,'0');
// Fixed-width ASCII inverse preserves SQL ORDER BY issued DESC,id DESC.
const inverse = text => [...text].map(c => (127-c.charCodeAt(0)).toString(16).padStart(2,'0')).join('');
const newest = (issued,id) => `${String(9999999999999999n-BigInt(issued)).padStart(16,'0')}:${inverse(id)}`;
const entryKey = (id,recipient) => `directentry:${id}:${recipient}`;
const messageKey = id => `directmsg:${id}`;
const status = value => ({status:value});

async function scanAll(tx,prefix) {
  const result = []; let after;
  for (;;) {
    const page = await tx.scan(prefix,{limit:1000,...(after ? {after} : {})});
    result.push(...page);
    if (page.length < 1000) return result;
    after = page.at(-1).key;
  }
}

async function approved(tx,m,at) {
  if (m?.state !== 'active') return false;
  if (m.role === 'admin') return true;
  const g = m.approval_proof?.grant;
  return !!g && g.subjectId === m.device_id && g.name === m.name && g.role === m.role &&
    Number.isSafeInteger(g.expires) && g.expires > at && await isAdmin(tx,g.issuerId);
}

function boundProof(proof,admin,id,name,role,at) {
  const g = proof?.grant;
  // HTTP verifies the signature; repeat binding and expiry at commit time.
  return object(proof) && object(g) && g.subjectId === id && g.issuerId === admin &&
    g.name === name && g.role === role && Number.isSafeInteger(g.expires) && g.expires > at && bytes(proof) <= 8000;
}

function queueKeys(m,e) {
  const tail = `${padded(Math.max(e.next_attempt,e.lease_until))}:${padded(m.issued)}:${m.id}:${e.recipient_id}`;
  return [`directpush:all:${tail}`,`directpush:sender:${m.sender_id}:${tail}`,`directpush:message:${m.id}:${tail}`];
}

async function removeQueue(tx,m,e) { for (const key of queueKeys(m,e)) await tx.delete(key); }
async function removeQueueRow(tx,prefix,row) {
  // Clean only the observed index generation, never a newer active lease.
  const tail = row.key.slice(prefix.length), value = row.value;
  for (const key of [`directpush:all:${tail}`,`directpush:sender:${value.sender_id}:${tail}`,`directpush:message:${value.message_id}:${tail}`]) await tx.delete(key);
}
async function putQueue(tx,m,e) {
  if (e.push_state === 'accepted' || e.push_attempts >= 8) return;
  const value = {message_id:m.id,recipient_id:e.recipient_id,sender_id:m.sender_id};
  for (const key of queueKeys(m,e)) await tx.put(key,value,m.expires);
}

async function audit(tx,at,actor,action,message=null,target=null) {
  await tx.put(`directaudit:${padded(at)}:${randomUUID()}`,{actor_id:actor,action,message_id:message,target_id:target,created_at:at},at+7*DAY);
}

const directoryMember = m => ({id:m.device_id,name:m.name,role:m.role,card:m.card,approvalProof:m.approval_proof ?? null});
const adminMember = m => ({...directoryMember(m),state:m.state,createdAt:m.created_at,approvedAt:m.approved_at ?? null,revokedAt:m.revoked_at ?? null});

async function clearDeviceAccess(tx,id) {
  await deletePushSubscriptionTx(tx,id);
  await revokeDeviceAuthTx(tx,id);
}

export function createDirectStore(db,{now=Date.now}={}) {
  if (typeof db?.transaction !== 'function' || typeof now !== 'function') throw new Error('Direct store configuration missing');
  const transaction = action => db.transaction(tx => {
    const at = now();
    if (!Number.isSafeInteger(at) || at <= 0) throw new Error('Clock unavailable');
    return action(tx,at);
  });
  return {
    accept(deviceId,nonce,op,issued,card,signingSpki) {
      return transaction(async (tx,at) => {
        if (!OPS.has(op) || !validId(deviceId)) return 'denied';
        const m = await tx.get(memberKey(deviceId));
        if (m?.state !== 'active' || m.signing_spki !== signingSpki) return 'denied';
        return acceptTeamRequest(tx,{deviceId,nonce,op:'status',issued,card,signingSpki},at);
      });
    },
    directory(deviceId) {
      return transaction(async tx => {
        if (!validId(deviceId) || (await tx.get(memberKey(deviceId)))?.state !== 'active') return status('denied');
        return {members:(await teamMembers(tx)).filter(m => m.state === 'active' && m.card != null)
          .sort((a,b) => cmp(a.role,b.role)||cmp(a.name,b.name)||cmp(a.device_id,b.device_id)).map(directoryMember)};
      });
    },
    members(adminId) {
      return transaction(async tx => {
        if (!await isAdmin(tx,adminId)) return status('denied');
        return {members:(await teamMembers(tx)).sort((a,b) => cmp(a.state,b.state)||cmp(a.name,b.name)||cmp(a.device_id,b.device_id)).map(adminMember)};
      });
    },
    certify(adminId,deviceId,proof) {
      return transaction(async (tx,at) => {
        if (!await isAdmin(tx,adminId) || !validId(deviceId)) return status('denied');
        const m = await tx.get(memberKey(deviceId));
        if (m?.state !== 'active' || m.role === 'admin') return status('denied');
        if (!boundProof(proof,adminId,deviceId,m.name,m.role,at)) return status('invalid');
        await tx.put(memberKey(deviceId),{...m,approval_proof:proof});
        await audit(tx,at,adminId,'certified',null,deviceId);
        return {state:'active'};
      });
    },
    create(senderId,requestHash,data) {
      return transaction(async (tx,at) => {
        if (!validId(senderId) || !validHash(requestHash) || !object(data) || !validNonce(data.id) ||
            !['cardiology','orit'].includes(data.group) || !['admission','review','reply'].includes(data.kind) ||
            !Number.isSafeInteger(data.issued) || !Number.isSafeInteger(data.expires) || data.issued <= 0 ||
            data.expires <= data.issued || data.expires-data.issued > DAY || !Array.isArray(data.entries) ||
            data.entries.length < 1 || data.entries.length > 25 || bytes(data) > 2050000) return 'invalid';
        if (data.kind === 'reply' ? !validNonce(data.replyTo) || data.replyTo === data.id || !object(data.payload) || data.payload.replyTo !== data.replyTo : Object.hasOwn(data,'replyTo')) return 'invalid';
        const sender = await tx.get(memberKey(senderId));
        if (!senderAllowed(sender,data.kind) || !await approved(tx,sender,at)) return 'denied';
        if (data.expires <= at || data.issued > at+30000) return 'invalid';
        const old = await tx.get(messageKey(data.id));
        if (old) return old.sender_id === senderId && old.request_hash === requestHash ? 'exists' : 'conflict';
        let recipients;
        if (data.kind === 'reply') {
          const parent = await tx.get(messageKey(data.replyTo));
          if (!parent || parent.expires <= at) return 'missing';
          const originalEntry = await tx.get(entryKey(parent.id,senderId));
          if (parent.group_name !== data.group || !recipientAllowed(sender,parent,originalEntry)) return 'denied';
          const recipient = await tx.get(memberKey(parent.sender_id));
          if (parent.sender_id === senderId || !senderAllowed(recipient,'reply')) return 'denied';
          recipients = [recipient];
        } else {
          recipients = (await teamMembers(tx)).filter(m => m.state === 'active' && m.role === roleFor(data.group))
            .sort((a,b) => cmp(a.device_id,b.device_id));
        }
        const entries = [...data.entries].sort((a,b) => cmp(a?.recipientId,b?.recipientId));
        if (!recipients.length || JSON.stringify(entries.map(e => e?.recipientId)) !== JSON.stringify(recipients.map(m => m.device_id))) return 'roster_changed';
        for (const m of recipients) if (!await approved(tx,m,at)) return 'denied';
        for (const e of entries) {
          if (!object(e) || !validId(e.recipientId) || typeof e.token !== 'string' || Buffer.byteLength(e.token,'utf8') > 1000) return 'invalid';
          const parts = e.token.split('.');
          if (!['PSO1','PSO2'].includes(parts[0]) || parts[1] !== e.recipientId || parts[2] !== senderId || parts.some(s => !s || !/^[A-Za-z0-9_-]+$/.test(s))) return 'invalid';
        }
        const hasPayload = Object.hasOwn(data,'payload');
        const payloadBytes = hasPayload ? bytes(data.payload) : 0;
        if (hasPayload && (!object(data.payload) || payloadBytes > 2000000)) return 'invalid';
        // Tiny quota records are retained independently of ciphertext TTL, so
        // expiring messages cannot bypass the rolling daily send/photo caps.
        const ownQuota = (await scanAll(tx,`directquota:sender:${senderId}:`)).map(r => r.value).filter(q => q.created_at > at-DAY);
        if (ownQuota.length >= 500 || (hasPayload && ownQuota.filter(q => q.payload_bytes > 0).length >= 30)) return 'limited';
        const globalQuota = (await scanAll(tx,'directquota:all:')).map(r => r.value);
        if (globalQuota.filter(q => q.created_at > at-DAY).length >= 5000 ||
            (hasPayload && globalQuota.filter(q => q.expires > at).reduce((s,q) => s+q.payload_bytes,0)+payloadBytes > 250000000)) return 'limited';
        const m = {id:data.id,request_hash:requestHash,sender_id:senderId,group_name:data.group,kind:data.kind,issued:data.issued,
          expires:data.expires,created_at:at,has_payload:hasPayload,recipient_count:entries.length,opened_count:0,...(data.kind === 'reply' ? {reply_to:data.replyTo} : {})};
        await tx.put(messageKey(m.id),m,m.expires);
        if (hasPayload) await tx.put(`directpayload:${m.id}`,data.payload,m.expires);
        await tx.put(`directout:${senderId}:${newest(m.issued,m.id)}`,{message_id:m.id},m.expires);
        for (const item of entries) {
          const e = {message_id:m.id,recipient_id:item.recipientId,token:item.token,opened_at:null,push_state:'queued',push_attempts:0,lease_until:0,next_attempt:0,endpoint_hash:null,...(data.kind === 'reply' ? {recipient_role:recipients[0].role} : {})};
          await tx.put(entryKey(m.id,e.recipient_id),e,m.expires);
          await tx.put(`directin:${e.recipient_id}:${newest(m.issued,m.id)}`,{message_id:m.id,group_name:m.group_name},m.expires);
          await putQueue(tx,m,e);
        }
        const quota = {created_at:at,expires:m.expires,payload_bytes:payloadBytes}, quotaTTL = Math.max(at+DAY,m.expires);
        await tx.put(`directquota:all:${padded(at)}:${m.id}`,quota,quotaTTL);
        await tx.put(`directquota:sender:${senderId}:${padded(at)}:${m.id}`,quota,quotaTTL);
        await audit(tx,at,senderId,'created',m.id);
        return 'created';
      });
    },
    list(deviceId,outbox,cursor=null) {
      return transaction(async (tx,at) => {
        const actor = validId(deviceId) ? await tx.get(memberKey(deviceId)) : null;
        if (actor?.state !== 'active') return status('denied');
        if (cursor !== null && (!object(cursor) || !validNonce(cursor.id) || !Number.isSafeInteger(cursor.issued) || cursor.issued <= 0)) return status('invalid');
        const prefix = `${outbox ? 'directout' : 'directin'}:${deviceId}:`, items = [], senderCache = new Map();
        let after = cursor ? `${prefix}${newest(cursor.issued,cursor.id)}` : null;
        for (;;) {
          const page = await tx.scan(prefix,{limit:100,...(after ? {after} : {})});
          for (const row of page) {
            const m = await tx.get(messageKey(row.value.message_id));
            if (!m || m.expires <= at || (outbox && m.sender_id !== deviceId)) continue;
            const e = await tx.get(entryKey(m.id,deviceId));
            if (!outbox && !recipientAllowed(actor,m,e)) continue;
            if (!senderCache.has(m.sender_id)) senderCache.set(m.sender_id,await tx.get(memberKey(m.sender_id)));
            const sender = senderCache.get(m.sender_id);
            if (!sender) continue;
            items.push({id:m.id,group:m.group_name,kind:m.kind,issued:m.issued,expires:m.expires,senderId:m.sender_id,senderName:sender.name,
              openedAt:e?.opened_at ?? null,recipientCount:m.recipient_count,openedCount:m.opened_count});
            if (items.length === 51) break;
          }
          if (items.length === 51 || page.length < 100) break;
          after = page.at(-1).key;
        }
        const more = items.length > 50;
        if (more) items.pop();
        return {items,next:more ? {id:items.at(-1).id,issued:items.at(-1).issued} : null};
      });
    },
    open(deviceId,id,ack=false) {
      return transaction(async (tx,at) => {
        const actor = validId(deviceId) ? await tx.get(memberKey(deviceId)) : null;
        if (actor?.state !== 'active') return status('denied');
        const m = validNonce(id) ? await tx.get(messageKey(id)) : null;
        if (!m || m.expires <= at) return status('missing');
        const e = await tx.get(entryKey(id,deviceId));
        if (!recipientAllowed(actor,m,e)) return status('denied');
        if (ack) {
          if (e.opened_at == null) {
            await tx.put(entryKey(id,deviceId),{...e,opened_at:at},m.expires);
            await tx.put(messageKey(id),{...m,opened_count:m.opened_count+1},m.expires);
            await audit(tx,at,deviceId,'opened',id);
          }
          return {openedAt:e.opened_at ?? at};
        }
        const sender = await tx.get(memberKey(m.sender_id));
        if (!sender?.card) return status('denied');
        const payload = m.has_payload ? await tx.get(`directpayload:${id}`) : null;
        if (m.has_payload && !payload) return status('missing');
        await audit(tx,at,deviceId,'retrieved',id);
        return {meta:{id,group:m.group_name,kind:m.kind,issued:m.issued,expires:m.expires,...(m.kind === 'reply' ? {replyTo:m.reply_to} : {})},payload,senderApprovalProof:sender.approval_proof ?? null,
          senderCard:sender.card,senderName:sender.name,senderRole:sender.role,token:e.token};
      });
    },
    update(adminId,deviceId,name,role,state,proof=null) {
      return transaction(async (tx,at) => {
        if (!await isAdmin(tx,adminId) || !validId(deviceId) || adminId === deviceId) return status('denied');
        const m = await tx.get(memberKey(deviceId));
        if (m?.state !== 'active' || m.role === 'admin') return status('denied');
        if (!validName(name) || !EDIT_ROLES.has(role) || !['active','revoked'].includes(state)) return status('invalid');
        if (state === 'active') {
          if (!boundProof(proof,adminId,deviceId,name,role,at)) return status('invalid');
          const others = (await teamMembers(tx)).filter(x => x.device_id !== deviceId && x.state === 'active' && x.role === role);
          if ((role === 'cardiologist' && others.length > 0) || (['bot','intensivist'].includes(role) && others.length >= 25)) return status('conflict');
        }
        await tx.put(memberKey(deviceId),{...m,name,role,state,approval_proof:state === 'active' ? proof : null,revoked_at:state === 'revoked' ? at : m.revoked_at ?? null});
        if (state === 'revoked') await clearDeviceAccess(tx,deviceId);
        await audit(tx,at,adminId,state === 'revoked' ? 'revoked' : 'updated',null,deviceId);
        return {state};
      });
    },
    replace(adminId,oldId,newId,proof) {
      return transaction(async (tx,at) => {
        if (!await isAdmin(tx,adminId) || !validId(oldId) || !validId(newId) || oldId === newId || oldId === adminId) return status('denied');
        const old = await tx.get(memberKey(oldId)), next = await tx.get(memberKey(newId));
        if (!old || old.role === 'admin' || !['active','revoked'].includes(old.state) || next?.state !== 'pending' || next.role === 'admin') return status('denied');
        if (!boundProof(proof,adminId,newId,old.name,old.role,at)) return status('invalid');
        const others = (await teamMembers(tx)).filter(m => m.device_id !== oldId && m.state === 'active' && m.role === old.role);
        if ((old.role === 'cardiologist' && others.length > 0) || (['bot','intensivist'].includes(old.role) && others.length >= 25)) return status('conflict');
        await tx.put(memberKey(oldId),{...old,state:'revoked',approval_proof:null,revoked_at:old.revoked_at ?? at});
        await clearDeviceAccess(tx,oldId);
        await tx.put(memberKey(newId),{...next,state:'active',name:old.name,role:old.role,approval_proof:proof,approved_at:at});
        await audit(tx,at,adminId,'replaced_old',null,oldId);
        await audit(tx,at,adminId,'replaced_new',null,newId);
        return {state:'active'};
      });
    },
    pushClaim(actorId,id=null) {
      return transaction(async (tx,at) => {
        const actor = validId(actorId) ? await tx.get(memberKey(actorId)) : null;
        if (actor?.state !== 'active') return status('denied');
        if (id !== null && !validNonce(id)) return status('invalid');
        const canAll = ['bot','admin'].includes(actor.role);
        const prefix = id ? `directpush:message:${id}:` : canAll ? 'directpush:all:' : `directpush:sender:${actorId}:`;
        const targets = []; let after, examined=0;
        for (;;) {
          const pageSize=Math.min(100,PUSH_SCAN_LIMIT-examined);
          if(pageSize<=0)break;
          const page = await tx.scan(prefix,{limit:pageSize,...(after ? {after} : {})});
          let future = false;
          for (const row of page) {
            if (Number(row.key.slice(prefix.length,prefix.length+16)) > at) { future=true; break; }
            examined++;
            const m = await tx.get(messageKey(row.value.message_id));
            if (!m || m.expires <= at) { await removeQueueRow(tx,prefix,row); continue; }
            // A message-filtered request by another doctor must never mutate
            // the real sender's queue or postpone their notifications.
            if (!canAll && m.sender_id !== actorId) continue;
            const e = await tx.get(entryKey(m.id,row.value.recipient_id));
            if (!e || e.push_state === 'accepted' || e.push_attempts >= 8 || e.lease_until > at || e.next_attempt > at) {
              await removeQueueRow(tx,prefix,row); continue;
            }
            const recipient = await tx.get(memberKey(e.recipient_id)), sender = await tx.get(memberKey(m.sender_id));
            const eligible = recipientAllowed(recipient,m,e) && senderAllowed(sender,m.kind);
            const sub = eligible ? await tx.get(`pushsub:${e.recipient_id}`) : null;
            if (!eligible || !sub || sub.refreshed_at < at-90*DAY) {
              // Bounded scans must make durable progress past devices without
              // subscriptions. Keep the message and attempt budget intact; a
              // later activation/subscription becomes eligible after 30 sec.
              await removeQueue(tx,m,e);
              const deferred={...e,next_attempt:at+PUSH_SKIP_BACKOFF};
              await tx.put(entryKey(m.id,e.recipient_id),deferred,m.expires);
              await putQueue(tx,m,deferred);
              continue;
            }
            const claimed = {...e,push_state:'sending',push_attempts:e.push_attempts+1,lease_until:at+60000,endpoint_hash:sub.endpoint_hash};
            await removeQueue(tx,m,e);
            await tx.put(entryKey(m.id,e.recipient_id),claimed,m.expires);
            await putQueue(tx,m,claimed);
            targets.push({id:m.id,recipientId:e.recipient_id,expires:m.expires,subscription:sub.subscription,lease:claimed.push_attempts});
            if (targets.length === 20) break;
          }
          if (targets.length === 20 || future || examined >= PUSH_SCAN_LIMIT || page.length < pageSize) break;
          after = page.at(-1).key;
        }
        return {targets};
      });
    },
    pushFinish(id,recipientId,lease,deliveryStatus) {
      return transaction(async (tx,at) => {
        if (!validNonce(id) || !validId(recipientId) || !Number.isSafeInteger(lease) || lease < 1 || !['accepted','gone','failed'].includes(deliveryStatus)) return 'invalid';
        const m = await tx.get(messageKey(id)), e = await tx.get(entryKey(id,recipientId));
        if (!m || m.expires <= at || !e || e.push_state !== 'sending' || e.push_attempts !== lease) return 'stale';
        await removeQueue(tx,m,e);
        const finished = {...e,push_state:deliveryStatus,lease_until:0,next_attempt:at+Math.min(3600000,30000*2**Math.min(e.push_attempts,6))};
        await tx.put(entryKey(id,recipientId),finished,m.expires);
        await putQueue(tx,m,finished);
        if (deliveryStatus === 'gone') {
          await deletePushSubscriptionTx(tx,recipientId,e.endpoint_hash);
        }
        return 'ok';
      });
    },
  };
}
