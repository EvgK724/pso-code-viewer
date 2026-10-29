// Native YDB port of direct-schema.sql. All authorization and recipient roster
// reads are repeated in the same serializable transaction as the mutation.
// Large encrypted photos live separately from metadata and queue indices.
import {INVITE_ROLES,GROUPS,memberRoles,hasRole,inRecipientGroup,roleGroup,isRehabGroup,isReplyKind,isGroupConversationKind,participatesInGroup,canSendGroup} from '../../docs/care-routing.mjs';
import { randomUUID } from 'node:crypto';
import { acceptTeamRequest, isAdmin, teamMembers, validId, validNonce, validHash, validName, roleCapacityReached, multiRoleFields, canAddRole } from './team-store.mjs';
import { deletePushSubscriptionTx } from './push-store.mjs';
import { revokeDeviceAuthTx } from './device-auth-store.mjs';

const DAY = 86400000, OPS = new Set(['create','inbox','outbox','open','ack','retry','admin_members','admin_update','admin_replace','directory','admin_certify','history','history_open','release_status']);
// 32 candidates bound the worst case below the adapter's 512-operation cap:
// current membership/subscription reads plus three queue index updates each.
const PUSH_SCAN_LIMIT = 32, PUSH_SKIP_BACKOFF = 30000;
const LIVE_TTL=2*DAY, HISTORY_TTL=90*DAY, HISTORY_BYTES=250000000, DAILY_PAYLOAD_BYTES=45000000;
const EDIT_ROLES = new Set(INVITE_ROLES);
const cmp = (a,b) => a < b ? -1 : a > b ? 1 : 0;
const bytes = x => Buffer.byteLength(JSON.stringify(x),'utf8');
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const memberKey = id => `member:${id}`;
const HUMAN_ROLES = new Set(['admin','neurologist','cardiologist','intensivist']);
const senderAllowed = (m,kind,group) => m?.state === 'active' && canSendGroup(m,group,kind);
// Existing private replies retain their old audience. New group conversations
// bind each delivered entry to the recipient's role at the moment of sending.
const recipientAllowed = (actor,m,e) => actor?.state === 'active' && !!e && (isGroupConversationKind(m.kind)
  ? hasRole(actor,e.recipient_role)&&participatesInGroup(actor,m.group_name)
  : m.kind === 'reply' ? HUMAN_ROLES.has(e.recipient_role) && hasRole(actor,e.recipient_role) : inRecipientGroup(actor,m.group_name));
const padded = n => String(n).padStart(16,'0');
// Fixed-width ASCII inverse preserves SQL ORDER BY issued DESC,id DESC.
const inverse = text => [...text].map(c => (127-c.charCodeAt(0)).toString(16).padStart(2,'0')).join('');
const newest = (issued,id) => `${String(9999999999999999n-BigInt(issued)).padStart(16,'0')}:${inverse(id)}`;
const entryKey = (id,recipient) => `directentry:${id}:${recipient}`;
const messageKey = id => `directmsg:${id}`;
const archiveKey = id => `directarchive:${id}`;
const messageMeta = m => ({id:m.id,group:m.group_name,kind:m.kind,issued:m.issued,expires:m.expires,...(isReplyKind(m.kind)?{replyTo:m.reply_to}:{})});
const historyItem = m => ({id:m.id,group:m.group_name,kind:m.kind,issued:m.issued,expires:m.expires,createdAt:m.created_at,archiveUntil:m.archive_until,recipientCount:m.recipient_count,openedCount:m.opened_count,hasContent:!!(m.sender_token||m.organizer_token)});
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
  const roles=memberRoles(m), proofs=[m.approval_proof,...(m.role_proofs??[])];
  if (!roles.length || proofs.length!==roles.length) return false;
  for(let i=0;i<roles.length;i++) {
    const g=proofs[i]?.grant;
    if (!g || g.subjectId!==m.device_id || g.name!==m.name || g.role!==roles[i] ||
      !Number.isSafeInteger(g.expires) || g.expires<=at || !await isAdmin(tx,g.issuerId)) return false;
  }
  return true;
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

const directoryMember = (m,includeRoles=false) => ({id:m.device_id,name:m.name,role:m.role,card:m.card,approvalProof:m.approval_proof ?? null,...multiRoleFields(m,includeRoles)});
const adminMember = (m,includeRoles=false) => ({...directoryMember(m,includeRoles),state:m.state,createdAt:m.created_at,approvedAt:m.approved_at ?? null,revokedAt:m.revoked_at ?? null,...(includeRoles&&m.pending_role?{pendingRole:m.pending_role}:{})});

// Metadata and ciphertext are budgeted together. A bounded set of daily buckets
// avoids scanning 90 days of per-message rate quota rows on each send.
async function reserveArchive(tx,archive,payloadBytes,at) {
  const rows=await tx.scan('directarchivebucket:',{limit:93});
  if(rows.length>92)throw new Error('Invalid archive accounting');
  let total=0;
  for(const {value} of rows){
    if(!Number.isSafeInteger(value.bytes)||value.bytes<0||!Number.isSafeInteger(value.until))throw new Error('Invalid archive accounting');
    if(value.until>at)total+=value.bytes;
  }
  const charge=bytes(archive)+payloadBytes+2048;
  if(total+charge>HISTORY_BYTES)return false;
  const bucket=Math.floor(archive.archive_until/DAY),key=`directarchivebucket:${bucket}`;
  const old=rows.find(r=>r.key===key)?.value;
  const until=(bucket+1)*DAY;
  await tx.put(key,{bytes:(old?.bytes??0)+charge,until},until);
  return true;
}
async function archiveReceipt(tx,id,recipient,patch,at) {
  const archive=await tx.get(archiveKey(id));
  if(!archive||archive.archive_until<=at)return;
  const recipients=archive.recipients.map(r=>r.id===recipient?{...r,...patch}:r);
  await tx.put(archiveKey(id),{...archive,recipients,opened_count:recipients.filter(r=>r.openedAt!==null).length},archive.archive_until);
}

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
    directory(deviceId,includeRoles=false) {
      return transaction(async tx => {
        const actor=validId(deviceId)?await tx.get(memberKey(deviceId)):null;
        if (actor?.state !== 'active') return status('denied');
        return {members:(await teamMembers(tx)).filter(m => m.state === 'active' && m.card != null &&
          // Older installed bots validate a closed set of roles. Preserve their
          // directory contract; rehab has no bot sender or recipient.
          (actor.role !== 'bot' || !isRehabGroup(roleGroup(m.role))))
          .sort((a,b) => cmp(a.role,b.role)||cmp(a.name,b.name)||cmp(a.device_id,b.device_id)).map(m=>directoryMember(m,includeRoles&&actor.role!=='bot'))};
      });
    },
    members(adminId,includeRoles=false) {
      return transaction(async tx => {
        if (!await isAdmin(tx,adminId)) return status('denied');
        return {members:(await teamMembers(tx)).sort((a,b) => cmp(a.state,b.state)||cmp(a.name,b.name)||cmp(a.device_id,b.device_id)).map(m=>adminMember(m,includeRoles))};
      });
    },
    certify(adminId,deviceId,proof) {
      return transaction(async (tx,at) => {
        if (!await isAdmin(tx,adminId) || !validId(deviceId)) return status('denied');
        const m = await tx.get(memberKey(deviceId));
        if (m?.state !== 'active' || m.role === 'admin') return status('denied');
        const requested=proof?.grant?.role;
        if (requested===m.role) {
          if (!boundProof(proof,adminId,deviceId,m.name,m.role,at)) return status('invalid');
          await tx.put(memberKey(deviceId),{...m,approval_proof:proof});
        } else if (m.pending_role===requested) {
          if (!canAddRole(m,requested) || !boundProof(proof,adminId,deviceId,m.name,requested,at)) return status('invalid');
          const invite=await tx.get(`invite:${m.pending_invite_hash}`);
          if (!invite || invite.claimed_by!==deviceId || invite.role!==requested || invite.inviter_id!==adminId || invite.expires<=at) return status('denied');
          const others=(await teamMembers(tx)).filter(x=>x.device_id!==deviceId);
          if (roleCapacityReached(others,requested)) return status('conflict');
          await tx.put(memberKey(deviceId),{...m,roles:[...memberRoles(m),requested],role_proofs:[...(m.role_proofs??[]),proof],pending_role:null,pending_invite_hash:null,pending_role_at:null});
        } else if (hasRole(m,requested)) {
          // An identical replay succeeds; a newly signed proof renews this one role.
          if (!boundProof(proof,adminId,deviceId,m.name,requested,at)) return status('invalid');
          await tx.put(memberKey(deviceId),{...m,role_proofs:memberRoles(m).slice(1).map((r,i)=>r===requested?proof:m.role_proofs[i])});
        } else return status('denied');
        await audit(tx,at,adminId,'certified',null,deviceId);
        return {state:'active'};
      });
    },
    create(senderId,requestHash,data) {
      return transaction(async (tx,at) => {
        if (!validId(senderId) || !validHash(requestHash) || !object(data) || !validNonce(data.id) ||
            !GROUPS.includes(data.group) || !['admission','review','reply','group_reply','discussion'].includes(data.kind) ||
            !Number.isSafeInteger(data.issued) || !Number.isSafeInteger(data.expires) || data.issued <= 0 ||
            data.expires <= data.issued || data.expires-data.issued > LIVE_TTL || !Array.isArray(data.entries) ||
            data.entries.length < 1 || bytes(data) > 2050000) return 'invalid';
        if(data.entries.length>25)return isGroupConversationKind(data.kind)?'group_too_large':'invalid';
        if (isReplyKind(data.kind) ? !validNonce(data.replyTo) || data.replyTo === data.id || !object(data.payload) || data.payload.replyTo !== data.replyTo : Object.hasOwn(data,'replyTo')) return 'invalid';
        const sender = await tx.get(memberKey(senderId));
        if (!senderAllowed(sender,data.kind,data.group) || !await approved(tx,sender,at)) return 'denied';
        const hasOrganizer=Object.hasOwn(data,'organizerId')||Object.hasOwn(data,'organizerToken');
        if(hasOrganizer){
          const root=await tx.get('config:organizer');
          if(sender.role!=='bot'||data.kind!=='admission'||!['cardiology','orit'].includes(data.group)||
             Object.hasOwn(data,'payload')||Object.hasOwn(data,'senderToken')||!validId(data.organizerId)||
             root?.device_id!==data.organizerId||sender.approval_proof?.grant?.issuerId!==data.organizerId||!await isAdmin(tx,data.organizerId))return 'denied';
          if(typeof data.organizerToken!=='string'||data.organizerToken.length>1000)return 'invalid';
          const parts=data.organizerToken.split('.');
          if(parts.length!==5||parts[0]!=='PSO1'||parts[1]!==data.organizerId||parts[2]!==senderId||parts.some(s=>!s||!/^[A-Za-z0-9_-]+$/.test(s)))return 'invalid';
        }
        if ((isRehabGroup(data.group)||isGroupConversationKind(data.kind)) && (!object(data.payload) || data.entries.some(e => typeof e?.token !== 'string' || !e.token.startsWith('PSO2.')))) return 'invalid';
        const archiveOld=await tx.get(archiveKey(data.id));
        if(archiveOld)return archiveOld.sender_id===senderId&&archiveOld.request_hash===requestHash?'exists':'conflict';
        if (data.expires <= at || data.issued > at+30000) return 'invalid';
        const old = await tx.get(messageKey(data.id));
        if (old) return old.sender_id === senderId && old.request_hash === requestHash ? 'exists' : 'conflict';
        if(hasOrganizer){
          // New archives capture a grant that verifies at the original message
          // time. Exact retries keep their already validated snapshot even if
          // the bot has since received a newer certificate.
          const grant=sender.approval_proof.grant;
          if(!Number.isSafeInteger(grant.issued)||grant.issued>data.issued+30000||grant.expires<=data.issued)return 'denied';
        }
        let recipients;
        if (data.kind === 'reply') {
          const parent = await tx.get(messageKey(data.replyTo));
          if (!parent || parent.expires <= at) return 'missing';
          const originalEntry = await tx.get(entryKey(parent.id,senderId));
          if (parent.group_name !== data.group || !recipientAllowed(sender,parent,originalEntry)) return 'denied';
          const recipient = await tx.get(memberKey(parent.sender_id));
          if (parent.sender_id === senderId || !senderAllowed(recipient,'reply',data.group)) return 'denied';
          recipients = [recipient];
        } else if(isGroupConversationKind(data.kind)) {
          if(data.kind==='group_reply'){
            const parent=await tx.get(messageKey(data.replyTo));
            if(!parent||parent.expires<=at)return 'missing';
            if(parent.group_name!==data.group)return 'denied';
            const originalEntry=await tx.get(entryKey(parent.id,senderId));
            if(parent.sender_id!==senderId&&!recipientAllowed(sender,parent,originalEntry))return 'denied';
          }
          recipients=(await teamMembers(tx)).filter(m=>m.state==='active'&&m.device_id!==senderId&&participatesInGroup(m,data.group))
            .sort((a,b)=>cmp(a.device_id,b.device_id));
          if(recipients.length>25)return 'group_too_large';
        } else {
          recipients = (await teamMembers(tx)).filter(m => m.state === 'active' && m.device_id !== senderId && inRecipientGroup(m,data.group))
            .sort((a,b) => cmp(a.device_id,b.device_id));
        }
        const entries = [...data.entries].sort((a,b) => cmp(a?.recipientId,b?.recipientId));
        if (!recipients.length || JSON.stringify(entries.map(e => e?.recipientId)) !== JSON.stringify(recipients.map(m => m.device_id))) return 'roster_changed';
        for (const m of recipients) if (!await approved(tx,m,at)) return 'denied';
        for (const e of entries) {
          if (!object(e) || !validId(e.recipientId) || typeof e.token !== 'string' || Buffer.byteLength(e.token,'utf8') > 1000) return 'invalid';
          const parts = e.token.split('.');
          if (!['PSO1','PSO2'].includes(parts[0]) || parts[1] !== e.recipientId || parts[2] !== senderId || parts.some(s => !s || !/^[A-Za-z0-9_-]+$/.test(s))) return 'invalid';
          if(hasOrganizer&&parts[0]!=='PSO1')return 'invalid';
        }
        const hasPayload = Object.hasOwn(data,'payload');
        const payloadBytes = hasPayload ? bytes(data.payload) : 0;
        if (hasPayload && (!object(data.payload) || payloadBytes > 2000000)) return 'invalid';
        const hasSenderToken=Object.hasOwn(data,'senderToken');
        if(hasSenderToken){
          if(!hasPayload||typeof data.senderToken!=='string'||data.senderToken.length>1000)return 'invalid';
          const parts=data.senderToken.split('.');
          if(parts.length!==6||parts[0]!=='PSO2'||parts[1]!==senderId||parts[2]!==senderId)return 'invalid';
        }
        // Tiny quota records are retained independently of ciphertext TTL, so
        // expiring messages cannot bypass daily send and encrypted-byte caps.
        const ownQuota = (await scanAll(tx,`directquota:sender:${senderId}:`)).map(r => r.value).filter(q => q.created_at > at-DAY);
        if (ownQuota.length >= 500 || (hasPayload && ownQuota.reduce((total,q)=>total+q.payload_bytes,0)+payloadBytes>DAILY_PAYLOAD_BYTES)) return 'limited';
        const globalQuota = (await scanAll(tx,'directquota:all:')).map(r => r.value);
        if (globalQuota.filter(q => q.created_at > at-DAY).length >= 5000 ||
            (hasPayload && globalQuota.filter(q => q.expires > at).reduce((s,q) => s+q.payload_bytes,0)+payloadBytes > 250000000)) return 'limited';
        const m = {id:data.id,request_hash:requestHash,sender_id:senderId,group_name:data.group,kind:data.kind,issued:data.issued,
          expires:data.expires,created_at:at,has_payload:hasPayload,recipient_count:entries.length,opened_count:0,...(isReplyKind(data.kind) ? {reply_to:data.replyTo} : {})};
        const archiveUntil=data.issued+HISTORY_TTL;
        // Archives are opt-in: a self-addressed human token, or a bot token
        // encrypted only to the active administrator who approved that bot.
        // Legacy requests without either token retain their original behavior.
        if(hasSenderToken||hasOrganizer){
          const archive={...m,archive_until:archiveUntil,sender_token:hasSenderToken?data.senderToken:null,
            organizer_id:hasOrganizer?data.organizerId:null,organizer_token:hasOrganizer?data.organizerToken:null,
            sender_approval_proof:hasOrganizer?sender.approval_proof:null,
            sender_card:sender.card,sender_name:sender.name,sender_role:sender.role,...(memberRoles(sender).length>1?{sender_roles:memberRoles(sender)}:{}),
            recipients:recipients.map(r=>({id:r.device_id,name:r.name,role:r.role,...(memberRoles(r).length>1?{roles:memberRoles(r)}:{}),openedAt:null,pushState:'queued',pushAcceptedAt:null}))};
          if(!await reserveArchive(tx,archive,payloadBytes,at))return 'history_full';
          await tx.put(archiveKey(m.id),archive,archiveUntil);
          const historyPrefix=hasOrganizer?`directbothistory:${data.organizerId}`:`directhistory:${senderId}`;
          await tx.put(`${historyPrefix}:${newest(m.issued,m.id)}`,{message_id:m.id},archiveUntil);
        }
        await tx.put(messageKey(m.id),m,m.expires);
        if (hasPayload) await tx.put(`directpayload:${m.id}`,data.payload,hasSenderToken?archiveUntil:m.expires);
        await tx.put(`directout:${senderId}:${newest(m.issued,m.id)}`,{message_id:m.id,...(isGroupConversationKind(m.kind)?{kind:m.kind}:{})},m.expires);
        for (const item of entries) {
          const e = {message_id:m.id,recipient_id:item.recipientId,token:item.token,opened_at:null,push_state:'queued',push_attempts:0,lease_until:0,next_attempt:0,endpoint_hash:null,...(data.kind === 'reply'||isGroupConversationKind(data.kind) ? {recipient_role:data.kind==='reply'?memberRoles(recipients.find(r=>r.device_id===item.recipientId)).find(r=>HUMAN_ROLES.has(r)):recipients.find(r=>r.device_id===item.recipientId).role} : {})};
          await tx.put(entryKey(m.id,e.recipient_id),e,m.expires);
          await tx.put(`directin:${e.recipient_id}:${newest(m.issued,m.id)}`,{message_id:m.id,group_name:m.group_name,...(isGroupConversationKind(m.kind)?{kind:m.kind}:{})},m.expires);
          await putQueue(tx,m,e);
        }
        const quota = {created_at:at,expires:m.expires,payload_bytes:payloadBytes}, quotaTTL = Math.max(at+DAY,m.expires);
        await tx.put(`directquota:all:${padded(at)}:${m.id}`,quota,quotaTTL);
        await tx.put(`directquota:sender:${senderId}:${padded(at)}:${m.id}`,quota,quotaTTL);
        await audit(tx,at,senderId,'created',m.id);
        return 'created';
      });
    },
    list(deviceId,outbox,cursor=null,includeConversations=false) {
      return transaction(async (tx,at) => {
        const actor = validId(deviceId) ? await tx.get(memberKey(deviceId)) : null;
        if (actor?.state !== 'active') return status('denied');
        if (typeof includeConversations!=='boolean' || (cursor !== null && (!object(cursor) || !validNonce(cursor.id) || !Number.isSafeInteger(cursor.issued) || cursor.issued <= 0))) return status('invalid');
        const prefix = `${outbox ? 'directout' : 'directin'}:${deviceId}:`, items = [], senderCache = new Map();
        const after = cursor ? `${prefix}${newest(cursor.issued,cursor.id)}` : null;
        // A page may be short or empty when old clients skip new conversation
        // kinds, or when roles were revoked. Bound all reads, then advance by
        // the last scanned record so later old messages remain reachable.
        const page=await tx.scan(prefix,{limit:100,...(after?{after}:{})});
        let lastScanned=null;
        for(const row of page){
          const issued=Number(9999999999999999n-BigInt(row.key.slice(prefix.length,prefix.length+16)));
          if(!Number.isSafeInteger(issued)||issued<=0||!validNonce(row.value.message_id))throw new Error('Invalid delivery index');
          lastScanned={id:row.value.message_id,issued};
          if(!includeConversations&&isGroupConversationKind(row.value.kind))continue;
          const m=await tx.get(messageKey(row.value.message_id));
          if(!m||m.expires<=at||(outbox&&m.sender_id!==deviceId)||(!includeConversations&&isGroupConversationKind(m.kind)))continue;
          const e=await tx.get(entryKey(m.id,deviceId));
          if(!outbox&&!recipientAllowed(actor,m,e))continue;
          if(!senderCache.has(m.sender_id))senderCache.set(m.sender_id,await tx.get(memberKey(m.sender_id)));
          const sender=senderCache.get(m.sender_id);
          if(!sender)continue;
          items.push({id:m.id,group:m.group_name,kind:m.kind,issued:m.issued,expires:m.expires,senderId:m.sender_id,senderName:sender.name,
            openedAt:e?.opened_at??null,recipientCount:m.recipient_count,openedCount:m.opened_count});
          if(items.length===51)break;
        }
        if(items.length>50){items.pop();return {items,next:{id:items.at(-1).id,issued:items.at(-1).issued}};}
        return {items,next:page.length===100?lastScanned:null};
      });
    },
    open(deviceId,id,ack=false,includeRoles=false) {
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
            await archiveReceipt(tx,id,deviceId,{openedAt:at},at);
            await audit(tx,at,deviceId,'opened',id);
          }
          return {openedAt:e.opened_at ?? at};
        }
        const sender = await tx.get(memberKey(m.sender_id));
        if (!sender?.card) return status('denied');
        const payload = m.has_payload ? await tx.get(`directpayload:${id}`) : null;
        if (m.has_payload && !payload) return status('missing');
        await audit(tx,at,deviceId,'retrieved',id);
        return {meta:messageMeta(m),payload,senderApprovalProof:sender.approval_proof ?? null,
          senderCard:sender.card,senderName:sender.name,senderRole:sender.role,token:e.token,...(includeRoles&&memberRoles(sender).length>1?{senderRoles:memberRoles(sender),senderRoleProofs:sender.role_proofs??[]}:{})};
      });
    },
    history(deviceId,cursor=null,source=null) {
      return transaction(async(tx,at)=>{
        const actor=validId(deviceId)?await tx.get(memberKey(deviceId)):null;
        if(actor?.state!=='active'||(source==='bot'&&actor.role!=='admin'))return status('denied');
        if(source!==null&&source!=='bot')return status('invalid');
        if(cursor!==null&&(!object(cursor)||!validNonce(cursor.id)||!Number.isSafeInteger(cursor.issued)||cursor.issued<=0))return status('invalid');
        const prefix=`${source==='bot'?'directbothistory':'directhistory'}:${deviceId}:`,after=cursor?`${prefix}${newest(cursor.issued,cursor.id)}`:null;
        const rows=await tx.scan(prefix,{limit:51,...(after?{after}:{})}),items=[];
        for(const row of rows){
          const archive=await tx.get(archiveKey(row.value.message_id));
          const owned=archive&&(source==='bot'?archive.organizer_id===deviceId:!archive.organizer_id&&archive.sender_id===deviceId);
          if(owned&&archive.archive_until>at)items.push(historyItem(archive));
        }
        const more=items.length>50;if(more)items.pop();
        return {items,next:more?{id:items.at(-1).id,issued:items.at(-1).issued}:null};
      });
    },
    historyOpen(deviceId,id,includeRoles=false) {
      return transaction(async(tx,at)=>{
        const actor=validId(deviceId)?await tx.get(memberKey(deviceId)):null;
        if(actor?.state!=='active')return status('denied');
        const archive=validNonce(id)?await tx.get(archiveKey(id)):null;
        if(!archive||archive.archive_until<=at)return status('missing');
        if(archive.organizer_id?archive.organizer_id!==deviceId||actor.role!=='admin':archive.sender_id!==deviceId)return status('denied');
        const payload=archive.sender_token?await tx.get(`directpayload:${id}`):null;
        if(archive.sender_token&&!payload)return status('missing');
        return {meta:messageMeta(archive),payload,senderToken:archive.sender_token,
          organizerToken:archive.organizer_token??null,senderApprovalProof:archive.sender_approval_proof??null,
          createdAt:archive.created_at,archiveUntil:archive.archive_until,recipients:archive.recipients.map(r=>{const {roles,...old}=r;return includeRoles?r:old;}),
          senderCard:archive.sender_card,senderName:archive.sender_name,senderRole:archive.sender_role,...(includeRoles&&archive.sender_roles?{senderRoles:archive.sender_roles}:{})};
      });
    },
    update(adminId,deviceId,name,role,state,proof=null,roles=null,roleProofs=null) {
      return transaction(async (tx,at) => {
        if (!await isAdmin(tx,adminId) || !validId(deviceId) || adminId === deviceId) return status('denied');
        const m = await tx.get(memberKey(deviceId));
        if (m?.state !== 'active' || m.role === 'admin') return status('denied');
        if (!validName(name) || !EDIT_ROLES.has(role) || !['active','revoked'].includes(state)) return status('invalid');
        const current=memberRoles(m), nextRoles=state==='revoked'?current:roles===null?[role]:memberRoles({role,roles});
        if (!nextRoles.length || (current.length>1 && JSON.stringify(nextRoles)!==JSON.stringify(current)) ||
            (current.length===1&&nextRoles.length>1)) return status('invalid');
        if (state === 'active') {
          if (!boundProof(proof,adminId,deviceId,name,role,at) ||
              (nextRoles.length>1 && (!Array.isArray(roleProofs)||roleProofs.length!==nextRoles.length-1||nextRoles.slice(1).some((r,i)=>!boundProof(roleProofs[i],adminId,deviceId,name,r,at))))) return status('invalid');
          const others = (await teamMembers(tx)).filter(x => x.device_id !== deviceId);
          if (nextRoles.some(r=>roleCapacityReached(others,r))) return status('conflict');
        }
        const {roles:oldRoles,role_proofs:oldProofs,...base}=m;
        await tx.put(memberKey(deviceId),{...base,name,role,state,approval_proof:state === 'active' ? proof : null,
          ...(nextRoles.length>1?{roles:nextRoles,role_proofs:state==='active'?roleProofs:oldProofs}:{}),
          ...(state==='revoked'?{pending_role:null,pending_invite_hash:null,pending_role_at:null}:{}),revoked_at:state === 'revoked' ? at : m.revoked_at ?? null});
        if (state === 'revoked') await clearDeviceAccess(tx,deviceId);
        await audit(tx,at,adminId,state === 'revoked' ? 'revoked' : 'updated',null,deviceId);
        return {state};
      });
    },
    replace(adminId,oldId,newId,proof,roleProofs=null) {
      return transaction(async (tx,at) => {
        if (!await isAdmin(tx,adminId) || !validId(oldId) || !validId(newId) || oldId === newId || oldId === adminId) return status('denied');
        const old = await tx.get(memberKey(oldId)), next = await tx.get(memberKey(newId));
        if (!old || old.role === 'admin' || !['active','revoked'].includes(old.state) || next?.state !== 'pending' || next.role === 'admin') return status('denied');
        const roles=memberRoles(old);
        if (!boundProof(proof,adminId,newId,old.name,old.role,at) || !roles.length ||
            (roles.length>1&&(!Array.isArray(roleProofs)||roleProofs.length!==roles.length-1||roles.slice(1).some((r,i)=>!boundProof(roleProofs[i],adminId,newId,old.name,r,at))))) return status('invalid');
        const others = (await teamMembers(tx)).filter(m => m.device_id !== oldId);
        if (roles.some(r=>roleCapacityReached(others,r))) return status('conflict');
        await tx.put(memberKey(oldId),{...old,state:'revoked',approval_proof:null,pending_role:null,pending_invite_hash:null,pending_role_at:null,revoked_at:old.revoked_at ?? at});
        await clearDeviceAccess(tx,oldId);
        await tx.put(memberKey(newId),{...next,state:'active',name:old.name,role:old.role,approval_proof:proof,...(roles.length>1?{roles,role_proofs:roleProofs}:{}),pending_role:null,pending_invite_hash:null,pending_role_at:null,approved_at:at});
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
        // Persist only a bot scan cursor, never change skipped rehab entries.
        // Otherwise a front page of rehab notifications could starve old PSO work.
        const cursorKey = actor.role === 'bot' && id === null ? `directbotcursor:${actorId}` : null;
        const savedCursor = cursorKey ? await tx.get(cursorKey) : null;
        const targetLimit=id===null?20:25;
        const targets = []; let after=savedCursor?.after, examined=0, lastExamined=null, exhausted=false;
        for (;;) {
          const pageSize=Math.min(100,PUSH_SCAN_LIMIT-examined);
          if(pageSize<=0)break;
          const page = await tx.scan(prefix,{limit:pageSize,...(after ? {after} : {})});
          let future = false;
          for (const row of page) {
            if (Number(row.key.slice(prefix.length,prefix.length+16)) > at) { future=true; break; }
            examined++;lastExamined=row.key;
            const m = await tx.get(messageKey(row.value.message_id));
            if (!m || m.expires <= at) { await removeQueueRow(tx,prefix,row); continue; }
            // A message-filtered request by another doctor must never mutate
            // the real sender's queue or postpone their notifications.
            if (!canAll && m.sender_id !== actorId) continue;
            // The bot must not trigger rehabilitation or human conversation notifications.
            if (actor.role === 'bot' && (isRehabGroup(m.group_name)||isGroupConversationKind(m.kind))) continue;
            const e = await tx.get(entryKey(m.id,row.value.recipient_id));
            if (!e || e.push_state === 'accepted' || e.push_attempts >= 8 || e.lease_until > at || e.next_attempt > at) {
              await removeQueueRow(tx,prefix,row); continue;
            }
            const recipient = await tx.get(memberKey(e.recipient_id)), sender = await tx.get(memberKey(m.sender_id));
            const eligible = recipientAllowed(recipient,m,e) && senderAllowed(sender,m.kind,m.group_name);
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
            await archiveReceipt(tx,m.id,e.recipient_id,{pushState:'sending'},at);
            await putQueue(tx,m,claimed);
            targets.push({id:m.id,recipientId:e.recipient_id,expires:m.expires,subscription:sub.subscription,lease:claimed.push_attempts});
            if (targets.length === targetLimit) break;
          }
          exhausted = future || (page.length < pageSize && examined < PUSH_SCAN_LIMIT && targets.length < targetLimit);
          if (targets.length === targetLimit || future || examined >= PUSH_SCAN_LIMIT || page.length < pageSize) break;
          after = page.at(-1).key;
        }
        if (cursorKey) {
          if (exhausted || !lastExamined) await tx.delete(cursorKey);
          else await tx.put(cursorKey,{after:lastExamined},at+DAY);
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
        await archiveReceipt(tx,id,recipientId,{pushState:deliveryStatus,...(deliveryStatus==='accepted'?{pushAcceptedAt:at}:{})},at);
        await putQueue(tx,m,finished);
        if (deliveryStatus === 'gone') {
          await deletePushSubscriptionTx(tx,recipientId,e.endpoint_hash);
        }
        return 'ok';
      });
    },
  };
}
