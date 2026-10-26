// Transactional YDB document port of team-schema.sql and direct-schema.sql's
// updated role limits. HTTP handlers verify signatures before using this store.
// Documents contain public staff keys and ciphertext, never patient plaintext.
import {revokeDeviceAuthTx} from './device-auth-store.mjs';

const MINUTE = 60000, DAY = 86400000;
const TEAM_OPS = new Set(['status','directory','invite','claim','pending','approve','revoke','create','resolve']);
const INVITE_ROLES = new Set(['neurologist','cardiologist','intensivist','bot']);
export const validId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(value);
export const validNonce = value => typeof value === 'string' && /^[A-Za-z0-9_-]{21}[AQgw]$/.test(value);
export const validHash = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
export const validName = value => typeof value === 'string' && value === value.normalize('NFC').trim() && [...value].length >= 1 && [...value].length <= 60 && !/[\p{Cc}\p{Cf}]/u.test(value);
export const validCard = value => typeof value === 'string' && value.length >= 100 && value.length <= 5000 && /^PSO-CARD1\.[A-Za-z0-9_-]+$/.test(value);
export const validSpki = value => typeof value === 'string' && /^[A-Za-z0-9_-]{121}[AQgw]$/.test(value);
const validToken = value => typeof value === 'string' && /^PSO1\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]\.[A-Za-z0-9_-]{512}\.[A-Za-z0-9_-]{85}[AQgw]$/.test(value);
const memberKey = id => `member:${id}`;
const compare = (a,b) => a < b ? -1 : a > b ? 1 : 0;
const memberView = m => ({id:m.device_id,name:m.name,role:m.role,card:m.card});
const roleFor = group => group === 'cardiology' ? 'cardiologist' : 'intensivist';
const senderAllowed = (m,kind) => m?.state === 'active' && (kind === 'admission' ? m.role === 'bot' : ['admin','neurologist'].includes(m.role));

async function removeSubscription(tx,deviceId,expectedEndpointHash=null) {
  const key = `pushsub:${deviceId}`, subscription = await tx.get(key);
  if (!subscription || (expectedEndpointHash !== null && subscription.endpoint_hash !== expectedEndpointHash)) return;
  await tx.delete(key);
  if (validHash(subscription.endpoint_hash)) {
    const indexKey = `pushendpoint:${subscription.endpoint_hash}`, index = await tx.get(indexKey);
    if (index?.device_id === deviceId) await tx.delete(indexKey);
  }
}

export async function isAdmin(tx,id) {
  if (!validId(id)) return false;
  const member = await tx.get(memberKey(id));
  return member?.state === 'active' && member.role === 'admin';
}

export async function teamMembers(tx) {
  const rows = await tx.scan('member:', {limit:101});
  if (rows.length > 100) throw new Error('Membership capacity exceeded');
  return rows.map(row => row.value);
}

// Checks every cap before writing any counter. The caller must use one
// serializable transaction, including the action guarded by these quotas.
export async function consumeTeamQuotas(tx, specifications, at) {
  const counters = [];
  for (const {scope,id,windowMs,limit} of specifications) {
    const bucket = Math.floor(at / windowMs);
    const key = `quota:team:${scope}:${id}:${bucket}`;
    const old = await tx.get(key), used = old?.used ?? 0;
    if (!Number.isSafeInteger(used) || used < 0) throw new Error('Invalid quota state');
    if (used >= limit) return false;
    counters.push({key,scope,id,bucket,windowMs,used:used+1});
  }
  for (const {key,...counter} of counters) {
    await tx.put(key,counter,(counter.bucket+1)*counter.windowMs+2*DAY);
  }
  return true;
}

// Shared by team, direct and device-holder authentication, as in the SQL RPCs.
// A status/claim request may come from an unknown or revoked device, but no
// membership is created here. Only the separately pinned admin can bind a card.
export async function acceptTeamRequest(tx,{deviceId,nonce,op,issued,card,signingSpki},at) {
  if (!validId(deviceId) || !validNonce(nonce) || !TEAM_OPS.has(op) || !validCard(card) || !validSpki(signingSpki) ||
      !Number.isSafeInteger(issued) || !Number.isSafeInteger(at) || issued < at-MINUTE || issued > at+30000) return 'denied';
  const nonceKey = `nonce:team:${deviceId}:${nonce}`;
  if (await tx.get(nonceKey)) return 'replay';
  const member = await tx.get(memberKey(deviceId));
  if (member && member.signing_spki !== signingSpki) return 'denied';
  if (!await consumeTeamQuotas(tx,[
    {scope:'day',id:'global',windowMs:DAY,limit:20000},
    {scope:'minute',id:deviceId,windowMs:MINUTE,limit:60},
    {scope:'day',id:deviceId,windowMs:DAY,limit:2000},
  ],at)) return 'limited';
  await tx.put(nonceKey,{device_id:deviceId,nonce,created_at:at},at+2*MINUTE);
  if (member && member.card == null && member.role === 'admin' && member.state === 'active') {
    await tx.put(memberKey(deviceId),{...member,card});
  }
  return 'ok';
}

function normalizedEntries(entries,senderId) {
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > 25 || Buffer.byteLength(JSON.stringify(entries),'utf8') > 24576) return null;
  const seen = new Set(), normalized = [];
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).sort().join(',') !== 'recipientId,token' ||
        !validId(entry.recipientId) || !validToken(entry.token) || seen.has(entry.recipientId)) return null;
    const parts = entry.token.split('.');
    if (parts[1] !== entry.recipientId || parts[2] !== senderId) return null;
    seen.add(entry.recipientId); normalized.push({recipientId:entry.recipientId,token:entry.token});
  }
  return normalized.sort((a,b) => compare(a.recipientId,b.recipientId));
}

export function createTeamStore(db,{now=Date.now}={}) {
  if (typeof db?.transaction !== 'function' || typeof now !== 'function') throw new Error('Team store configuration missing');
  const transaction = action => db.transaction(tx => {
    const at = now();
    if (!Number.isSafeInteger(at) || at <= 0) throw new Error('Clock unavailable');
    return action(tx,at);
  });
  return {
    accept(deviceId,nonce,op,issued,card,signingSpki) {
      return transaction((tx,at) => acceptTeamRequest(tx,{deviceId,nonce,op,issued,card,signingSpki},at));
    },
    status(deviceId) {
      return transaction(async tx => {
        const m = validId(deviceId) ? await tx.get(memberKey(deviceId)) : null;
        return m ? {state:m.state,role:m.role,name:m.name} : {state:'unregistered',role:null,name:null};
      });
    },
    directory(deviceId) {
      return transaction(async tx => {
        if (!validId(deviceId) || (await tx.get(memberKey(deviceId)))?.state !== 'active') return {status:'denied'};
        return {members:(await teamMembers(tx)).filter(m => m.state === 'active' && m.card != null)
          .sort((a,b) => compare(a.role,b.role)||compare(a.name,b.name)||compare(a.device_id,b.device_id)).map(memberView)};
      });
    },
    invite(adminId,idHash,name,role) {
      return transaction(async (tx,at) => {
        if (!validHash(idHash) || !validName(name) || !INVITE_ROLES.has(role)) return {status:'invalid'};
        if (!await isAdmin(tx,adminId)) return {status:'denied'};
        const key = `invite:${idHash}`, old = await tx.get(key);
        if (old) return old.inviter_id === adminId && old.name === name && old.role === role && old.expires > at && old.claimed_by == null
          ? {status:'exists',expires:old.expires} : {status:'conflict'};
        // Retention is bounded by the daily cap; page to avoid truncating a roster.
        let live = 0, after;
        for (;;) {
          const rows = await tx.scan('invite:',{limit:1000,...(after ? {after} : {})});
          for (const {value} of rows) if (value.expires > at && value.claimed_by == null) live++;
          if (live >= 100) return {status:'limited'};
          if (rows.length < 1000) break;
          after = rows.at(-1).key;
        }
        if (!await consumeTeamQuotas(tx,[{scope:'invite-day',id:adminId,windowMs:DAY,limit:100}],at)) return {status:'limited'};
        const expires = at+2*DAY;
        await tx.put(key,{id_hash:idHash,inviter_id:adminId,name,role,expires,claimed_by:null,created_at:at},expires+7*DAY);
        return {status:'created',expires};
      });
    },
    claim(deviceId,idHash,card,signingSpki) {
      return transaction(async (tx,at) => {
        if (!validId(deviceId) || !validHash(idHash) || !validCard(card) || !validSpki(signingSpki)) return 'denied';
        const key = `invite:${idHash}`, invite = await tx.get(key);
        if (!invite || !await isAdmin(tx,invite.inviter_id)) return 'denied';
        const old = await tx.get(memberKey(deviceId));
        if (old) return old.invite_hash === idHash && invite.claimed_by === deviceId && old.signing_spki === signingSpki &&
          ['pending','active'].includes(old.state) ? old.state : 'conflict';
        if (invite.expires <= at || invite.claimed_by != null || !INVITE_ROLES.has(invite.role) || !validName(invite.name)) return 'denied';
        if ((await teamMembers(tx)).length >= 100) return 'limited';
        await tx.put(memberKey(deviceId),{device_id:deviceId,name:invite.name,role:invite.role,state:'pending',card,
          signing_spki:signingSpki,invite_hash:idHash,created_at:at,approved_at:null,revoked_at:null,approval_proof:null});
        await tx.put(key,{...invite,claimed_by:deviceId},invite.expires+7*DAY);
        return 'pending';
      });
    },
    pending(adminId) {
      return transaction(async tx => {
        if (!await isAdmin(tx,adminId)) return {status:'denied'};
        return {members:(await teamMembers(tx)).filter(m => m.state === 'pending')
          .sort((a,b) => a.created_at-b.created_at||compare(a.device_id,b.device_id)).map(memberView)};
      });
    },
    approve(adminId,deviceId) {
      return transaction(async (tx,at) => {
        if (!await isAdmin(tx,adminId) || !validId(deviceId)) return 'denied';
        const member = await tx.get(memberKey(deviceId));
        if (!member || !INVITE_ROLES.has(member.role) || member.state === 'revoked') return 'denied';
        if (member.state === 'active') return 'active';
        if (member.state !== 'pending') return 'denied';
        const sameRole = (await teamMembers(tx)).filter(m => m.state === 'active' && m.role === member.role);
        if ((member.role === 'cardiologist' && sameRole.length) || (['bot','intensivist'].includes(member.role) && sameRole.length >= 25)) return 'conflict';
        await tx.put(memberKey(deviceId),{...member,state:'active',approved_at:at});
        return 'active';
      });
    },
    revoke(adminId,deviceId) {
      return transaction(async (tx,at) => {
        if (!await isAdmin(tx,adminId) || !validId(deviceId)) return 'denied';
        const member = await tx.get(memberKey(deviceId));
        if (!member || member.role === 'admin') return 'denied';
        await tx.put(memberKey(deviceId),{...member,state:'revoked',approval_proof:null,revoked_at:member.revoked_at ?? at});
        await removeSubscription(tx,deviceId);
        await revokeDeviceAuthTx(tx,deviceId);
        return 'revoked';
      });
    },
    create(senderId,idHash,requestHash,group,kind,issued,expires,entries) {
      return transaction(async (tx,at) => {
        if (!validId(senderId) || !validHash(idHash) || !validHash(requestHash) || !['cardiology','orit'].includes(group) ||
            !['admission','review'].includes(kind) || !Number.isSafeInteger(issued) || !Number.isSafeInteger(expires) ||
            issued <= 0 || expires <= issued || expires-issued > DAY) return 'invalid';
        const normalized = normalizedEntries(entries,senderId);
        if (!normalized) return 'invalid';
        const sender = await tx.get(memberKey(senderId));
        if (!senderAllowed(sender,kind) || sender.card == null) return 'denied';
        if (expires <= at) return 'invalid';
        const key = `teammsg:${idHash}`, old = await tx.get(key);
        if (old) return old.sender_id === senderId && old.request_hash === requestHash && old.group_name === group && old.kind === kind &&
          old.issued === issued && old.expires === expires && JSON.stringify(old.entries) === JSON.stringify(normalized) ? 'exists' : 'conflict';
        if (await tx.get(`legacy:${idHash}`)) return 'conflict';
        if (issued > at+30000) return 'invalid';
        const expected = (await teamMembers(tx)).filter(m => m.state === 'active' && m.card != null && m.role === roleFor(group))
          .map(m => m.device_id).sort(compare);
        if (!expected.length || JSON.stringify(expected) !== JSON.stringify(normalized.map(e => e.recipientId))) return 'roster_changed';
        if (!await consumeTeamQuotas(tx,[
          {scope:'create-day',id:'global',windowMs:DAY,limit:5000},
          {scope:'create-day',id:senderId,windowMs:DAY,limit:500},
          {scope:'create-minute',id:senderId,windowMs:MINUTE,limit:30},
        ],at)) return 'limited';
        await tx.put(key,{id_hash:idHash,request_hash:requestHash,sender_id:senderId,group_name:group,kind,issued,expires,entries:normalized,created_at:at},expires);
        return 'created';
      });
    },
    resolve(deviceId,idHash) {
      return transaction(async (tx,at) => {
        if (!validId(deviceId) || !validHash(idHash)) return {status:'missing'};
        const message = await tx.get(`teammsg:${idHash}`);
        if (!message || message.expires <= at) return {status:'missing'};
        const member = await tx.get(memberKey(deviceId));
        if (member?.state !== 'active' || member.role !== roleFor(message.group_name)) return {status:'denied'};
        const entry = message.entries.find(e => e.recipientId === deviceId);
        if (!entry) return {status:'denied'};
        const sender = await tx.get(memberKey(message.sender_id));
        if (!sender?.card) return {status:'denied'};
        return {status:'ok',token:entry.token,expires:message.expires,senderCard:sender.card,senderName:sender.name};
      });
    },
    pushClaim(senderId,idHash) {
      return transaction(async (tx,at) => {
        const targets = [];
        if (!validId(senderId) || !validHash(idHash)) return {targets};
        const message = await tx.get(`teammsg:${idHash}`);
        if (!message || message.sender_id !== senderId || message.expires <= at || !senderAllowed(await tx.get(memberKey(senderId)),message.kind)) return {targets};
        for (const {recipientId} of message.entries) {
          const member = await tx.get(memberKey(recipientId));
          if (member?.state !== 'active' || member.role !== roleFor(message.group_name)) continue;
          const subscription = await tx.get(`pushsub:${recipientId}`), key = `teampush:${idHash}:${recipientId}`;
          if (!subscription || !Number.isSafeInteger(subscription.refreshed_at) || subscription.refreshed_at < at-90*DAY ||
              !validHash(subscription.endpoint_hash) || !Array.isArray(subscription.senders) || !subscription.senders.includes(senderId) || await tx.get(key)) continue;
          await tx.put(key,{id_hash:idHash,recipient_id:recipientId,endpoint_hash:subscription.endpoint_hash,status:'sending',created_at:at},message.expires);
          targets.push({recipientId,subscription:subscription.subscription,expires:message.expires});
        }
        return {targets};
      });
    },
    pushFinish(idHash,recipientId,status) {
      return transaction(async tx => {
        if (!validHash(idHash) || !validId(recipientId) || !['accepted','gone','failed'].includes(status)) return 'invalid';
        const key = `teampush:${idHash}:${recipientId}`, claim = await tx.get(key);
        if (!claim || claim.status !== 'sending') return 'unchanged';
        const message = await tx.get(`teammsg:${idHash}`);
        if (!message) return 'unchanged';
        await tx.put(key,{...claim,status},message.expires);
        if (status === 'gone') await removeSubscription(tx,recipientId,claim.endpoint_hash);
        return 'ok';
      });
    },
  };
}
