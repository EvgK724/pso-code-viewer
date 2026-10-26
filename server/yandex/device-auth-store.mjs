// WebAuthn state is private backend state. Challenges are consumed atomically;
// only session hashes, public credentials and staff identifiers are persisted.
import {createHash} from 'node:crypto';
import {acceptTeamRequest,isAdmin,validId,validHash} from './team-store.mjs';

const sha = value => createHash('sha256').update(value,'utf8').digest('hex');
const purposeValid = value => ['enroll','unlock'].includes(value);
const credentialKey = id => `authcred:${id}`;
const credentialOwnerKey = id => `authcredid:${sha(id)}`;
const exact = (value,keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;
const counterValid = value => Number.isSafeInteger(value) && value >= 0;
const futureExpiry = (value,at,ttl) => Number.isSafeInteger(value) && value > at && value <= at+ttl;
const credentialValid = value => exact(value,'counter,id,publicKey,transports') &&
  typeof value.id === 'string' && /^[A-Za-z0-9_-]{16,4096}$/.test(value.id) &&
  typeof value.publicKey === 'string' && /^[A-Za-z0-9_-]{32,8192}$/.test(value.publicKey) &&
  counterValid(value.counter) && Array.isArray(value.transports) && value.transports.length <= 10 &&
  value.transports.every(t => typeof t === 'string' && ['usb','nfc','ble','smart-card','hybrid','internal'].includes(t));

async function active(tx,id) {
  if (!validId(id)) return false;
  const member = await tx.get(`member:${id}`);
  return member?.state === 'active' && member.role !== 'bot';
}

async function removeSessions(tx,id) {
  let after;
  for (;;) {
    const rows = await tx.scan(`authsession:${id}:`,{limit:1000,...(after ? {after} : {})});
    for (const {key,value} of rows) {
      await tx.delete(key);
      const indexKey = `authtoken:${value.token_hash}`;
      if ((await tx.get(indexKey))?.device_id === id) await tx.delete(indexKey);
    }
    if (rows.length < 1000) return;
    after = rows.at(-1).key;
  }
}

// Called within the same transaction as a member revoke or phone replacement.
export async function revokeDeviceAuthTx(tx,id) {
  if (!validId(id)) return;
  const credential = await tx.get(credentialKey(id));
  if (credential) {
    const indexKey = credentialOwnerKey(credential.credential_id);
    if ((await tx.get(indexKey))?.device_id === id) await tx.delete(indexKey);
    await tx.delete(credentialKey(id));
  }
  for (const purpose of ['enroll','unlock']) await tx.delete(`authchallenge:${id}:${purpose}`);
  await removeSessions(tx,id);
}

// Evaluate the clock when the gate is called, including after a transaction
// retry; never accept a session using a timestamp cached by the HTTP handler.
export async function unlockCheckTx(tx,id,token,at=Date.now()) {
  if (!Number.isSafeInteger(at) || !await active(tx,id)) return false;
  if (!await tx.get(credentialKey(id))) return true;
  if (!validId(token)) return false;
  const hash = sha(token), session = await tx.get(`authsession:${id}:${hash}`);
  return session?.device_id === id && session.token_hash === hash && session.expires > at;
}

export function createDeviceAuthStore(db,{now=Date.now}={}) {
  if (typeof db?.transaction !== 'function' || typeof now !== 'function') throw new Error('Auth store configuration missing');
  const transaction = action => db.transaction(tx => {
    const at = now();
    if (!Number.isSafeInteger(at) || at <= 0) throw new Error('Clock unavailable');
    return action(tx,at);
  });
  const putSession = async (tx,id,hash,expires) => {
    const value = {device_id:id,token_hash:hash,expires};
    await tx.put(`authsession:${id}:${hash}`,value,expires);
    await tx.put(`authtoken:${hash}`,value,expires);
  };
  return {
    accept(id,nonce,issued,card,signingSpki) {
      return transaction(async (tx,at) => {
        if (!await active(tx,id)) return 'denied';
        const result = await acceptTeamRequest(tx,{deviceId:id,nonce,op:'status',issued,card,signingSpki},at);
        return result === 'replay' ? 'conflict' : result;
      });
    },
    status(id) {
      return transaction(async tx => await active(tx,id) ? {enabled:!!await tx.get(credentialKey(id))} : null);
    },
    credential(id) {
      return transaction(async tx => {
        if (!await active(tx,id)) return null;
        const c = await tx.get(credentialKey(id));
        return c ? {id:c.credential_id,publicKey:c.public_key,counter:c.counter,transports:c.transports} : null;
      });
    },
    challengePut(id,purpose,challenge,expires) {
      return transaction(async (tx,at) => {
        if (!await active(tx,id) || !purposeValid(purpose) || typeof challenge !== 'string' ||
            !/^[A-Za-z0-9_-]{32,128}$/.test(challenge) || !futureExpiry(expires,at,300000)) return 'denied';
        if ((purpose === 'enroll') === !!await tx.get(credentialKey(id))) return 'conflict';
        await tx.put(`authchallenge:${id}:${purpose}`,{device_id:id,purpose,challenge,expires},expires);
        return 'ok';
      });
    },
    challengeTake(id,purpose) {
      return transaction(async (tx,at) => {
        if (!await active(tx,id) || !purposeValid(purpose)) return null;
        const key = `authchallenge:${id}:${purpose}`, row = await tx.get(key);
        await tx.delete(key);
        return row?.expires > at ? row.challenge : null;
      });
    },
    enroll(id,credential,tokenHash,expires) {
      return transaction(async (tx,at) => {
        if (!await active(tx,id) || !validHash(tokenHash) || !futureExpiry(expires,at,600000) || !credentialValid(credential)) return 'denied';
        if (await tx.get(credentialKey(id)) || await tx.get(credentialOwnerKey(credential.id)) || await tx.get(`authtoken:${tokenHash}`)) return 'conflict';
        await tx.put(credentialKey(id),{device_id:id,credential_id:credential.id,public_key:credential.publicKey,
          counter:credential.counter,transports:credential.transports,created_at:at});
        await tx.put(credentialOwnerKey(credential.id),{device_id:id});
        await putSession(tx,id,tokenHash,expires);
        return 'ok';
      });
    },
    unlock(id,credentialId,oldCounter,newCounter,tokenHash,expires) {
      return transaction(async (tx,at) => {
        if (!await active(tx,id) || !validHash(tokenHash) || !futureExpiry(expires,at,600000) ||
            !counterValid(oldCounter) || !counterValid(newCounter)) return 'denied';
        const row = await tx.get(credentialKey(id));
        if (!row || row.credential_id !== credentialId || row.counter !== oldCounter ||
            ((row.counter > 0 || newCounter > 0) && newCounter <= row.counter)) return 'conflict';
        const tokenOwner = await tx.get(`authtoken:${tokenHash}`);
        if (tokenOwner && tokenOwner.device_id !== id) return 'conflict';
        await tx.put(credentialKey(id),{...row,counter:newCounter});
        await removeSessions(tx,id);
        await putSession(tx,id,tokenHash,expires);
        return 'ok';
      });
    },
    unlockCheck(id,token) { return transaction((tx,at) => unlockCheckTx(tx,id,token,at)); },
    reset(adminId,id,token) {
      return transaction(async (tx,at) => {
        if (!await isAdmin(tx,adminId)) return 'denied';
        if (!await unlockCheckTx(tx,adminId,token,at)) return 'locked';
        const member = validId(id) ? await tx.get(`member:${id}`) : null;
        if (!member || member.role === 'bot') return 'denied';
        await revokeDeviceAuthTx(tx,id);
        return 'ok';
      });
    },
  };
}
