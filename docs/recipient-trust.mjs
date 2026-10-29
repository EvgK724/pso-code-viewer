// An administrator's signature authorizes a specific device key and role.
// The administrator key MUST be pinned from an independently verified source;
// a directory response is never a source of trust. These public certificates
// do not replace the server's current-state/revocation checks.
import {deviceIdentity, exportPublicCard, importPublicCard} from './exchange.mjs';

export const RECIPIENT_GRANT_DOMAIN = 'PSO-RECIPIENT-GRANT-v1\0';
export const MAX_GRANT_TTL = 365 * 24 * 60 * 60 * 1000;
import {ROLES} from './care-routing.mjs';
const enc = new TextEncoder();
const scope = encodeURIComponent(new URL('./', import.meta.url).pathname);
const PIN_KEY = 'pso-organizer-pin-v1-' + scope;
const exact = (v, keys) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join(',') === keys;
const b64 = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');

function failure() { throw new Error('Допуск врача не подтверждён организатором. Обновите подключение у организатора.'); }
function unb64(value, length) {
  if (typeof value !== 'string' || value.length !== Math.ceil(length * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) failure();
  let result;
  try { const s=value.replace(/-/g,'+').replace(/_/g,'/'); result=Uint8Array.from(atob(s+'='.repeat((4-s.length%4)%4)), c=>c.charCodeAt(0)); }
  catch { failure(); }
  if(result.length!==length || b64(result)!==value) failure();
  return result;
}
function label(value) {
  if (typeof value !== 'string' || value !== value.normalize('NFC').trim() || !value || [...value].length>60 || /[\p{Cc}\p{Cf}]/u.test(value)) failure();
  return value;
}
function canonicalGrant(value, now) {
  if (!exact(value,'expires,issued,issuerId,name,role,subjectId,v') || value.v!==1 || !ROLES.includes(value.role)) failure();
  unb64(value.subjectId,32); unb64(value.issuerId,32); label(value.name);
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(value.issued) || !Number.isSafeInteger(value.expires) ||
      value.issued<=0 || value.issued>now+30000 || value.expires<=now || value.expires<=value.issued || value.expires-value.issued>MAX_GRANT_TTL) failure();
  if (value.role==='admin' && value.subjectId!==value.issuerId) failure();
  return {v:1,subjectId:value.subjectId,role:value.role,name:value.name,issued:value.issued,expires:value.expires,issuerId:value.issuerId};
}
async function organizerCard(value) {
  const card = typeof value === 'string' ? value : value?.card;
  if (!card) throw new Error('Сначала подтвердите ключ организатора по его приглашению.');
  return importPublicCard(card);
}
function storageOrThrow(storage) {
  try {
    const value=storage || globalThis.localStorage;
    if (!value || typeof value.getItem!=='function' || typeof value.setItem!=='function') throw new Error();
    return value;
  } catch { throw new Error('Не удалось открыть хранилище доверенного ключа организатора.'); }
}

export async function makeRecipientGrant(device, member, {now=Date.now(),ttlMs=MAX_GRANT_TTL}={}) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs<60000 || ttlMs>MAX_GRANT_TTL) failure();
  const subject=await importPublicCard(member?.card), issuer=await deviceIdentity(device);
  if (subject.id!==member?.id) failure();
  const grant=canonicalGrant({v:1,subjectId:subject.id,role:member.role,name:member.name,issued:now,expires:now+ttlMs,issuerId:issuer.id},now);
  const signature=b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},device.signing.privateKey,enc.encode(RECIPIENT_GRANT_DOMAIN+JSON.stringify(grant))));
  return {grant,signature,issuerCard:await exportPublicCard(device,'Организатор')};
}

export async function verifyRecipientGrant(member, pinnedOrganizerCard, now=Date.now()) {
  const root=await organizerCard(pinnedOrganizerCard);
  const proof=member?.approvalProof;
  if (!exact(proof,'grant,issuerCard,signature')) failure();
  const grant=canonicalGrant(proof.grant,now), signature=unb64(proof.signature,64);
  const issuer=await importPublicCard(proof.issuerCard), subject=await importPublicCard(member.card);
  if (issuer.id!==root.id || grant.issuerId!==root.id || grant.subjectId!==subject.id || member.id!==subject.id ||
      member.role!==grant.role || member.name!==grant.name) failure();
  if (!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},root.signingPublicKey,signature,enc.encode(RECIPIENT_GRANT_DOMAIN+JSON.stringify(grant)))) failure();
  return {...subject,name:grant.name,role:grant.role,approvalProof:proof,verified:true};
}

export async function verifyRecipientDirectory(members,pinnedOrganizerCard,now=Date.now()) {
  if (!Array.isArray(members) || members.length>100) failure();
  const parsed=[],seen=new Set();
  for (const member of members) {
    const checked=await verifyRecipientGrant(member,pinnedOrganizerCard,now);
    if (seen.has(checked.id)) failure();
    seen.add(checked.id); parsed.push(checked);
  }
  return parsed;
}

export async function loadOrganizerCard({storage}={}) {
  const store=storageOrThrow(storage);
  let raw;
  try { raw=store.getItem(PIN_KEY); } catch { throw new Error('Не удалось прочитать доверенный ключ организатора.'); }
  if(raw===null) return null;
  let value;
  try { value=JSON.parse(raw); } catch { throw new Error('Сохранённый ключ организатора повреждён.'); }
  if(!exact(value,'card,pinnedAt,v') || value.v!==1 || !Number.isSafeInteger(value.pinnedAt) || value.pinnedAt<=0) throw new Error('Сохранённый ключ организатора повреждён.');
  return {...await importPublicCard(value.card),verified:true};
}

export async function pinOrganizerCard(card,{confirmed=false,replace=false,storage,now=Date.now()}={}) {
  if(confirmed!==true) throw new Error('Подтвердите ключ организатора по известному вам каналу.');
  if(!Number.isSafeInteger(now) || now<=0) failure();
  const parsed=await organizerCard(card), store=storageOrThrow(storage);
  const previous=await loadOrganizerCard({storage:store});
  if(previous && previous.id!==parsed.id && replace!==true) throw new Error('Ключ организатора изменился. Необходимо отдельное подтверждение замены.');
  // Only public key material is stored here. It grants no decryption access.
  try { store.setItem(PIN_KEY,JSON.stringify({v:1,card:parsed.card,pinnedAt:now})); }
  catch { throw new Error('Не удалось сохранить доверенный ключ организатора.'); }
  return {...parsed,verified:true};
}

export async function trustedInvitationURL(base,id,card) {
  unb64(id,16);
  const root=await organizerCard(card), url=new URL('./',base);
  if(url.protocol!=='https:' || url.username || url.password || url.search) throw new Error('Неверный адрес просмотрщика.');
  // Keep the complete invitation in one URL-safe token. A literal card prefix
  // followed by a dot can be split from its payload by messenger link previews.
  // The envelope carries the same public card; it does not establish trust.
  url.hash='invite='+b64(enc.encode(JSON.stringify({v:1,id,organizer:root.card})));
  return url.href;
}

// Short invitations commit to the exact public card received from the organizer.
// Fetching that card from the server does not pin it or authorize this device.
export async function shortTrustedInvitationURL(base,id,card) {
  const idBytes=unb64(id,16),root=await organizerCard(card),url=new URL('./',base);
  if(root.card!==(typeof card==='string'?card:card?.card)) throw new Error('Карточка организатора повреждена.');
  if(url.protocol!=='https:' || url.username || url.password || url.search) throw new Error('Неверный адрес просмотрщика.');
  const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(root.card)));
  const token=new Uint8Array(48);token.set(idBytes);token.set(digest,16);
  url.hash='i='+b64(token);
  return url.href;
}

export function parseShortInvitation(input,base) {
  if(typeof input!=='string' || input.length>12000) return null;
  try {
    const url=new URL(input.trim(),base),own=new URL('./',base);
    if(url.protocol!=='https:' || url.origin!==own.origin || ![own.pathname,own.pathname+'index.html'].includes(url.pathname) || url.search || url.username || url.password || !/^#i=[A-Za-z0-9_-]{64}$/.test(url.hash)) return null;
    const token=unb64(url.hash.slice(3),48);
    return {id:b64(token.slice(0,16)),organizerHash:b64(token.slice(16))};
  } catch { return null; }
}

export async function verifyShortInvitation(input,base,info,{now=Date.now()}={}) {
  const reference=parseShortInvitation(input,base);
  if(!reference || !exact(info,'expires,id,organizerCard') || info.id!==reference.id ||
     !Number.isSafeInteger(now) || !Number.isSafeInteger(info.expires) || info.expires<=now ||
     typeof info.organizerCard!=='string') throw new Error('Приглашение недоступно или срок его действия истёк.');
  const root=await importPublicCard(info.organizerCard);
  if(root.card!==info.organizerCard || b64(await crypto.subtle.digest('SHA-256',enc.encode(root.card)))!==reference.organizerHash)
    throw new Error('Содержимое приглашения не совпадает со ссылкой. Попросите организатора отправить новое приглашение.');
  return {id:reference.id,organizerCard:root.card,fingerprint:root.fingerprint};
}

export async function parseTrustedInvitation(input,base) {
  if(typeof input!=='string' || input.length>12000) return null;
  try {
    const url=new URL(input.trim(),base), own=new URL('./',base);
    if(url.protocol!=='https:' || url.origin!==own.origin || ![own.pathname,own.pathname+'index.html'].includes(url.pathname) || url.search || url.username || url.password) return null;
    const values=new URLSearchParams(url.hash.slice(1));
    const keys=[...values.keys()].sort().join(',');
    let id,card;
    if(keys==='invite') {
      const token=values.get('invite');
      const bytes=unb64(token,Math.floor(token.length*3/4));
      const payload=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
      if(!exact(payload,'id,organizer,v') || payload.v!==1) return null;
      id=payload.id;card=payload.organizer;
    } else if(keys==='join,organizer') {
      // Complete invitations already sent by an earlier version remain valid.
      id=values.get('join');card=values.get('organizer');
    } else return null;
    const root=await importPublicCard(card);
    unb64(id,16);
    return {id,organizerCard:root.card,fingerprint:root.fingerprint};
  } catch { return null; }
}
