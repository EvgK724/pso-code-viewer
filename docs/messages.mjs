// Recipient-specific wrapped keys for a single encrypted message/photo payload.
// Public identities must be approved by the caller before seal/open; the server
// can verify signatures without having either the AES key or patient plaintext.
import {deviceIdentity, importPublicCard} from './exchange.mjs';

export const MAX_PHOTO_BYTES = 1024 * 1024;
export const MAX_MESSAGE_PLAINTEXT_BYTES = 1420000;
export const MAX_MESSAGE_CIPHERTEXT_CHARS = Math.ceil((MAX_MESSAGE_PLAINTEXT_BYTES + 16) * 4 / 3);
export const MAX_MESSAGE_TTL = 86400000;
export const MESSAGE_SIGN_DOMAIN = 'PSO-MESSAGE-v2\0';
export const MESSAGE_KEY_LABEL = 'PSO-MESSAGE-KEY-v2';
const enc = new TextEncoder(), dec = new TextDecoder('utf-8', {fatal:true});
const GROUPS = ['cardiology','orit'], KINDS = ['admission','review','reply'];
const BAD = /[\p{Cc}\p{Cf}]/u;
const exact = (v,k) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join(',') === k;

export function messageBase64url(value) {
  const bytes = new Uint8Array(value); let binary = '';
  // Do not spread photo-sized buffers into a single function call.
  for (let i=0;i<bytes.length;i+=8192) binary += String.fromCharCode(...bytes.subarray(i,i+8192));
  return btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
export function messageUnbase64url(value, expected=0, max=MAX_MESSAGE_CIPHERTEXT_CHARS) {
  if (typeof value !== 'string' || !value || value.length > max || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Некорректная зашифрованная запись.');
  let result;
  try { const s=value.replace(/-/g,'+').replace(/_/g,'/'); result=Uint8Array.from(atob(s+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0)); }
  catch { throw new Error('Некорректная зашифрованная запись.'); }
  if ((expected && result.length !== expected) || messageBase64url(result) !== value) throw new Error('Некорректная зашифрованная запись.');
  return result;
}
function metaValue(meta,now) {
  if (!exact(meta,meta?.kind==='reply'?'expires,group,id,issued,kind,replyTo,v':'expires,group,id,issued,kind,v') || meta.v !== 2 || !GROUPS.includes(meta.group) || !KINDS.includes(meta.kind)) throw new Error('Неверные параметры сообщения.');
  messageUnbase64url(meta.id,16,22);
  if(meta.kind==='reply'){messageUnbase64url(meta.replyTo,16,22);if(meta.replyTo===meta.id)throw new Error('Ответ не может ссылаться на себя.');}
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(meta.issued) || !Number.isSafeInteger(meta.expires) || meta.issued <= 0 || meta.expires <= meta.issued || meta.expires-meta.issued > MAX_MESSAGE_TTL || meta.expires-meta.issued < 60000 || meta.issued > now+30000 || meta.expires <= now) throw new Error('Срок сообщения истёк или время создания неверно.');
  return {v:2,id:meta.id,group:meta.group,kind:meta.kind,issued:meta.issued,expires:meta.expires,...(meta.kind==='reply'?{replyTo:meta.replyTo}:{})};
}
export function validateMessagePayload(payload,now=Date.now()) {
  if (!exact(payload,payload?.kind==='reply'?'ciphertext,expires,group,id,issued,iv,kind,replyTo,v':'ciphertext,expires,group,id,issued,iv,kind,v')) throw new Error('Неверный формат зашифрованного сообщения.');
  const meta=metaValue({v:payload.v,id:payload.id,group:payload.group,kind:payload.kind,issued:payload.issued,expires:payload.expires,...(payload.kind==='reply'?{replyTo:payload.replyTo}:{})},now);
  messageUnbase64url(payload.iv,12,16);
  const bytes=messageUnbase64url(payload.ciphertext,0,MAX_MESSAGE_CIPHERTEXT_CHARS);
  if (bytes.length < 16 || bytes.length > MAX_MESSAGE_PLAINTEXT_BYTES+16) throw new Error('Зашифрованное сообщение слишком большое.');
  return {...meta,iv:payload.iv,ciphertext:payload.ciphertext};
}
export async function messagePayloadHash(payload,now=Date.now()) {
  const valid=validateMessagePayload(payload,now);
  return messageBase64url(await crypto.subtle.digest('SHA-256',enc.encode(JSON.stringify(valid))));
}
function surnameValue(value) {
  if (typeof value !== 'string' || BAD.test(value)) throw new Error('Неверная фамилия.');
  const s=value.normalize('NFC').trim().replace(/ +/g,' ').replace(/[\u2010\u2011]/g,'-');
  const shape=/^[\p{L}][\p{L}\p{M}]*(?:[ '\u2019\u02BC-][\p{L}][\p{L}\p{M}]*)*$/u;
  if ([...s].length>80 || (s && (!shape.test(s) || [...s].some(c=>/\p{L}/u.test(c)&&!/[\p{Script=Latin}\p{Script=Cyrillic}]/u.test(c))))) throw new Error('Фамилия: до 80 букв кириллицы или латиницы.');
  return s;
}
function commentValue(value) {
  if (typeof value !== 'string' || /[\p{Cf}\u0000-\u0008\u000b-\u001f\u007f-\u009f]/u.test(value)) throw new Error('Неверный комментарий.');
  const s=value.normalize('NFC').trim();
  if ([...s].length > 2000) throw new Error('Комментарий: не более 2000 символов.');
  return s;
}
// Walk every scan, not only the first SOS: progressive JPEGs may contain
// ancillary metadata between scans. Return exact spans for metadata removal.
export function inspectJPEGStructure(bytes,{rejectMetadata=false}={}) {
  if(!(bytes instanceof Uint8Array)||bytes.length<4||bytes[0]!==255||bytes[1]!==216)throw new Error('Повреждённый JPEG.');
  const bad=()=>{throw new Error('Повреждённый JPEG.');};
  let offset=2,dimensions=null,sawScan=false,entropy=false;
  const segments=[{start:0,end:2,marker:0xd8}];
  const sof=new Set([0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf]);
  while(offset<bytes.length){
    if(segments.length>10000)bad();
    if(entropy){
      const start=offset;
      while(offset<bytes.length){
        if(bytes[offset]!==255){offset++;continue;}
        let next=offset+1;while(bytes[next]===255)next++;
        const marker=bytes[next];
        if(marker===0||(marker>=0xd0&&marker<=0xd7)){offset=next+1;continue;}
        break;
      }
      if(offset>start)segments.push({start,end:offset,marker:null});
      if(offset>=bytes.length)bad();entropy=false;
    }
    const start=offset;
    if(bytes[offset++]!==255)bad();while(bytes[offset]===255)offset++;
    if(offset>=bytes.length)bad();
    const marker=bytes[offset++];
    if(marker===0xd8||marker===0||(marker>=0xd0&&marker<=0xd7))bad();
    if(rejectMetadata&&(marker===0xfe||(marker>=0xe1&&marker<=0xef&&marker!==0xee)))throw new Error('Фото содержит служебные данные. Подготовьте его заново.');
    if(marker===0xd9){
      if(!dimensions||!sawScan||offset!==bytes.length)bad();
      segments.push({start,end:offset,marker});return {...dimensions,segments};
    }
    if(marker===0x01){segments.push({start,end:offset,marker});continue;}
    if(offset+2>bytes.length)bad();
    const length=(bytes[offset]<<8)|bytes[offset+1];
    if(length<2||offset+length>bytes.length)bad();
    if(sof.has(marker)){
      if(length<8||dimensions||sawScan)bad();
      const next={height:(bytes[offset+3]<<8)|bytes[offset+4],width:(bytes[offset+5]<<8)|bytes[offset+6]};
      if(!next.width||!next.height)throw new Error('Неверный размер JPEG.');
      dimensions=next;
    }
    if(marker===0xda){if(!dimensions||length<6)bad();sawScan=true;entropy=true;}
    offset+=length;segments.push({start,end:offset,marker});
  }
  bad();
}
export function jpegDimensions(bytes,options={}) {
  const {width,height}=inspectJPEGStructure(bytes,options);return {width,height};
}
export function validateMessagePhoto(photo) {
  if (photo === null) return null;
  if (!exact(photo,'data,height,mime,width') || photo.mime !== 'image/jpeg' || !Number.isSafeInteger(photo.width) || !Number.isSafeInteger(photo.height) || photo.width<1 || photo.height<1 || photo.width>2000 || photo.height>2000) throw new Error('Неверный формат фотографии.');
  const bytes=messageUnbase64url(photo.data,0,Math.ceil(MAX_PHOTO_BYTES*4/3));
  if(bytes.length>MAX_PHOTO_BYTES || bytes.length<4 || bytes[0]!==255 || bytes[1]!==216 || bytes[bytes.length-2]!==255 || bytes[bytes.length-1]!==217) throw new Error('Фотография должна быть JPEG размером до 1 МБ.');
  const dimensions=jpegDimensions(bytes,{rejectMetadata:true});
  if(dimensions.width!==photo.width || dimensions.height!==photo.height)throw new Error('Размер фотографии не совпадает с описанием.');
  return {mime:'image/jpeg',data:photo.data,width:photo.width,height:photo.height};
}
function contentValue(content,kind) {
  if(!exact(content,'comment,department,photo,surname'))throw new Error('Неверный формат содержания сообщения.');
  const surname=surnameValue(content.surname),comment=commentValue(content.comment),photo=validateMessagePhoto(content.photo);
  if(!['','ПСО','ОРИТ'].includes(content.department))throw new Error('Неизвестное отделение.');
  if(kind==='admission' && !surname)throw new Error('Для поступления требуется фамилия.');
  if(!surname&&!comment&&!photo)throw new Error('Добавьте фамилию, комментарий или фото.');
  return {surname,department:content.department,comment,photo};
}
async function checkedContact(contact,requireVerified=true) {
  if(requireVerified && contact?.verified !== true) throw new Error('Получатель или отправитель не подтверждён.');
  const card=await importPublicCard(contact?.card);
  if(card.id!==contact.id || (contact.fingerprint && card.fingerprint!==contact.fingerprint)) throw new Error('Ключ контакта изменился.');
  // Use keys imported from the approved card, not mutable parallel fields.
  return {...card,name:contact.name || card.name};
}
export function inspectMessageToken(token) {
  if(typeof token!=='string' || token.length>1000)throw new Error('Неверный код сообщения.');
  const p=token.split('.');if(p.length!==6 || p[0]!=='PSO2')throw new Error('Неизвестный формат сообщения.');
  messageUnbase64url(p[1],32,43);messageUnbase64url(p[2],32,43);
  const wrappedKey=messageUnbase64url(p[3],384,512),hash=messageUnbase64url(p[4],32,43),signature=messageUnbase64url(p[5],64,86);
  return {recipientId:p[1],senderId:p[2],wrappedKey,payloadHash:p[4],hash,signature,signedBytes:enc.encode(MESSAGE_SIGN_DOMAIN+p.slice(0,5).join('.'))};
}
export async function verifyMessageEnvelope(token,payload,sender,now=Date.now()) {
  const p=inspectMessageToken(token),verifiedSender=await checkedContact(sender,false);
  if(p.senderId!==verifiedSender.id || p.payloadHash!==await messagePayloadHash(payload,now) || !await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},verifiedSender.signingPublicKey,p.signature,p.signedBytes))throw new Error('Подпись сообщения не подтверждена.');
  return p;
}
export async function sealMessage(device,recipients,content,meta) {
  const at=Date.now(),m=metaValue({v:2,...meta},at),value=contentValue({surname:'',department:'',comment:'',photo:null,...content},m.kind);
  if(!Array.isArray(recipients)||recipients.length<1||recipients.length>25)throw new Error('Выберите от 1 до 25 получателей.');
  const verified=await Promise.all(recipients.map(c=>checkedContact(c)));
  if(new Set(verified.map(c=>c.id)).size!==verified.length)throw new Error('Получатели повторяются.');
  const sender=await deviceIdentity(device),keyBytes=crypto.getRandomValues(new Uint8Array(32)),iv=crypto.getRandomValues(new Uint8Array(12));
  const plaintext=enc.encode(JSON.stringify(value));
  if(plaintext.length>MAX_MESSAGE_PLAINTEXT_BYTES){plaintext.fill(0);keyBytes.fill(0);throw new Error('Сообщение слишком большое.');}
  try {
    const key=await crypto.subtle.importKey('raw',keyBytes,{name:'AES-GCM'},false,['encrypt']);
    const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(JSON.stringify(m)),tagLength:128},key,plaintext);
    const payload={...m,iv:messageBase64url(iv),ciphertext:messageBase64url(ciphertext)},hash=await messagePayloadHash(payload,at);
    const entries=await Promise.all(verified.map(async recipient=>{
      const wrapped=messageBase64url(await crypto.subtle.encrypt({name:'RSA-OAEP',label:enc.encode(MESSAGE_KEY_LABEL)},recipient.encryptionPublicKey,keyBytes));
      const unsigned=['PSO2',recipient.id,sender.id,wrapped,hash].join('.');
      const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},device.signing.privateKey,enc.encode(MESSAGE_SIGN_DOMAIN+unsigned));
      return {recipientId:recipient.id,token:unsigned+'.'+messageBase64url(signature)};
    }));
    return {payload,entries};
  } finally {keyBytes.fill(0);plaintext.fill(0);}
}
export async function openMessage(device,token,payload,contactsArray,now=Date.now()) {
  const p=inspectMessageToken(token),own=await deviceIdentity(device);
  if(p.recipientId!==own.id)throw new Error('Сообщение предназначено другому получателю или телефону.');
  const sender=Array.isArray(contactsArray)?contactsArray.find(c=>c?.id===p.senderId&&c.verified===true):null;
  if(!sender)throw new Error('Отправитель не подтверждён.');
  const verifiedSender=await checkedContact(sender),m=validateMessagePayload(payload,now);
  await verifyMessageEnvelope(token,m,verifiedSender,now);
  let keyBytes,plaintext,data;
  try {
    keyBytes=new Uint8Array(await crypto.subtle.decrypt({name:'RSA-OAEP',label:enc.encode(MESSAGE_KEY_LABEL)},device.encryption.privateKey,p.wrappedKey));
    if(keyBytes.length!==32)throw new Error('key');
    const key=await crypto.subtle.importKey('raw',keyBytes,{name:'AES-GCM'},false,['decrypt']);
    const aad=metaValue({v:m.v,id:m.id,group:m.group,kind:m.kind,issued:m.issued,expires:m.expires,...(m.kind==='reply'?{replyTo:m.replyTo}:{})},now);
    plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:messageUnbase64url(m.iv,12),additionalData:enc.encode(JSON.stringify(aad)),tagLength:128},key,messageUnbase64url(m.ciphertext));
    data=JSON.parse(dec.decode(plaintext));
    const value=contentValue(data,m.kind);
    if(JSON.stringify(value)!==JSON.stringify(data))throw new Error('noncanonical');
    return {...value,messageId:m.id,kind:m.kind,group:m.group,issued:m.issued,expires:m.expires,...(m.kind==='reply'?{replyTo:m.replyTo}:{}),senderName:verifiedSender.name,code:'ПСО-'+m.id};
  } catch {throw new Error('Не удалось расшифровать или проверить содержание сообщения.');}
  finally {if(keyBytes)keyBytes.fill(0);if(plaintext)new Uint8Array(plaintext).fill(0);}
}
