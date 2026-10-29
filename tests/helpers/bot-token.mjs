// Synthetic PSO1 tokens for JS integration/security tests. Production bot
// encryption stays in Python/OpenSSL; this helper is never deployed.
import {deviceIdentity,importPublicCard} from '../../docs/exchange.mjs';
const enc=new TextEncoder(),DOMAIN='PSO-SURNAME-LINK-v1';
const b64=value=>Buffer.from(value).toString('base64url');

export async function signBotPayload(device,recipient,value){
  const own=await deviceIdentity(device),target=await importPublicCard(typeof recipient==='string'?recipient:recipient.card);
  const cipher=await crypto.subtle.encrypt({name:'RSA-OAEP',label:enc.encode(DOMAIN)},target.encryptionPublicKey,enc.encode(JSON.stringify(value)));
  const unsigned=['PSO1',target.id,own.id,b64(cipher)].join('.');
  const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},device.signing.privateKey,enc.encode(DOMAIN+'\0'+unsigned));
  return unsigned+'.'+b64(signature);
}

export function sealBoundBotToken(device,recipient,meta,{surname='Тестов',department='ПСО'}={}){
  return signBotPayload(device,recipient,{n:surname,d:department,j:meta.id,i:meta.issued,x:meta.expires,g:meta.group});
}
