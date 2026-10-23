// Authenticated team directory and per-recipient encrypted group links.
// Only the server assigns roles; invitations merely request administrator review.
import {exportPublicCard, importPublicCard} from './exchange.mjs';
const DOMAIN='PSO-TEAM-v1\0', enc=new TextEncoder();
const ROLES=['admin','neurologist','intensivist','cardiologist','bot'];
const ID=/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/, LINK=/^[A-Za-z0-9_-]{21}[AQgw]$/;
const b64=x=>btoa(String.fromCharCode(...new Uint8Array(x))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===k;
const text=v=>typeof v==='string'&&v.trim()===v&&v.length>0&&[...v].length<=60&&!/[\p{Cc}\p{Cf}]/u.test(v);
export function randomTeamID(){return b64(crypto.getRandomValues(new Uint8Array(16)));}
export function joinIDFromInput(input,base){
  const value=String(input).trim();
  let url;try{url=new URL(value,base);}catch{return null;}
  const own=new URL('./',base);
  if(url.origin!==own.origin||![own.pathname,own.pathname+'index.html'].includes(url.pathname)||url.search||url.username||url.password)return null;
  const id=url.hash.startsWith('#join=')?url.hash.slice(6):'';return LINK.test(id)?id:null;
}
export async function teamEnvelope(device,op,data={},issued=Date.now()){
  if(!['status','directory','invite','claim','pending','approve','revoke','create','resolve'].includes(op)||!Number.isSafeInteger(issued))throw new Error('Неверный запрос команды.');
  const card=await exportPublicCard(device,'Устройство');
  const unsigned={v:1,op,issued,nonce:randomTeamID(),card,data};
  const signature=b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},device.signing.privateKey,enc.encode(DOMAIN+JSON.stringify(unsigned))));
  return {...unsigned,signature};
}
export class TeamError extends Error {constructor(message,status){super(message);this.status=status;}}
export class TeamClient {
  constructor(endpoint,{fetch:fetcher=globalThis.fetch.bind(globalThis),timeout=15000,now=Date.now}={}){
    const u=new URL(endpoint);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw new Error('Неверный адрес команды.');
    this.endpoint=u.href;this.fetcher=fetcher;this.timeout=timeout;this.now=now;
  }
  async request(device,op,data={}){
    const envelope=await teamEnvelope(device,op,data,this.now());
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),this.timeout);
    try{
      const r=await this.fetcher(this.endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({envelope}),credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',redirect:'error',signal:controller.signal});
      if(!r.ok){const messages={403:'Этот телефон не имеет доступа. Проверьте подключение у администратора.',404:'Ссылка не найдена или срок её действия истёк.',409:'Состав команды изменился или приглашение уже использовано. Обновите подключение и повторите.',429:'Слишком много запросов. Повторите немного позже.'};throw new TeamError(messages[r.status]||'Сервис команды недоступен. Повторите позже.',r.status);}
      if(!r.headers.get('content-type')?.startsWith('application/json'))throw new Error('Неверный ответ команды.');
      const reader=r.body?.getReader();if(!reader)throw new Error('Не удалось проверить ответ команды.');
      let bytes=0,body='';const decoder=new TextDecoder('utf-8',{fatal:true});
      try{for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>1000000){await reader.cancel();throw new Error('Ответ команды слишком большой.');}body+=decoder.decode(value,{stream:true});}body+=decoder.decode();return JSON.parse(body);}finally{reader.releaseLock();}
    }catch(e){if(e.name==='AbortError'||e instanceof TypeError||e instanceof SyntaxError)throw new Error('Нет связи с командой. Проверьте интернет.');throw e;}finally{clearTimeout(timer);}
  }
  async status(device){const r=await this.request(device,'status');if(!exact(r,'name,role,state')||!['active','pending','unregistered','revoked'].includes(r.state)||!(r.role===null||ROLES.includes(r.role))||!(r.name===null||text(r.name)))throw new Error('Не удалось проверить подключение.');return r;}
  async members(device,op='directory'){
    const r=await this.request(device,op);if(!exact(r,'members')||!Array.isArray(r.members)||r.members.length>100)throw new Error('Не удалось проверить состав команды.');
    const members=[],ids=new Set();for(const v of r.members){if(!exact(v,'card,id,name,role')||!ID.test(v.id)||!text(v.name)||!ROLES.includes(v.role)||ids.has(v.id))throw new Error('Не удалось проверить состав команды.');const c=await importPublicCard(v.card);if(c.id!==v.id)throw new Error('Ключ врача не совпадает с подключением.');ids.add(v.id);members.push({...c,name:v.name,role:v.role,verified:true});}return members;
  }
  directory(device){return this.members(device);}
  pending(device){return this.members(device,'pending');}
  async invite(device,name,role){if(!text(name)||!['neurologist','intensivist','cardiologist','bot'].includes(role))throw new Error('Укажите имя и специальность.');const id=randomTeamID(),r=await this.request(device,'invite',{name,role,id});if(!exact(r,'expires,id')||r.id!==id||!Number.isSafeInteger(r.expires)||r.expires<=this.now())throw new Error('Приглашение не подтверждено.');return r;}
  async claim(device,id){if(!LINK.test(id))throw new Error('Приглашение неполное.');const r=await this.request(device,'claim',{id});if(!exact(r,'state')||!['pending','active'].includes(r.state))throw new Error('Заявка не подтверждена.');return r;}
  async change(device,op,deviceId){if(!['approve','revoke'].includes(op)||!ID.test(deviceId))throw new Error('Неверное подключение.');const r=await this.request(device,op,{deviceId});if(!exact(r,'state')||!['active','revoked'].includes(r.state))throw new Error('Изменение не подтверждено.');return r;}
  async create(device,{group,ttlMinutes,entries},base){
    if(!['cardiology','orit'].includes(group)||!Number.isSafeInteger(ttlMinutes)||ttlMinutes<1||ttlMinutes>1440||!Array.isArray(entries)||!entries.length||entries.length>25)throw new Error('Проверьте получателей и срок ссылки.');
    const id=randomTeamID(),issued=this.now(),expires=issued+ttlMinutes*60000;
    const r=await this.request(device,'create',{id,group,kind:'review',issued,expires,entries});
    if(!exact(r,'expires,id,push')||r.id!==id||r.expires!==expires||!['accepted','partial','unavailable'].includes(r.push))throw new Error('Создание ссылки не подтверждено.');
    const link=new URL('./',base);link.hash='r='+id;return {...r,link:link.href};
  }
  async resolve(device,id){
    if(!LINK.test(id))throw new Error('Ссылка неполная.');const r=await this.request(device,'resolve',{id});
    if(!exact(r,'expires,senderCard,senderName,token')||!Number.isSafeInteger(r.expires)||r.expires<=this.now()||!text(r.senderName)||typeof r.token!=='string')throw new Error('Не удалось проверить запись.');
    const sender=await importPublicCard(r.senderCard),parts=r.token.split('.');
    if(parts.length!==5||parts[0]!=='PSO1'||parts[2]!==sender.id)throw new Error('Отправитель записи не совпадает с ключом.');
    return {token:r.token,expires:r.expires,sender:{...sender,name:r.senderName,verified:true}};
  }
}
