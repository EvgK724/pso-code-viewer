// Same-origin Cloud Functions HTTP adapter. No trust in a caller-supplied URL,
// no arbitrary file access, no API caching, no plaintext/request logging.
import {readFile} from 'node:fs/promises';
const MAX_BODY=2100000;
const files=['index.html','styles.css','app.mjs','api-queue.mjs','updates.mjs','direct.mjs','messages.mjs','photos.mjs','device-unlock.mjs','recipient-trust.mjs','crypto.mjs','exchange.mjs','storage.mjs','sharing.mjs','push.mjs','team.mjs','shortlinks.mjs','shortlink-config.mjs','manifest.webmanifest','sw.js','icon-pso-v2-192.png','icon-pso-v2-512.png','apple-touch-icon-pso-v2.png','favicon-pso-v2.png','icon-192.png','icon-512.png','apple-touch-icon.png','robots.txt'];
const APIs=new Set(['pso-team','pso-direct','pso-push','pso-device-auth']);
export function validateOrigin(value) {
  const u=new URL(value);
  if(u.protocol!=='https:'||u.origin!==value||u.username||u.password||!u.hostname.includes('.')||u.hostname==='functions.yandexcloud.net')throw new Error('Dedicated HTTPS origin required');
  return u.origin;
}
const security={
 'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
 'Permissions-Policy':'geolocation=(), microphone=(), camera=(self)','Strict-Transport-Security':'max-age=31536000'
};
export function jsonReply(statusCode,value){return {statusCode,headers:{...security,'Content-Type':'application/json; charset=utf-8'},isBase64Encoded:false,body:JSON.stringify(value)};}
const reject=(code=400)=>jsonReply(code,{error:'request_rejected'});
export function createHttpRouter({allowedOrigin,handlers,assets=new URL('../../docs/',import.meta.url)}) {
 const origin=validateOrigin(allowedOrigin),host=new URL(origin).host;
 const policy="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
 const cached=new Map();
 async function asset(name){
  if(!cached.has(name))cached.set(name,(async()=>{
   let data=await readFile(new URL(name,assets));
   if(name==='shortlink-config.mjs'){
    data=Buffer.from(`export const SHORTLINK_ENDPOINT = '';\n`+[['PUSH_ENDPOINT','pso-push'],['TEAM_ENDPOINT','pso-team'],['DIRECT_ENDPOINT','pso-direct'],['DEVICE_AUTH_ENDPOINT','pso-device-auth']].map(([key,path])=>`export const ${key} = ${JSON.stringify(origin+'/api/'+path)};`).join('\n'));
   }else if(name==='index.html'){
    const html=data.toString('utf8'),pattern=/<meta\s+http-equiv=["']Content-Security-Policy["']\s+content=(["'])(.*?)\1\s*\/?\s*>/gis;
    if([...html.matchAll(pattern)].length!==1)throw new Error('CSP missing');
    data=Buffer.from(html.replace(pattern,`<meta http-equiv="Content-Security-Policy" content="${policy.replace(/; frame-ancestors 'none'/,'')}">`));
  }else if(name==='sw.js')data=Buffer.from(data.toString('utf8').replace('github-v21-install-help','yandex-v12-install-help'));
   else if(name==='manifest.webmanifest'){
    const manifest=JSON.parse(data);Object.assign(manifest,{id:'./',start_url:'./',scope:'./'});data=Buffer.from(JSON.stringify(manifest));
   }
   return data;
  })().catch(e=>{cached.delete(name);throw e;}));
  return cached.get(name);
 }
 return async event=>{
  try{
   if(!event||typeof event!=='object'||typeof event.httpMethod!=='string')return reject();
   // Only the configured gateway host may serve this origin-bound application.
   const headers=new Headers();
   for(const [key,value]of Object.entries(event.headers||{})){
    if(typeof value!=='string'||headers.has(key))return reject();headers.set(key,value);
   }
   for(const [key,values]of Object.entries(event.multiValueHeaders||{})){
    if(!Array.isArray(values)||values.length!==1||typeof values[0]!=='string'||(headers.has(key)&&headers.get(key)!==values[0]))return reject();headers.set(key,values[0]);
   }
   if(headers.get('host')!==host)return reject(403);
   const path=event.path,method=event.httpMethod.toUpperCase();
   if(typeof path!=='string'||!/^\/[A-Za-z0-9._/-]*$/.test(path)||path.includes('//')||path.split('/').some(p=>p==='.'||p==='..'))return reject();
   const query=Object.keys(event.queryStringParameters||{}).length||Object.keys(event.multiValueQueryStringParameters||{}).length;
   const api=path.startsWith('/api/'),route=path.slice(5);
   if(api){
    if(query||!APIs.has(route)||!['POST','OPTIONS'].includes(method))return reject(APIs.has(route)?400:404);
    if(typeof event.body!=='string'&&event.body!=null)return reject();
    let data;
    if(event.isBase64Encoded===true){
     const s=event.body||'';if(s.length>Math.ceil(MAX_BODY/3)*4||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))return reject(413);
     data=Buffer.from(s,'base64');
    }else data=Buffer.from(event.body||'','utf8');
    if(data.length>MAX_BODY)return reject(413);
    headers.delete('content-length');headers.delete('transfer-encoding');
    const request=new Request(origin+path,{method,headers,...(data.length?{body:data}:{}),redirect:'error'});
    const handler=handlers[route];if(typeof handler!=='function')return reject(503);
    const response=await handler(request);
    return {statusCode:response.status,headers:{...Object.fromEntries(response.headers),...security},isBase64Encoded:false,body:await response.text()};
   }
   if(!['GET','HEAD'].includes(method)||query)return reject(404);
   const name=path==='/'?'index.html':path.slice(1);
   if(!files.includes(name))return reject(404);
   const data=await asset(name),ext=name.split('.').at(-1);
   const type={html:'text/html; charset=utf-8',mjs:'text/javascript; charset=utf-8',js:'text/javascript; charset=utf-8',css:'text/css; charset=utf-8',png:'image/png',webmanifest:'application/manifest+json',txt:'text/plain; charset=utf-8'}[ext];
   return {statusCode:200,headers:{...security,'Cache-Control':'no-cache','Content-Type':type,'Content-Security-Policy':policy,...(name==='sw.js'?{'Service-Worker-Allowed':'/'}:{})},isBase64Encoded:true,body:method==='HEAD'?'':data.toString('base64')};
  }catch{return reject(503);}
 };
}
