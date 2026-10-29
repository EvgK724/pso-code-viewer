import test from 'node:test';
import assert from 'node:assert/strict';
import {createHttpRouter,validateOrigin} from './http.mjs';
const origin='https://example.apigw.yandexcloud.net';
const event=(path,extra={})=>({path,httpMethod:'GET',headers:{host:new URL(origin).host},...extra});
test('static shell is scoped to one HTTPS origin and has no foreign broker',async()=>{
 const router=createHttpRouter({allowedOrigin:origin,handlers:{}});
 for(const path of ['/','/api-queue.mjs','/shortlink-config.mjs','/sw.js','/manifest.webmanifest','/icon-pso-v2-192.png','/fonts/pso-comic-cyrillic.woff2','/fonts/Pangolin-OFL.txt']){
  const r=await router(event(path));assert.equal(r.statusCode,200);assert.equal(r.headers['X-Frame-Options'],'DENY');
  if(path.endsWith('.woff2')){assert.equal(r.headers['Content-Type'],'font/woff2');assert.equal(Buffer.from(r.body,'base64').subarray(0,4).toString(),'wOF2');assert.match(r.headers['Content-Security-Policy'],/font-src 'self';/);}
  if(path==='/shortlink-config.mjs'){const code=Buffer.from(r.body,'base64').toString();assert(!code.includes('supabase'));assert(code.includes(origin+'/api/pso-direct'));}
 }
 const html=Buffer.from((await router(event('/'))).body,'base64').toString();assert(!html.includes('spugfikalpihorcwcdqc'));assert.match(html,/font-src 'self';/);
});
test('reject path, duplicate origin, spoofed host and setup commands over HTTP',async()=>{
 let calls=0;const router=createHttpRouter({allowedOrigin:origin,handlers:{'pso-direct':()=>{calls++;return new Response('{}');}}});
 for(const e of [event('/../connection.json'),event('/%2e%2e/connection.json'),event('/server/yandex/entry.mjs'),event('/',{headers:{host:'evil.example'}}),event('/api/maintenance',{httpMethod:'POST',body:'{"action":"bootstrap"}'})])assert.notEqual((await router(e)).statusCode,200);
 assert.equal(calls,0);
});
test('HTTP adapter preserves exact origin and bounds API bytes',async()=>{
 let request;const router=createHttpRouter({allowedOrigin:origin,handlers:{'pso-direct':r=>{request=r;return new Response('{"ok":true}',{headers:{'Cache-Control':'public'}});}}});
 const r=await router(event('/api/pso-direct',{httpMethod:'POST',headers:{host:new URL(origin).host,origin,'content-type':'application/json'},body:'{}'}));
 assert.equal(r.statusCode,200);assert.equal(r.headers['Cache-Control'],'no-store');assert.equal(request.headers.get('origin'),origin);assert.equal(await request.text(),'{}');
 assert.equal((await router(event('/api/pso-direct',{httpMethod:'POST',body:'a'.repeat(2100001)}))).statusCode,413);
 assert.equal((await router(event('/api/pso-direct',{httpMethod:'POST',queryStringParameters:{x:'y'}}))).statusCode,400);
});
test('shared Cloud Functions origin cannot host an isolated key store',()=>assert.throws(()=>validateOrigin('https://functions.yandexcloud.net')));
