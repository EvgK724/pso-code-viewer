import test from 'node:test';
import assert from 'node:assert/strict';
import {MessageChannel} from 'node:worker_threads';
import {installReleaseNotices,releaseCapability} from '../docs/release-notices.mjs';

test('release capability requires a live worker handshake; legacy and malformed responses fail closed',async()=>{
  assert.equal(await releaseCapability(null),0);
  assert.equal(await releaseCapability({postMessage(){}},{Channel:MessageChannel,timeoutMs:5}),0);
  const worker={postMessage(data,ports){assert.deepEqual(data,{type:'PSO_GET_RELEASE_CAPABILITY'});ports[0].postMessage({type:'PSO_RELEASE_CAPABILITY',notificationsVersion:1});}};
  assert.equal(await releaseCapability(worker,{Channel:MessageChannel}),1);
  assert.equal(await releaseCapability({postMessage(data,ports){ports[0].postMessage({type:'PSO_RELEASE_CAPABILITY',notificationsVersion:1,url:'https://other.example'});}},{Channel:MessageChannel}),0);
});

test('release checks skip nonhuman/inactive devices, register capability, throttle and announce each newer release once',async()=>{
  let active=false,time=1000000,calls=0,checks=0,version=18;
  const notices=[];
  const client=installReleaseNotices({navigator:{onLine:true,serviceWorker:{controller:{}}},document:{},isEligible:()=>active,now:()=>time,capability:async()=>1,
    request:async data=>{calls++;assert.deepEqual(data,{clientVersion:17,notificationsVersion:1});return {version,updateAvailable:version>17};},
    onAvailable:v=>notices.push(v),checkUpdate:()=>{checks++;}});
  await client.check();assert.equal(calls,0);
  active=true;await client.check();assert.deepEqual(notices,[18]);assert.equal(checks,1);
  await client.check();assert.equal(calls,1);
  await client.check(true);assert.equal(calls,2);assert.deepEqual(notices,[18]);
  version=19;time+=300001;await client.check();assert.deepEqual(notices,[18,19]);
  active=false;await client.check(true);assert.equal(calls,3);
});

test('only current-worker release clicks trigger the banner and update check without touching the draft',async()=>{
  const listeners=new Map(),worker={},draft={text:'Неотправленный текст'},notices=[];
  let requests=0,checks=0;
  const nav={serviceWorker:{controller:worker,addEventListener:(type,fn)=>listeners.set(type,fn)}};
  installReleaseNotices({navigator:nav,document:{},isEligible:()=>true,capability:async()=>1,
    request:async()=>{requests++;return {version:18,updateAvailable:true};},onAvailable:v=>notices.push(v),checkUpdate:()=>{checks++;}});
  const receive=listeners.get('message');
  receive({source:{},data:{type:'PSO_RELEASE_AVAILABLE',version:18}});assert.equal(checks,0);
  receive({source:worker,data:{type:'PSO_RELEASE_AVAILABLE',version:17}});assert.equal(checks,0);
  receive({source:worker,data:{type:'PSO_RELEASE_AVAILABLE',version:18}});
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(notices,[18]);assert.equal(checks,1);assert.equal(requests,1);assert.equal(draft.text,'Неотправленный текст');
});

test('offline and failed or inconsistent release responses do not break the application',async()=>{
  const nav={onLine:false};let calls=0;
  const client=installReleaseNotices({navigator:nav,document:{},isEligible:()=>true,capability:async()=>0,request:async()=>{calls++;throw new Error('offline');},onAvailable:()=>assert.fail('unexpected release')});
  await client.check(true);assert.equal(calls,0);nav.onLine=true;await client.check(true);assert.equal(calls,1);
  const invalid=installReleaseNotices({navigator:{},document:{},isEligible:()=>true,capability:async()=>0,request:async()=>({version:18,updateAvailable:false}),onAvailable:()=>assert.fail('inconsistent response')});
  await invalid.check();
});
