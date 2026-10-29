import test from 'node:test';
import assert from 'node:assert/strict';
import {installAppUpdates} from '../docs/updates.mjs';

class Events {
  constructor(extra={}) { Object.assign(this,extra); this.listeners=new Map(); }
  addEventListener(type, callback) { const set=this.listeners.get(type)||new Set(); set.add(callback);this.listeners.set(type,set); }
  removeEventListener(type, callback) { this.listeners.get(type)?.delete(callback); }
  emit(type) { for(const callback of this.listeners.get(type)||[]) callback(); }
}
const flush = () => new Promise(resolve=>setImmediate(resolve));
function setup({existing=true,update=async()=>{},online=true,timeoutMs=100,register=async registration=>registration}={}) {
  const statuses=[],registrations=[];let readyCount=0,time=100000,calls=0;
  const registration=new Events({installing:null,waiting:null,update:async()=>{calls++;return update(registration);}});
  const serviceWorker=new Events({controller:existing?{}:null,ready:Promise.resolve(registration),register:async(...args)=>{registrations.push(args);return register(registration,registrations.length);}});
  const navigator={serviceWorker,onLine:online};const document=new Events({hidden:false});
  const manager=installAppUpdates({navigator,document,onStatus:s=>statuses.push(s),onReady:()=>readyCount++,now:()=>time,timeoutMs});
  return {manager,registration,serviceWorker,navigator,document,statuses,registrations,readyCount:()=>readyCount,calls:()=>calls,setTime:t=>{time=t;}};
}
test('registration bypasses HTTP cache and explicitly checks; ready returns registration',async()=>{
  const h=setup();assert.equal(await h.manager.ready,h.registration);await h.manager.check();
  assert.deepEqual(h.registrations,[['./sw.js',{updateViaCache:'none'}]]);assert.equal(h.calls(),1);
  assert.equal(h.statuses.at(-1),'current');assert.equal(h.readyCount(),0);
});
test('an installed update announces readiness without reloading or clearing storage',async()=>{
  const worker=new Events({state:'installing'});
  const h=setup({update:async r=>{r.installing=worker;r.emit('updatefound');}});
  await h.manager.ready;await flush();
  worker.state='activated';worker.emit('statechange');h.serviceWorker.emit('controllerchange');
  await h.manager.check();assert.equal(h.readyCount(),1);assert.equal(h.statuses.at(-1),'ready');
});
test('first installation does not masquerade as an update',async()=>{
  const worker=new Events({state:'installing'});
  const h=setup({existing:false,update:async r=>{r.installing=worker;}});
  await h.manager.ready;await flush();worker.state='activated';worker.emit('statechange');h.serviceWorker.emit('controllerchange');
  await h.manager.check();assert.equal(h.readyCount(),0);assert.equal(h.statuses.at(-1),'current');
});
test('first installation establishes a baseline for a later update in the same page',async()=>{
  let worker=new Events({state:'installing'});
  const h=setup({existing:false,update:async r=>{r.installing=worker;r.emit('updatefound');}});
  await h.manager.ready;await flush();
  h.serviceWorker.controller=worker;h.serviceWorker.emit('controllerchange');
  worker.state='activated';worker.emit('statechange');await h.manager.check();
  assert.equal(h.readyCount(),0);assert.equal(h.statuses.at(-1),'current');
  worker=new Events({state:'installing'});const secondCheck=h.manager.check();await flush();
  worker.state='activated';worker.emit('statechange');
  h.serviceWorker.controller=worker;h.serviceWorker.emit('controllerchange');await secondCheck;
  assert.equal(h.readyCount(),1);assert.equal(h.statuses.at(-1),'ready');
});
test('onReady runs before the ready status callback',async()=>{
  const sw=new Events({controller:{},ready:Promise.resolve({}),register:async()=>new Events({update:async()=>{}})});
  let ready=false;
  const h=installAppUpdates({navigator:{serviceWorker:sw,onLine:true},document:new Events({hidden:false}),onReady:()=>{ready=true;},onStatus:s=>{if(s==='ready')assert.equal(ready,true);}});
  await h.check();sw.controller={};sw.emit('controllerchange');assert.equal(ready,true);
});
test('automatic foreground checks are throttled, manual checks are not',async()=>{
  const h=setup();await h.manager.check();h.document.emit('visibilitychange');await flush();assert.equal(h.calls(),1);
  h.document.hidden=true;h.setTime(200001);h.document.emit('visibilitychange');await flush();assert.equal(h.calls(),1);
  h.document.hidden=false;h.document.emit('visibilitychange');await flush();assert.equal(h.calls(),2);
  await h.manager.check();assert.equal(h.calls(),3);
});
test('offline checks show status, do not update and recover manually',async()=>{
  const h=setup({online:false});await h.manager.ready;assert.equal(h.calls(),0);assert.equal(h.statuses.at(-1),'offline');
  h.navigator.onLine=true;await h.manager.check();assert.equal(h.calls(),1);assert.equal(h.statuses.at(-1),'current');
});
test('a stuck installation times out and can still announce activation later',async()=>{
  const worker=new Events({state:'installing'});const h=setup({timeoutMs:5,update:async r=>{r.installing=worker;}});
  await h.manager.check();assert.equal(h.statuses.at(-1),'failed');
  worker.state='activated';worker.emit('statechange');assert.equal(h.readyCount(),1);assert.equal(h.statuses.at(-1),'ready');
});
test('network failure leaves keys usable and permits another manual check',async()=>{
  let failed=true;const h=setup({update:async()=>{if(failed)throw Error('offline');}});
  await h.manager.check();assert.equal(h.statuses.at(-1),'failed');failed=false;await h.manager.check();assert.equal(h.statuses.at(-1),'current');
});
test('a rejected installation is not reported as current',async()=>{
  const worker=new Events({state:'installing'});const h=setup({update:async r=>{r.installing=worker;}});
  await h.manager.ready;await flush();worker.state='redundant';worker.emit('statechange');
  await h.manager.check();assert.equal(h.readyCount(),0);assert.equal(h.statuses.at(-1),'failed');
});


test('initial registration failure reports download failure and manual retry recovers both checking and push readiness',async()=>{
  const h=setup({register:async(registration,attempt)=>{if(attempt===1)throw new Error('SW download failed');return registration;}});
  const initialReady=h.manager.ready,initialCheck=h.manager.check();
  await assert.rejects(initialReady,/SW download failed/);await initialCheck;
  assert.equal(h.statuses.at(-1),'failed');assert.equal(h.registrations.length,1);assert.equal(h.calls(),0);
  const retry=h.manager.check();assert.notEqual(h.manager.ready,initialReady);await retry;
  assert.equal(await h.manager.ready,h.registration);assert.equal(h.statuses.at(-1),'current');assert.equal(h.registrations.length,2);assert.equal(h.calls(),1);
  await h.manager.check();assert.equal(h.registrations.length,2);assert.equal(h.calls(),2);
});

test('foreground retry after a failed registration shares a single new registration with manual checks',async()=>{
  let release;const h=setup({register:async(registration,attempt)=>{if(attempt===1)throw Error('offline');await new Promise(resolve=>release=resolve);return registration;}});
  await h.manager.check();assert.equal(h.statuses.at(-1),'failed');h.setTime(200001);h.document.emit('visibilitychange');await flush();
  const first=h.manager.check(),second=h.manager.check();assert.equal(first,second);assert.equal(h.registrations.length,2);release();await first;
  assert.equal(await h.manager.ready,h.registration);assert.equal(h.statuses.at(-1),'current');assert.equal(h.calls(),1);
});

test('only a missing service-worker registration API reports unsupported',async()=>{
  for(const navigator of [{onLine:true},{serviceWorker:{},onLine:false}]){
    const statuses=[];const manager=installAppUpdates({navigator,document:new Events(),onStatus:s=>statuses.push(s)});
    await assert.rejects(manager.ready,/unavailable/);await manager.check();assert.equal(statuses.at(-1),'unsupported');assert.ok(!statuses.includes('failed'));
  }
});
