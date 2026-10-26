import test from 'node:test';
import assert from 'node:assert/strict';
import {makeDevice} from '../docs/crypto.mjs';
import {deviceIdentity} from '../docs/exchange.mjs';
import {createApiQueue,runApiRequest,readApiError,apiDiagnosticText} from '../docs/api-queue.mjs';
import {TeamClient,randomTeamID} from '../docs/team.mjs';
import {DirectClient} from '../docs/direct.mjs';
import {PushClient} from '../docs/push.mjs';
import {DeviceUnlockClient} from '../docs/device-unlock.mjs';

const device=await makeDevice(),id=(await deviceIdentity(device)).id;
const reply=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});
const endpoint='https://viewer.example/api/';
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
const immediate=()=>new Promise(resolve=>setImmediate(resolve));

test('all API clients wait for a slow server response without aborting or replaying it',async t=>{
  t.mock.timers.enable({apis:['setTimeout']});
  const cases=[
    [options=>new TeamClient(endpoint+'team',options),client=>client.request(device,'approve',{deviceId:id}),{state:'active'}],
    [options=>new DirectClient(endpoint+'direct',options),client=>client.request(device,'admin_certify',{deviceId:id}),{status:'ok'}],
    [options=>new PushClient(endpoint+'push',options),client=>client.status(device),{status:'disabled'}],
    [options=>new DeviceUnlockClient(endpoint+'auth',options),client=>client.status(device),{enabled:false}]
  ];
  for(const [create,request,body] of cases){
    const started=deferred(),hold=deferred();let signal,calls=0;
    const client=create({fetch:async(_url,options)=>{
      calls++;signal=options.signal;started.resolve();
      await hold.promise;return reply(body);
    }});
    const pending=request(client);await started.promise;
    // Connection (10s), shared DB deadline (45s), cleanup and network transit.
    t.mock.timers.tick(65000);
    assert.equal(signal.aborted,false);
    hold.resolve();await pending;
    assert.equal(calls,1);
  }
});

test('FIFO serializes work, and a failed item does not stop the next item',async()=>{
  const queue=createApiQueue(),hold=deferred(),started=deferred(),order=[];
  const first=queue(async()=>{order.push('one');started.resolve();await hold.promise;throw new Error('first failed');});
  const rejected=assert.rejects(first,/first failed/);
  const second=queue(async()=>{order.push('two');return 2;});
  await started.promise;assert.deepEqual(order,['one']);hold.resolve();
  await rejected;assert.equal(await second,2);assert.deepEqual(order,['one','two']);
});

test('all four API clients share one queue; signatures and timeouts start after waiting',async()=>{
  const hold=deferred(),started=deferred(),requests=[];let clock=1800000000000,clockCalls=0;
  const now=()=>{clockCalls++;return clock;};
  function fetcher(label,body){return async(_url,options)=>{
    const envelope=JSON.parse(options.body).envelope;
    requests.push({label,envelope,aborted:options.signal.aborted});
    if(label==='team'){started.resolve();await hold.promise;}
    return reply(body);
  };}
  const team=new TeamClient(endpoint+'team',{now,timeout:1000,fetch:fetcher('team',{state:'unregistered',name:null,role:null})});
  const direct=new DirectClient(endpoint+'direct',{now,timeout:20,fetch:fetcher('direct',{members:[]})});
  const push=new PushClient(endpoint+'push',{now,timeout:20,fetch:fetcher('push',{status:'disabled'})});
  const auth=new DeviceUnlockClient(endpoint+'auth',{now,timeout:20,fetch:fetcher('auth',{enabled:false})});
  const first=team.status(device);await started.promise;
  const rest=[direct.request(device,'directory'),push.status(device),auth.status(device)];
  await new Promise(resolve=>setTimeout(resolve,35));
  assert.equal(clockCalls,1);assert.equal(requests.length,1);
  clock+=120000;hold.resolve();await first;await Promise.all(rest);
  assert.deepEqual(requests.map(r=>r.label),['team','direct','push','auth']);
  for(const r of requests.slice(1)){assert.equal(r.envelope.issued,clock);assert.equal(r.aborted,false);}
});

test('onboarding retries use fresh signatures/nonces and immutable action data',async()=>{
  const requests=[],delays=[];let clock=1800000000000;
  const client=new TeamClient(endpoint+'team',{now:()=>clock,sleep:async ms=>{delays.push(ms);clock+=ms;},random:()=>0.5,
    fetch:async(_url,o)=>{const e=JSON.parse(o.body).envelope;requests.push(e);return requests.length<3?reply({},503):reply({state:'active'});}});
  const action={deviceId:id},pending=client.request(device,'approve',action);action.deviceId='changed-after-call';
  assert.deepEqual(await pending,{state:'active'});
  assert.deepEqual(delays,[600,1200]);assert.equal(new Set(requests.map(r=>r.nonce)).size,3);
  assert.equal(new Set(requests.map(r=>r.signature)).size,3);
  assert.deepEqual(requests.map(r=>r.issued),[1800000000000,1800000000600,1800000001800]);
  for(const e of requests)assert.deepEqual(e.data,{deviceId:id});
});

test('invite retry preserves invitation ID and normalizes the doctor name to NFC',async()=>{
  const requests=[];
  const client=new TeamClient(endpoint+'team',{sleep:async()=>{},random:()=>0,
    fetch:async(_url,o)=>{const e=JSON.parse(o.body).envelope;requests.push(e);return requests.length===1?reply({},502):reply({id:e.data.id,expires:Date.now()+60000});}});
  const invite=await client.invite(device,'Андреи\u0306','neurologist');
  assert.equal(requests.length,2);assert.equal(requests[0].data.id,invite.id);assert.equal(requests[1].data.id,invite.id);
  assert.equal(requests[0].data.name,'Андрей');assert.deepEqual(requests[0].data,requests[1].data);
});

test('certify retries keep the same proof; replacing a device is never retried',async()=>{
  const proof={grant:{subjectId:id,issued:1},signature:'synthetic'},requests=[];
  const client=new DirectClient(endpoint+'direct',{sleep:async()=>{},random:()=>0,
    fetch:async(_url,o)=>{const e=JSON.parse(o.body).envelope;requests.push(e);return requests.length<3?reply({},504):reply({status:'ok'});}});
  const action=client.certify(device,id,proof);proof.signature='mutated';await action;
  assert.equal(requests.length,3);assert.equal(new Set(requests.map(e=>e.nonce)).size,3);
  for(const e of requests)assert.equal(e.data.approvalProof.signature,'synthetic');
  let replacements=0;
  const replace=new DirectClient(endpoint+'direct',{sleep:async()=>{},fetch:async()=>{replacements++;return reply({},503);}});
  await assert.rejects(replace.replace(device,id,id,proof),e=>e.status===503);assert.equal(replacements,1);
});

test('permanent errors never retry, and transient retries stop after three attempts',async()=>{
  for(const status of [400,403,404,409,413,415,429,500]){
    let calls=0,delays=0;
    const options={sleep:async()=>{delays++;},fetch:async()=>{calls++;return reply({},status);}};
    await assert.rejects(new TeamClient(endpoint+'team',options).change(device,'approve',id),e=>e.status===status);
    assert.equal(calls,1);assert.equal(delays,0);
    calls=0;
    await assert.rejects(new DirectClient(endpoint+'direct',options).certify(device,id,{}),e=>e.status===status);
    assert.equal(calls,1);assert.equal(delays,0);
  }
  let calls=0;
  const client=new TeamClient(endpoint+'team',{sleep:async()=>{},fetch:async()=>{calls++;return reply({},503);}});
  await assert.rejects(client.change(device,'approve',id),e=>e.status===503&&/HTTP 503/.test(e.message));assert.equal(calls,3);
});

test('network interruption and timeout retry onboarding, but invalid JSON and reads do not',async()=>{
  for(const name of ['TypeError','AbortError']){
    let calls=0;
    const client=new TeamClient(endpoint+'team',{sleep:async()=>{},fetch:async()=>{
      if(++calls===1){if(name==='TypeError')throw new TypeError('private network detail');const e=new Error('private detail');e.name=name;throw e;}
      return reply({state:'pending'});
    }});
    assert.equal((await client.claim(device,randomTeamID())).state,'pending');assert.equal(calls,2);
  }
  let calls=0;
  const bad=new TeamClient(endpoint+'team',{sleep:async()=>{},fetch:async()=>{calls++;return new Response('invalid-json',{headers:{'Content-Type':'application/json'}});}});
  await assert.rejects(bad.claim(device,randomTeamID()));assert.equal(calls,1);
  calls=0;
  const read=new TeamClient(endpoint+'team',{sleep:async()=>{},fetch:async()=>{calls++;return reply({},503);}});
  await assert.rejects(read.status(device));assert.equal(calls,1);
});

test('retry backoff does not occupy the shared queue',async()=>{
  const started=deferred(),hold=deferred();let calls=0;
  const first=runApiRequest(async()=>{if(++calls===1){const e=new Error('transient');e.status=503;throw e;}return 'retried';},
    {retry:true,sleep:async()=>{started.resolve();await hold.promise;}});
  await started.promise;
  assert.equal(await runApiRequest(async()=>'other'),'other');hold.resolve();assert.equal(await first,'retried');
});

test('error diagnostics retain only safe codes and clock errors give an actionable explanation',async()=>{
  const body={error:'request_rejected',message:'private patient',diagnostic:{stage:'approve',code:'database_conflict',status:400100,cause:'private SQL'}};
  const details=await readApiError(reply(body,503));
  assert.deepEqual(details,{code:'request_rejected',diagnostic:{stage:'approve',code:'database_conflict',status:400100}});
  assert.equal(apiDiagnosticText(details),' [approve/database_conflict · 400100]');
  for(const diagnostic of [{stage:'private SQL',code:'database_conflict',status:400100},{stage:'approve',code:'private patient',status:400100}])
    assert.deepEqual(await readApiError(reply({...body,diagnostic},503)),{code:'request_rejected'});
  assert.deepEqual(await readApiError(reply({error:'private patient'},503)),{code:''});
  assert.deepEqual(await readApiError(reply({error:'clock_skew',padding:'x'.repeat(2500)},400)),{code:''});
  const clock=new TeamClient(endpoint+'team',{fetch:async()=>reply({error:'clock_skew'},400)});
  await assert.rejects(clock.change(device,'approve',id),e=>e.status===400&&/дату и время/.test(e.message)&&e.code==='clock_skew');
});

test('WebAuthn user prompt does not hold the network queue',async()=>{
  const promptStarted=deferred(),promptDone=deferred();
  const b64=n=>Buffer.alloc(n,3).toString('base64url');
  const client=new DeviceUnlockClient(endpoint+'auth',{credentials:{get:async()=>{promptStarted.resolve();await promptDone.promise;throw new Error('cancel');}},
    fetch:async(_url,o)=>JSON.parse(o.body).envelope.op==='status'?reply({enabled:true}):reply({options:{challenge:b64(32),userVerification:'required'}})});
  const operation=client.ensure(device),cancelled=assert.rejects(operation,/не подтверждён/);
  await promptStarted.promise;
  let ran=false;await runApiRequest(async()=>{ran=true;});assert.equal(ran,true);
  promptDone.resolve();await cancelled;await immediate();
});
