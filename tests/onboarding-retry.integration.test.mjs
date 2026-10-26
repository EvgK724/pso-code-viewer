import test from 'node:test';
import assert from 'node:assert/strict';
import {createMemoryDatabase} from '../server/yandex/test-db.mjs';
import {createTeamStore} from '../server/yandex/team-store.mjs';
import {createDirectStore} from '../server/yandex/direct-store.mjs';
import {createTeamHandler} from '../server/team-handler.mjs';
import {createDirectHandler} from '../server/direct-handler.mjs';
import {makeDevice} from '../docs/crypto.mjs';
import {exportPublicCard,importPublicCard} from '../docs/exchange.mjs';
import {TeamClient} from '../docs/team.mjs';
import {DirectClient} from '../docs/direct.mjs';
import {makeRecipientGrant,verifyRecipientGrant} from '../docs/recipient-trust.mjs';

const origin='https://viewer.example';

test('one onboarding action recovers lost committed replies without duplicate members or changed grants',async()=>{
  const db=createMemoryDatabase(),admin=await makeDevice(),doctor=await makeDevice();
  const adminCard=await exportPublicCard(admin,'ТЕСТ ОРГАНИЗАТОР');
  const owner=await importPublicCard(adminCard);
  await db.seed('member:'+owner.id,{device_id:owner.id,name:owner.name,role:'admin',state:'active',card:adminCard,
    signing_spki:Buffer.from(await crypto.subtle.exportKey('spki',owner.signingPublicKey)).toString('base64url'),
    created_at:Date.now(),approved_at:Date.now(),revoked_at:null,invite_hash:null,approval_proof:null});
  const teamStore={...createTeamStore(db),keys:async()=>null};
  const directStore={...createDirectStore(db),keys:async()=>null,unlockCheck:async()=>false};
  const teamHandler=createTeamHandler({store:teamStore,allowedOrigin:origin});
  const directHandler=createDirectHandler({store:directStore,allowedOrigin:origin});
  const lost=new Set(['invite','claim','approve','admin_certify']),seen=new Map();
  const fetcher=async(url,options)=>{
    const {envelope}=JSON.parse(options.body);
    const history=seen.get(envelope.op)||[];history.push(envelope);seen.set(envelope.op,history);
    const handle=url.endsWith('/pso-team')?teamHandler:directHandler;
    const response=await handle(new Request(url,{...options,headers:{...options.headers,Origin:origin}}));
    if(lost.has(envelope.op)&&history.length===1){
      assert.equal(response.status,200,'fault is injected only AFTER a successful committed operation');
      await response.text();
      return new Response('{"error":"request_rejected"}',{status:503,headers:{'Content-Type':'application/json'}});
    }
    return response;
  };
  const options={fetch:fetcher,sleep:async()=>{},random:()=>0};
  const team=new TeamClient(origin+'/api/pso-team',options),direct=new DirectClient(origin+'/api/pso-direct',options);
  const invitation=await team.invite(admin,'ТЕСТ КАРДИОЛОГ','cardiologist');
  assert.equal((await team.claim(doctor,invitation.id)).state,'pending');
  const [pending]=await team.pending(admin);
  assert.equal(pending.name,'ТЕСТ КАРДИОЛОГ');
  assert.equal((await team.change(admin,'approve',pending.id)).state,'active');
  const proof=await makeRecipientGrant(admin,pending);
  await direct.certify(admin,pending.id,proof);
  const members=await direct.members(admin);
  assert.equal(members.length,2);
  assert.equal(members.filter(m=>m.state==='pending').length,0);
  const active=members.find(m=>m.id===pending.id);
  assert.equal(active.state,'active');
  assert.equal((await verifyRecipientGrant(active,owner)).role,'cardiologist');
  assert.equal((await team.status(doctor)).state,'active');
  assert.equal([...db.dump().keys()].filter(k=>k.startsWith('invite:')).length,1);
  for(const op of lost){
    const requests=seen.get(op);assert.equal(requests.length,2,op+' has one bounded recovery');
    assert.deepEqual(requests[0].data,requests[1].data,op+' retains the exact intended action');
    assert.notEqual(requests[0].nonce,requests[1].nonce,op+' uses a fresh signed nonce');
  }
  await team.change(admin,'revoke',pending.id);
  const calls=seen.get('admin_certify').length;
  await assert.rejects(direct.certify(admin,pending.id,proof),e=>e.status===403);
  assert.equal(seen.get('admin_certify').length,calls+1,'revoked access is never retried');
  assert.equal((await team.status(doctor)).state,'revoked');
});
