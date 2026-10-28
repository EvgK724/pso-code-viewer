import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,webcrypto} from 'node:crypto';
import {makeDevice} from '../docs/crypto.mjs';
import {deviceIdentity,exportPublicCard} from '../docs/exchange.mjs';
import {TeamClient} from '../docs/team.mjs';
import {shortTrustedInvitationURL,parseShortInvitation,verifyShortInvitation} from '../docs/recipient-trust.mjs';
import {createTeamHandler} from '../server/team-handler.mjs';
import {createTeamStore} from '../server/yandex/team-store.mjs';
import {createMemoryDatabase} from '../server/yandex/test-db.mjs';

if(!globalThis.crypto)globalThis.crypto=webcrypto;

test('short invitation survives a lost create response, verifies without consuming, and enrolls only after explicit claim and approval',async()=>{
  const now=Date.now(),origin='https://viewer.example',endpoint=origin+'/api/pso-team';
  const [admin,doctor]=await Promise.all([makeDevice(),makeDevice()]);
  const [organizer,recipient]=await Promise.all([deviceIdentity(admin),deviceIdentity(doctor)]);
  const organizerCard=await exportPublicCard(admin,'Организатор');
  const db=createMemoryDatabase({now:()=>now}),store=createTeamStore(db,{now:()=>now});
  const signingSpki=Buffer.from(await crypto.subtle.exportKey('spki',admin.signing.publicKey)).toString('base64url');
  await db.seed('member:'+organizer.id,{device_id:organizer.id,name:'Организатор',role:'admin',state:'active',
    card:organizerCard,signing_spki:signingSpki,invite_hash:null,created_at:now,approved_at:now,revoked_at:null,approval_proof:null});
  const handler=createTeamHandler({store:{...store,keys:async()=>{throw new Error('Unexpected push setup');}},allowedOrigin:origin,now:()=>now});
  const envelopes=[];let loseFirstCreateResponse=true;
  const client=new TeamClient(endpoint,{now:()=>now,sleep:async()=>{},random:()=>0,fetch:async(url,options)=>{
    const {envelope}=JSON.parse(options.body);envelopes.push(envelope);
    const response=await handler(new Request(url,{...options,headers:{...options.headers,Origin:origin}}));
    if(envelope.op==='invite'&&loseFirstCreateResponse&&response.ok){
      loseFirstCreateResponse=false;
      throw new TypeError('Synthetic lost response after committed creation');
    }
    return response;
  }});

  const created=await client.invite(admin,'Врач','cardiologist',organizerCard);
  const attempts=envelopes.filter(e=>e.op==='invite');
  assert.equal(attempts.length,2);
  assert.deepEqual(attempts[0].data,attempts[1].data,'Network retry preserves the invitation ID and exact snapshot');
  assert.notEqual(attempts[0].nonce,attempts[1].nonce,'Retry uses fresh authentication');
  assert.notEqual(attempts[0].card,organizerCard,'Signed envelope display name is not substituted for the snapshot');
  const invitationKey='invite:'+createHash('sha256').update(Buffer.from(created.id,'base64url')).digest('hex');
  const before=db.dump().get(invitationKey);
  assert.equal(before.organizer_card,organizerCard);
  assert.equal([...db.dump().keys()].filter(key=>key.startsWith('invite:')).length,1);
  assert.equal([...db.dump()].find(([key])=>key.startsWith('quota:team:invite-day:'))[1].used,1);

  const url=await shortTrustedInvitationURL(origin+'/',created.id,organizerCard);
  assert.match(new URL(url).hash,/^#i=[A-Za-z0-9_-]{64}$/);
  assert.equal(parseShortInvitation(url,origin+'/').id,created.id);
  for(let n=0;n<2;n++){
    const info=await client.invitationInfo(doctor,created.id);
    assert.deepEqual(info,{id:created.id,expires:created.expires,organizerCard});
    const checked=await verifyShortInvitation(url,origin+'/',info,{now});
    assert.deepEqual(checked,{id:created.id,organizerCard,fingerprint:organizer.fingerprint});
    assert.deepEqual(db.dump().get(invitationKey),before,'Opening and verifying leave invitation unclaimed');
    assert.equal(db.dump().has('member:'+recipient.id),false,'Opening never enrolls the recipient');
  }

  const tampered=new URL(url),bytes=Buffer.from(tampered.hash.slice(3),'base64url');
  bytes[47]^=1;tampered.hash='i='+bytes.toString('base64url');
  assert.equal(parseShortInvitation(tampered.href,origin+'/').id,created.id);
  const info=await client.invitationInfo(doctor,created.id);
  await assert.rejects(verifyShortInvitation(tampered.href,origin+'/',info,{now}),/не совпадает/);
  assert.deepEqual(db.dump().get(invitationKey),before);
  assert.equal(db.dump().has('member:'+recipient.id),false);
  assert.equal(envelopes.some(e=>e.op==='claim'),false);

  assert.deepEqual(await client.claim(doctor,created.id),{state:'pending'});
  assert.equal(db.dump().get(invitationKey).claimed_by,recipient.id);
  assert.deepEqual(await client.status(doctor),{state:'pending',role:'cardiologist',name:'Врач'});
  await assert.rejects(client.invitationInfo(doctor,created.id),error=>error.status===404);
  assert.deepEqual(await client.change(admin,'approve',recipient.id),{state:'active'});
  assert.deepEqual(await client.status(doctor),{state:'active',role:'cardiologist',name:'Врач'});
});
