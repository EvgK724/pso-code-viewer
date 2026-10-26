import test from 'node:test';
import assert from 'node:assert/strict';
import {createMemoryDatabase} from './test-db.mjs';
import {runDatabaseSelfTest,runMaintenance,bootstrapOrganizer,scopedDatabase} from './maintenance.mjs';
import {makeDevice} from '../../docs/crypto.mjs';
import {exportPublicCard,importPublicCard} from '../../docs/exchange.mjs';
const origin='https://example.apigw.yandexcloud.net';
test('private live selftest uses only synthetic namespace and leaves nothing',async()=>{
 const db=createMemoryDatabase();await db.seed('preserve:real',{kept:true});
 const result=await runDatabaseSelfTest(db);assert.equal(result.ok,true);assert.equal(result.checks.length,5);
 assert.deepEqual([...db.dump()],[['preserve:real',{kept:true}]]);
});
test('setup ignores caller-proposed bootstrap identity; only operator-configured card can be used',async()=>{
 const db=createMemoryDatabase(),device=await makeDevice(),card=await exportPublicCard(device,'Тестовый организатор');
 const owner=await importPublicCard(card);
 await assert.rejects(runMaintenance(db,{action:'bootstrap',card},{allowedOrigin:origin}));
 await assert.rejects(runMaintenance(db,{action:'bootstrap'},{allowedOrigin:origin}));
 assert.equal(db.dump().size,0);
 assert.equal((await runMaintenance(db,{action:'bootstrap'},{allowedOrigin:origin,organizerCard:card})).ok,true);
 assert.equal(db.dump().get('member:'+owner.id).role,'admin');
 assert.equal((await bootstrapOrganizer(db,card,origin)).alreadyConfigured,true);
 await assert.rejects(bootstrapOrganizer(db,card,'https://other.example'));
 const other=await exportPublicCard(await makeDevice(),'Другой');await assert.rejects(bootstrapOrganizer(db,other,origin));
 assert.equal([...db.dump().keys()].filter(k=>k.startsWith('member:')).length,1);
});
test('synthetic expiry capped even if tested store normally retains records for days',async()=>{
 let at=Date.now();const db=createMemoryDatabase({now:()=>at}),scoped=scopedDatabase(db,'selftest:x:');
 await scoped.transaction(tx=>tx.put('audit:1',{test:true},at+7*86400000));
 at+=3600001;assert.equal(db.dump().size,0);
});
