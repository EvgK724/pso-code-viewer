import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
import {httpHandler} from './runtime.mjs';
import {validateOrigin,jsonReply} from './http.mjs';
import {safeServiceDiagnostic} from '../team-handler.mjs';

const ORIGIN='https://viewer.example';
const event={path:'/api/pso-team',httpMethod:'POST',headers:{host:'viewer.example',origin:ORIGIN},body:'{}'};

// Run the real runtime orchestration without a database, IAM token, network,
// or changing its production dependency surface solely for test injection.
async function runtimeFixture(){
  const source=await readFile(new URL('./runtime.mjs',import.meta.url),'utf8');
  const f={pin:{origin:ORIGIN},readError:null,reads:[],factoryOptions:[],drivers:[],dispatches:0,handlerSetups:0};
  const db={
    async read(key){f.reads.push(key);if(f.readError)throw f.readError;return f.pin;},
    async transaction(){throw new Error('Organizer check must not open a multi-query transaction');}
  };
  class Driver{
    constructor(options){this.options=options;this.destroyed=false;f.drivers.push(this);}
    async ready(timeout){this.readyTimeout=timeout;return true;}
    async destroy(){this.destroyed=true;}
  }
  const sdk={Driver,TokenAuthService:class{constructor(token){this.token=token;}}};
  const handler=()=>{f.handlerSetups++;return async()=>new Response('{}');};
  const context=vm.createContext({URL,Response,Promise,setTimeout,clearTimeout,
    process:{env:{PSO_SETUP_MODE:'off',PSO_VIEWER_ORIGIN:ORIGIN}}});
  const exportsByName={
    'node:module':{createRequire:()=>name=>{assert.equal(name,'ydb-sdk');return sdk;}},
    'node:fs/promises':{readFile:async()=>JSON.stringify({endpoint:'grpcs://test.invalid',database:'/test'})},
    './ydb-database.mjs':{createYdbDatabase:options=>{f.factoryOptions.push(options);return db;}},
    './team-store.mjs':{createTeamStore:()=>({})},
    './direct-store.mjs':{createDirectStore:()=>({})},
    './push-store.mjs':{createPushStore:()=>({keys:()=>{}})},
    './device-auth-store.mjs':{createDeviceAuthStore:()=>({unlockCheck:()=>{}})},
    '../team-handler.mjs':{createTeamHandler:handler,safeServiceDiagnostic},
    '../direct-handler.mjs':{createDirectHandler:handler},
    '../push-handler.mjs':{createPushHandler:handler},
    '../device-auth-handler.mjs':{createDeviceAuthHandler:handler},
    './http.mjs':{jsonReply,validateOrigin,createHttpRouter:({handlers})=>async()=>{
      f.dispatches++;return jsonReply(200,{routes:Object.keys(handlers).length});
    }},
    '@simplewebauthn/server':{}
  };
  const modules=new Map();
  function dependency(specifier){
    assert.ok(Object.hasOwn(exportsByName,specifier),'Unexpected import '+specifier);
    if(!modules.has(specifier)){
      const values=exportsByName[specifier];
      modules.set(specifier,new vm.SyntheticModule(Object.keys(values),function(){
        for(const [key,value]of Object.entries(values))this.setExport(key,value);
      },{context}));
    }
    return modules.get(specifier);
  }
  const mod=new vm.SourceTextModule(source,{context,identifier:'file:///pso/server/yandex/runtime.mjs',
    initializeImportMeta(meta){meta.url='file:///pso/server/yandex/runtime.mjs';},
    async importModuleDynamically(specifier){
      const dep=dependency(specifier);if(dep.status==='unlinked')await dep.link(()=>{});
      if(dep.status!=='evaluated')await dep.evaluate();return dep;
    }});
  await mod.link(dependency);await mod.evaluate();
  f.runtime=mod.namespace;
  f.context={token:{access_token:'synthetic-token'}};
  return f;
}

test('runtime setup and connection diagnostics stay bounded without revealing configuration',async()=>{
  const previousMode=process.env.PSO_SETUP_MODE,previousOrigin=process.env.PSO_VIEWER_ORIGIN;
  try{
    process.env.PSO_SETUP_MODE='on';process.env.PSO_VIEWER_ORIGIN=ORIGIN;
    let response=await httpHandler(event,{});
    assert.equal(response.statusCode,503);assert.deepEqual(JSON.parse(response.body),{error:'setup_required'});

    process.env.PSO_SETUP_MODE='off';process.env.PSO_VIEWER_ORIGIN='PRIVATE invalid endpoint';
    response=await httpHandler(event,{});
    assert.equal(response.statusCode,503);assert.deepEqual(JSON.parse(response.body),{
      error:'service_unavailable',diagnostic:{stage:'configuration',code:'internal_error',status:null}
    });

    process.env.PSO_VIEWER_ORIGIN=ORIGIN;
    response=await httpHandler(event,{});
    assert.equal(response.statusCode,503);assert.deepEqual(JSON.parse(response.body),{
      error:'service_unavailable',diagnostic:{stage:'database_connect',code:'internal_error',status:null}
    });
  }finally{
    if(previousMode===undefined)delete process.env.PSO_SETUP_MODE;else process.env.PSO_SETUP_MODE=previousMode;
    if(previousOrigin===undefined)delete process.env.PSO_VIEWER_ORIGIN;else process.env.PSO_VIEWER_ORIGIN=previousOrigin;
  }
});

test('each API call freshly checks organizer pin with one read and a shared request budget',
  {skip:typeof vm.SourceTextModule!=='function'},async()=>{
    const f=await runtimeFixture();
    let response=await f.runtime.httpHandler(event,f.context);
    assert.equal(response.statusCode,200);assert.equal(f.dispatches,1);
    assert.deepEqual(f.reads,['config:organizer']);
    assert.equal(f.factoryOptions[0].requestTimeoutMs,45000);
    assert.equal(f.drivers[0].readyTimeout,10000);assert.equal(f.drivers[0].destroyed,true);

    // Removing the pin after success must disable the very next request.
    f.pin=null;
    response=await f.runtime.httpHandler(event,f.context);
    assert.equal(response.statusCode,503);
    assert.deepEqual(JSON.parse(response.body),{error:'organizer_setup_required'});
    assert.equal(f.dispatches,1);assert.equal(f.handlerSetups,4);
    assert.equal(f.reads.length,2);assert.equal(f.drivers[1].destroyed,true);

    // A pin for another deployment is not accepted, even after prior success.
    f.pin={origin:'https://another.example'};
    response=await f.runtime.httpHandler(event,f.context);
    assert.equal(response.statusCode,503);assert.equal(f.dispatches,1);
    assert.equal(f.reads.length,3);
    assert.ok(f.factoryOptions.every(options=>options.requestTimeoutMs===45000));
    assert.ok(f.drivers.every(driver=>driver.destroyed));
  });

test('cancelled organizer read fails closed before handlers and exposes only safe diagnostics',
  {skip:typeof vm.SourceTextModule!=='function'},async()=>{
    const f=await runtimeFixture();
    f.readError=Object.assign(new Error('private SQL parameters'),{code:'database_unavailable',status:400160});
    const response=await f.runtime.httpHandler(event,f.context);
    assert.equal(response.statusCode,503);
    assert.deepEqual(JSON.parse(response.body),{error:'service_unavailable',diagnostic:{
      stage:'organizer_check',code:'database_unavailable',status:400160
    }});
    assert.equal(f.dispatches,0);assert.equal(f.handlerSetups,0);
    assert.equal(f.drivers[0].destroyed,true);
    assert.equal(response.body.includes('private'),false);
  });

test('database wrapper forwards optional budget and always closes driver after callback failure',
  {skip:typeof vm.SourceTextModule!=='function'},async()=>{
    const f=await runtimeFixture();
    await assert.rejects(f.runtime.withDatabase(f.context,async()=>{throw new Error('callback rejected');},
      {requestTimeoutMs:32000}),/callback rejected/);
    assert.equal(f.factoryOptions[0].requestTimeoutMs,32000);
    assert.equal(f.drivers[0].destroyed,true);
    await f.runtime.withDatabase(f.context,async()=>42);
    assert.equal(Object.hasOwn(f.factoryOptions[1],'requestTimeoutMs'),false);
    assert.equal(f.drivers[1].destroyed,true);
  });
