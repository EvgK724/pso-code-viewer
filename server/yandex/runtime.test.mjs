import test from 'node:test';
import assert from 'node:assert/strict';
import {httpHandler} from './runtime.mjs';

const ORIGIN='https://viewer.example';
const event={path:'/api/pso-team',httpMethod:'POST',headers:{host:'viewer.example',origin:ORIGIN},body:'{}'};

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
