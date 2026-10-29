import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';

const source=await readFile(new URL('../docs/sw.js',import.meta.url),'utf8');
const now=1792756800000;
const base='https://viewer.example/pso-code-viewer/';
const id='AAAAAAAAAAAAAAAAAAAAAQ';
const valid=()=>({v:1,id,expires:now+60000});
function harness({windows=[],matchError=false,matchHang=false,baseURL=base}={}) {
  const events=new Map(),shown=[],opened=[],cached=[],focusedOpened=[];
  let closed=0;
  class FixedDate extends Date {static now(){return now;}}
  const context={
    URL,Date:FixedDate,setTimeout:fn=>setTimeout(fn,10),clearTimeout,
    self:{
      location:new URL('sw.js',baseURL),
      addEventListener(name,fn){events.set(name,fn);},
      registration:{async showNotification(title,options){shown.push({title,...options});}},
      clients:{async matchAll(options){assert.equal(options.type,'window');if(matchError)throw Error('unavailable');if(matchHang)return new Promise(()=>{});return windows;},async openWindow(url){opened.push(url);return {async focus(){focusedOpened.push(url);return this;}};}}
    },
    caches:{async open(name){cached.push(name);throw Error('Push must never access caches');}},
    fetch(){throw Error('Push must never request or decrypt patient data');}
  };
  vm.runInNewContext(source,context);
  async function run(name,event){let pending;events.get(name)({...event,waitUntil(p){pending=p;}});assert.ok(pending);await pending;}
  return {
    shown,opened,cached,focusedOpened,closed:()=>closed,
    push(value,{throws=false,noData=false}={}){return run('push',{data:noData?undefined:{json(){if(throws)throw Error('bad json');return value;}}});},
    click(data){return run('notificationclick',{notification:{data,close(){closed++;}}});}
  };
}

test('push notification has a generic body and restricted data, with no network or cached records',async()=>{
  const h=harness();await h.push(valid());
  assert.equal(h.shown.length,1);assert.equal(h.shown[0].title,'ПСО');
  assert.equal(h.shown[0].body,'Новое сообщение ПСО');
  assert.deepEqual(JSON.parse(JSON.stringify(h.shown[0].data)),valid());
  assert.equal(h.shown[0].icon,base+'icon-pso-v2-192.png');
  assert.deepEqual(h.cached,[]);assert.deepEqual(h.opened,[]);
  await h.click(h.shown[0].data);
  assert.deepEqual(h.opened,[base+'#r='+id]);assert.equal(h.closed(),1);
});

test('self-test notification opens the app home without a fictitious patient link',async()=>{
  const h=harness();await h.push({...valid(),id:null});
  assert.equal(h.shown[0].body,'Проверка уведомлений');
  await h.click(h.shown[0].data);assert.deepEqual(h.opened,[base]);
});

test('two-day direct notifications retain their inbox target but longer payloads are rejected',async()=>{
  const direct={...valid(),v:2,expires:now+172800000};
  const h=harness();await h.push(direct);
  assert.deepEqual(JSON.parse(JSON.stringify(h.shown[0].data)),direct);
  await h.click(h.shown[0].data);assert.deepEqual(h.opened,[base+'#m='+id]);
  const invalid=harness();await invalid.push({...direct,expires:now+172830001});
  assert.deepEqual(JSON.parse(JSON.stringify(invalid.shown[0].data)),{v:1,id:null,expires:0});
});

test('malformed and expired pushes still display a generic safe notification',async t=>{
  const bad=[null,[],{},'text',{...valid(),v:3},{...valid(),expires:now},{...valid(),expires:now+86430001},
    {...valid(),expires:'tomorrow'},{...valid(),expires:NaN},{...valid(),id:'https://evil.example/'},
    {...valid(),id:'AAAAAAAAAAAAAAAAAAAAAB'},{...valid(),id:id+'x'},
    {...valid(),surname:'Петров'},{...valid(),url:'https://evil.example/'}];
  for(const input of bad)await t.test(JSON.stringify(input),async()=>{
    const h=harness();await h.push(input);assert.equal(h.shown.length,1);
    assert.equal(h.shown[0].body,'Новое сообщение ПСО');
    assert.deepEqual(JSON.parse(JSON.stringify(h.shown[0].data)),{v:1,id:null,expires:0});
    await h.click(h.shown[0].data);assert.deepEqual(h.opened,[base]);
  });
  for(const options of [{throws:true},{noData:true}]){
    const h=harness();await h.push(null,options);assert.equal(h.shown.length,1);await h.click(h.shown[0].data);assert.deepEqual(h.opened,[base]);
  }
});

test('click rechecks data, expiry and destination even if the notification was altered',async()=>{
  for(const data of [{...valid(),expires:now-1},{...valid(),url:'https://evil.example/'},{...valid(),id:'../another-app/'},undefined]){
    const h=harness();await h.click(data);assert.deepEqual(h.opened,[base]);
  }
});

test('an existing app window is focused before navigating to the right fragment',async()=>{
  for(const suffix of ['', 'index.html', '?anything=1']){
    const actions=[];
    const window={url:base+suffix,frameType:'top-level',async focus(){actions.push(['focus']);return this;},async navigate(url){actions.push(['navigate',url]);return this;}};
    const h=harness({windows:[window]});await h.click(valid());
    assert.deepEqual(actions,[['focus'],['navigate',base+'#r='+id]]);
    assert.deepEqual(h.opened,[]);
  }
});

test('test and expired notifications focus an existing app without reloading it',async()=>{
  for(const data of [{...valid(),id:null},{...valid(),expires:now-1},{...valid(),id:'https://evil.example/'}]){
    let focused=0;
    const window={url:base,async focus(){focused++;return this;},navigate(){assert.fail('must not reload an existing app for a test or invalid notification');}};
    const h=harness({windows:[window]});await h.click(data);
    assert.equal(focused,1);assert.deepEqual(h.opened,[]);
  }
});

test('sibling sites, nested paths, foreign origins and credential URLs are never focused',async()=>{
  const urls=['https://viewer.example/another-app/','https://viewer.example/pso-code-viewer/extra/',
    'https://other.example/pso-code-viewer/','https://user@viewer.example/pso-code-viewer/','not a URL'];
  const h=harness({windows:urls.map(url=>({url,async focus(){assert.fail('foreign window focus');},async navigate(){assert.fail('foreign window navigation');}}))});
  await h.click(valid());assert.deepEqual(h.opened,[base+'#r='+id]);
});

test('failed or null window navigation and focus fall back to opening and focusing the app',async()=>{
  for(const window of [
    {url:base,async focus(){return this;},async navigate(){throw Error('closed');}},
    {url:base,async focus(){return this;},async navigate(){return null;}},
    {url:base,async focus(){throw Error('closed');}},
    {url:base,async focus(){return null;}}
  ]){const h=harness({windows:[window]});await h.click(valid());assert.deepEqual(h.opened,[base+'#r='+id]);assert.deepEqual(h.focusedOpened,h.opened);}
  const h=harness({matchError:true});await h.click(valid());assert.deepEqual(h.opened,[base+'#r='+id]);
});

test('suspended clients cannot indefinitely block focus or the opening fallback',async()=>{
  for(const operation of ['focus','navigate']){
    const actions=[];
    const window={url:base,async focus(){actions.push('focus');return this;},async navigate(){actions.push('navigate');return this;}};
    let finish;
    window[operation]=()=>{actions.push(operation+'-pending');return new Promise(resolve=>{finish=resolve;});};
    const h=harness({windows:[window]});await h.click({...valid(),v:2});
    assert.deepEqual(h.opened,[base+'#m='+id]);assert.deepEqual(h.focusedOpened,h.opened);
    if(operation==='navigate')assert.equal(actions[0],'focus');
    finish(window);await Promise.resolve();
    assert.equal(h.opened.length,1);
  }
  const h=harness({matchHang:true});await h.click({...valid(),id:null});assert.deepEqual(h.opened,[base]);
});

test('an embedded client is skipped in favour of an application window',async()=>{
  let focused=0;
  const nested={url:base,frameType:'nested',focus(){assert.fail('must not focus an iframe');}};
  const app={url:base,frameType:'top-level',async focus(){focused++;return this;}};
  const h=harness({windows:[nested,app]});await h.click({...valid(),id:null});
  assert.equal(focused,1);assert.deepEqual(h.opened,[]);
});

test('root deployment also constructs its own internal route',async()=>{
  const h=harness({baseURL:'https://viewer.example/'});await h.click(valid());assert.deepEqual(h.opened,['https://viewer.example/#r='+id]);
});


test('direct push v2 opens only the direct inbox message route without plaintext',async()=>{
  const h=harness(), payload={...valid(),v:2};await h.push(payload);
  assert.equal(h.shown[0].body,'Новое сообщение ПСО');
  assert.deepEqual(JSON.parse(JSON.stringify(h.shown[0].data)),payload);
  await h.click(h.shown[0].data);assert.deepEqual(h.opened,[base+'#m='+id]);
  assert.deepEqual(h.cached,[]);
});
