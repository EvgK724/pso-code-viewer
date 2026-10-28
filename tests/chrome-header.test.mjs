import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';

const source=await readFile(new URL('../docs/app.mjs',import.meta.url),'utf8');
const start=source.indexOf('function installBrandScroll(){');
const end=source.indexOf('\ninstallBrandScroll();',start);
assert.ok(start>=0&&end>start,'Header installer remains available in the production app');
const installer=source.slice(start,end)+'\ninstallBrandScroll();';

function headerHarness({scrollY=0,header=true,animationFrames=true}={}){
  const styles=new Map(),classes=new Set(),shellClasses=new Set(),listeners=new Map(),frames=[];
  const shell={classList:{add:value=>shellClasses.add(value)}};
  const brand={parentElement:shell,classList:{add:value=>classes.add(value)},style:{setProperty:(name,value)=>styles.set(name,value)}};
  const context=vm.createContext({
    scrollY,
    document:{querySelector(selector){assert.equal(selector,'.brand');return header?brand:null;}},
    ...(animationFrames?{requestAnimationFrame:fn=>{frames.push(fn);return frames.length;}}:{}),
    addEventListener(type,listener,options){listeners.set(type,{listener,options});},
    scrollTo(){assert.fail('Header must never change document scroll position');}
  });
  vm.runInContext(installer,context);
  return {styles,classes,shellClasses,listeners,frames,
    position:()=>styles.get('--brand-scroll-y'),
    scroll(y){context.scrollY=y;listeners.get('scroll')?.listener({preventDefault(){assert.fail('Native scrolling must remain enabled');}});},
    pageshow(y){context.scrollY=y;listeners.get('pageshow')?.listener();},
    frame(){const pending=frames.splice(0);for(const fn of pending)fn();}
  };
}

test('header starts at the safe top for zero or negative iOS overscroll and respects restored positive scroll',()=>{
  for(const [scrollY,expected] of [[0,'0px'],[-64,'0px'],[112,'-112px']]){
    const h=headerHarness({scrollY});
    assert.equal(h.position(),expected);
    assert.ok(h.classes.has('is-viewport-bound'));
    assert.ok(h.shellClasses.has('has-viewport-brand'));
    assert.equal(h.frames.length,0,'Initial position is synchronous');
  }
});

test('passive scroll coalesces to one frame and uses the latest position without smoothing or locking scroll',()=>{
  const h=headerHarness();
  assert.equal(h.listeners.get('scroll').options.passive,true);
  h.scroll(8);h.scroll(24);h.scroll(42.5);
  assert.equal(h.frames.length,1);assert.equal(h.position(),'0px');
  h.frame();assert.equal(h.position(),'-42.5px');
  h.scroll(-30);h.frame();assert.equal(h.position(),'0px');
  h.scroll(0);h.frame();assert.equal(h.position(),'0px');
  h.scroll(90);h.frame();assert.equal(h.position(),'-90px');
});

test('pageshow synchronizes immediately and an already queued frame cannot restore a stale offset',()=>{
  const h=headerHarness({scrollY:75});
  h.scroll(120);assert.equal(h.frames.length,1);
  h.pageshow(-18);assert.equal(h.position(),'0px');
  h.frame();assert.equal(h.position(),'0px');
  h.pageshow(340);assert.equal(h.position(),'-340px');
});

test('missing header or frame API preserves the normal-flow fallback without installing scroll handlers',()=>{
  for(const options of [{header:false},{animationFrames:false}]){
    const h=headerHarness(options);
    assert.equal(h.position(),undefined);
    assert.equal(h.classes.size,0);assert.equal(h.shellClasses.size,0);
    assert.equal(h.listeners.size,0);
  }
});

