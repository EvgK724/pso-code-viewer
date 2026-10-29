import {APP_RELEASE, RELEASE_NOTIFICATIONS_VERSION} from './release-info.mjs';

const exact = (value,keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;
export function releaseCapability(worker,{Channel=globalThis.MessageChannel,timeoutMs=800}={}) {
  if (!worker || typeof worker.postMessage !== 'function' || typeof Channel !== 'function') return Promise.resolve(0);
  return new Promise(resolve => {
    const channel = new Channel();
    let timer, finished=false;
    const finish = value => {
      if (finished) return;
      finished=true;clearTimeout(timer);channel.port1.close();channel.port2.close();resolve(value);
    };
    timer=setTimeout(()=>finish(0),timeoutMs);
    channel.port1.onmessage = event => finish(exact(event.data,'notificationsVersion,type') && event.data.type === 'PSO_RELEASE_CAPABILITY' && event.data.notificationsVersion === RELEASE_NOTIFICATIONS_VERSION ? RELEASE_NOTIFICATIONS_VERSION : 0);
    try { worker.postMessage({type:'PSO_GET_RELEASE_CAPABILITY'},[channel.port2]); } catch { finish(0); }
  });
}

// Public release metadata only. No drafts, keys, messages or patient information
// are persisted here, and a notification never reloads or navigates the page.
export function installReleaseNotices({request,isEligible,onAvailable=()=>{},checkUpdate=()=>{},navigator:nav=globalThis.navigator,document:doc=globalThis.document,now=Date.now,capability=releaseCapability}={}) {
  let pending=null,lastCheck=-Infinity,announced=0;
  const sw=nav?.serviceWorker;
  function announce(version) {
    if (!isEligible() || !Number.isSafeInteger(version) || version<=APP_RELEASE || version>1000000 || version<=announced) return;
    announced=version;onAvailable(version);void checkUpdate();
  }
  async function check(force=false) {
    if (!isEligible() || nav?.onLine===false) return;
    if (pending) return pending;
    if (!force && now()-lastCheck<300000) return;
    lastCheck=now();
    pending=(async()=>{
      const notificationsVersion=await capability(sw?.controller);
      const result=await request({clientVersion:APP_RELEASE,notificationsVersion});
      if (!exact(result,'updateAvailable,version') || !Number.isSafeInteger(result.version) || result.version<17 || result.version>1000000 || result.updateAvailable!==(result.version>APP_RELEASE)) return;
      if (result.updateAvailable) announce(result.version);
    })().catch(()=>{}).finally(()=>{pending=null;});
    return pending;
  }
  sw?.addEventListener?.('message',event=>{
    if (event.source!==sw.controller || !exact(event.data,'type,version') || event.data.type!=='PSO_RELEASE_AVAILABLE') return;
    announce(event.data.version);void check(true);
  });
  sw?.addEventListener?.('controllerchange',()=>{void check(true);});
  doc?.addEventListener?.('visibilitychange',()=>{if(!doc.hidden)void check();});
  return {check};
}
