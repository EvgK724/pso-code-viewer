// One page may refresh inbox, device protection and push at the same time.
// Serialize signed API work so their shared database counters do not contend.
// Callers create signatures and start network timeouts inside the queued work.
// Yandex allows 10s to connect, then one 45s database budget plus cleanup.
// Leave network headroom so a phone does not abort a still-running write.
export const API_REQUEST_TIMEOUT_MS = 70000;
export function createApiQueue() {
  let tail = Promise.resolve();
  return work => {
    const next = tail.then(work);
    tail = next.catch(() => {});
    return next;
  };
}
const enqueue = createApiQueue();
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

export async function runApiRequest(work, {retry=false, sleep=wait, random=Math.random}={}) {
  for (let attempt=0;;attempt++) {
    try { return await enqueue(work); }
    catch (error) {
      // Only callers whose action data is state-idempotent may opt in.
      // A lost reply can follow a successful commit: keep the same action ID,
      // but sign a fresh nonce/timestamp when this action is tried again.
      const transient=error?.networkFailure===true || [502,503,504].includes(error?.status);
      if (!retry || !transient || attempt>=2) throw error;
      await sleep(Math.round(600*2**attempt*(0.85+0.3*random())));
    }
  }
}

const errorCodes=new Set(['request_rejected','clock_skew','unlock_required','id_conflict','roster_changed','replay']);
const diagnosticCodes=new Set(['database_conflict','database_deadline','database_unavailable','invalid_record','invalid_result','result_limit','database_closed','transaction_closed','operation_limit','internal_error']);
const stages=new Set(['validation','accept','status','directory','pending','invite','claim','approve','revoke','resolve','create','configuration','database_connect','organizer_check','handler_setup','dispatch']);

// Error bodies are not trusted display text. Read a small bounded JSON body and
// retain only explicitly allowed machine codes, never message/cause/stack/data.
export async function readApiError(response) {
  if (!response.headers.get('content-type')?.startsWith('application/json')) return {code:''};
  const reader=response.body?.getReader();
  if (!reader) return {code:''};
  try {
    let size=0,text='';const decoder=new TextDecoder('utf-8',{fatal:true});
    for (;;) {
      const {done,value}=await reader.read();if(done)break;
      size+=value.byteLength;
      if(size>2048){await reader.cancel().catch(()=>{});return {code:''};}
      text+=decoder.decode(value,{stream:true});
    }
    const body=JSON.parse(text+decoder.decode()),code=errorCodes.has(body?.error)?body.error:'';
    const d=body?.diagnostic;
    if(!diagnosticCodes.has(d?.code)||!stages.has(d?.stage))return {code};
    const status=Number.isSafeInteger(d.status)&&d.status>=100000&&d.status<=999999?d.status:null;
    return {code,diagnostic:{stage:d.stage,code:d.code,status}};
  } catch { return {code:''}; }
  finally {reader.releaseLock();}
}
export function apiDiagnosticText({diagnostic}={}) {
  return diagnostic?' ['+diagnostic.stage+'/'+diagnostic.code+(diagnostic.status===null?'':' · '+diagnostic.status)+']':'';
}
