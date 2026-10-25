// DRAFT Supabase entrypoint. Deploy beside shortlink-handler.mjs only after a
// dedicated project's schema, allowlist, quotas, expiry and access checks pass.
// Server credentials must never be placed in docs/ or sent to the browser.
import {createShortlinkHandler} from './shortlink-handler.mjs';

const projectURL = Deno.env.get('SUPABASE_URL');
const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
const allowedOrigin = Deno.env.get('PSO_VIEWER_ORIGIN')||'https://evgk724.github.io';
if (!projectURL || !serviceRoleKey) throw new Error('Short-link service is not configured.');
const rpcBase = new URL('/rest/v1/rpc/', projectURL);
if (rpcBase.protocol !== 'https:') throw new Error('Short-link service requires HTTPS.');

async function rpc(name: string, body: Record<string, unknown>) {
  const abort = new AbortController();
  const timeout = setTimeout(() => abort.abort(), 8000);
  try {
    const response = await fetch(new URL(name, rpcBase), {
      method:'POST',
      headers:{'Content-Type':'application/json', 'apikey':serviceRoleKey!,
        'Authorization':'Bearer ' + serviceRoleKey!},
      body:JSON.stringify(body), signal:abort.signal, redirect:'error', cache:'no-store'
    });
    // Intentionally do not include response bodies, records or credential details
    // in exceptions/logs. The generic handler returns a non-sensitive error.
    if (!response.ok) throw new Error('Storage unavailable.');
    return await response.json();
  } finally { clearTimeout(timeout); }
}

function unbase64url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]{122}$/.test(value)) throw new Error('Writer key unavailable.');
  const base = value.replace(/-/g,'+').replace(/_/g,'/');
  return Uint8Array.from(atob(base + '=='), c => c.charCodeAt(0));
}

const store = {
  async getWriter(senderID: string) {
    const record = await rpc('pso_shortlink_writer', {p_sender_id:senderID});
    if (!record || record.enabled !== true) return null;
    const signingPublicKey = await crypto.subtle.importKey('spki', unbase64url(record.signing_spki),
      {name:'ECDSA',namedCurve:'P-256'}, false, ['verify']);
    return {signingPublicKey,enabled:true};
  },
  async put(record: {idHash:string; requestHash:string; senderID:string; token:string; issued:number; expires:number}) {
    // Ignore any client/handler `now`; quota and expiry checks use DB time.
    return await rpc('pso_shortlink_put', {
      p_id_hash:record.idHash, p_request_hash:record.requestHash, p_sender_id:record.senderID,
      p_token:record.token, p_issued:record.issued, p_expires:record.expires
    });
  },
  async resolve(idHash: string, _now?: number) {
    return await rpc('pso_shortlink_resolve', {p_id_hash:idHash});
  }
};

// The handler authenticates create requests with the existing device signature
// and the server allowlist. Resolve uses an unguessable 128-bit capability and
// returns ciphertext only. There is no public list, update or redirect endpoint.
// Deploy with verify_jwt:false because this is custom device authentication;
// service-role credentials stay exclusively inside this Edge Function.
Deno.serve(createShortlinkHandler({store,allowedOrigin}));
