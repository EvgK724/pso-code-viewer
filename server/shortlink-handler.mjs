// Provider-neutral ciphertext broker. No plaintext patient fields or private keys.
// getWriter must bind an independently approved device ID to its signing key.
// put must atomically recheck enabled status, enforce quotas and compare requestHash
// for an existing idHash. It returns created/exists/conflict/limited/denied.
// resolve returns only {token, expires}, or null. Expired rows need separate cleanup.
export const MAX_BODY_BYTES = 8192;
const MAX_TTL = 24 * 60 * 60 * 1000;
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', {fatal:true});
const CREATE_DOMAIN = 'PSO-SHORT-LINK-v1\0';
const TOKEN_DOMAIN = 'PSO-SURNAME-LINK-v1\0';

class BadRequest extends Error {
  constructor(status = 400) { super('Request rejected'); this.status = status; }
}
function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === keys;
}
function decode64(value, length) {
  if (typeof value !== 'string' || value.length !== Math.ceil(length * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) throw new BadRequest();
  let bytes;
  try {
    const s = value.replace(/-/g, '+').replace(/_/g, '/');
    bytes = Uint8Array.from(atob(s + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
  } catch { throw new BadRequest(); }
  const canonical = btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  if (bytes.length !== length || canonical !== value) throw new BadRequest();
  return bytes;
}
function parseToken(token) {
  if (typeof token !== 'string' || token.length > 900) throw new BadRequest();
  const parts = token.split('.');
  if (parts.length !== 5 || parts[0] !== 'PSO1') throw new BadRequest();
  decode64(parts[1], 32); decode64(parts[2], 32); decode64(parts[3], 384);
  return {senderID:parts[2], signature:decode64(parts[4], 64), signed:enc.encode(TOKEN_DOMAIN + parts.slice(0, 4).join('.'))};
}
function isSigningKey(key) {
  return key?.type === 'public' && key.algorithm?.name === 'ECDSA' &&
    key.algorithm?.namedCurve === 'P-256' && key.usages?.includes('verify');
}
async function readJSON(request) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get('content-type') || '')) throw new BadRequest(415);
  const declared = request.headers.get('content-length');
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > MAX_BODY_BYTES)) throw new BadRequest(413);
  if (!request.body) throw new BadRequest();
  const reader = request.body.getReader(), chunks = [];
  let size = 0;
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) { await reader.cancel().catch(() => {}); throw new BadRequest(413); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(dec.decode(bytes)); } catch { throw new BadRequest(); }
}
async function hash(crypto, bytes) {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(n => n.toString(16).padStart(2, '0')).join('');
}

export function createShortlinkHandler({store, allowedOrigin, now = Date.now, crypto = globalThis.crypto}) {
  let origin;
  try { origin = new URL(allowedOrigin); } catch { throw new Error('Configure one HTTPS origin'); }
  if (origin.protocol !== 'https:' || origin.origin !== allowedOrigin) throw new Error('Configure one HTTPS origin');
  if (!crypto?.subtle || !store?.getWriter || !store?.put || !store?.resolve) throw new Error('Broker dependencies are missing');
  function response(status, body, cors = false) {
    const headers = {
      'Cache-Control':'no-store', 'Referrer-Policy':'no-referrer',
      'X-Content-Type-Options':'nosniff', 'Vary':'Origin'
    };
    if (cors) headers['Access-Control-Allow-Origin'] = allowedOrigin;
    if (status === 204) {
      headers['Access-Control-Allow-Methods'] = 'POST';
      headers['Access-Control-Allow-Headers'] = 'Content-Type';
      headers['Access-Control-Max-Age'] = '600';
    } else headers['Content-Type'] = 'application/json; charset=utf-8';
    return new Response(status === 204 ? null : JSON.stringify(body), {status, headers});
  }
  const rejected = (status, cors) => response(status, {error:'request_rejected'}, cors);
  return async function handle(request) {
    const cors = request.headers.get('origin') === allowedOrigin;
    if (!cors) return rejected(403, false);
    try {
      const url = new URL(request.url);
      if (url.search || url.hash || url.username || url.password) return rejected(400, true);
      if (request.method === 'OPTIONS') {
        const method = request.headers.get('access-control-request-method');
        const headers = (request.headers.get('access-control-request-headers') || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
        if (method !== 'POST' || headers.some(s => s !== 'content-type')) return rejected(403, true);
        return response(204, null, true);
      }
      if (request.method !== 'POST') return rejected(405, true);
      const data = await readJSON(request), at = now();
      if (!Number.isSafeInteger(at)) throw new Error('Clock unavailable');
      if (exact(data, 'id,op') && data.op === 'resolve') {
        const idHash = await hash(crypto, decode64(data.id, 16));
        const row = await store.resolve(idHash, at);
        if (!row || !Number.isSafeInteger(row.expires) || row.expires <= at) return rejected(404, true);
        try { parseToken(row.token); } catch { return rejected(503, true); }
        return response(200, {token:row.token, expires:row.expires}, true);
      }
      if (!exact(data, 'envelope,op') || data.op !== 'create' || !exact(data.envelope, 'expires,id,issued,signature,token,v')) throw new BadRequest();
      const e = data.envelope;
      if (e.v !== 1 || !Number.isSafeInteger(e.issued) || !Number.isSafeInteger(e.expires) ||
          e.issued < at - 60000 || e.issued > at + 30000 || e.expires <= at ||
          e.expires <= e.issued || e.expires - e.issued > MAX_TTL) throw new BadRequest();
      const idBytes = decode64(e.id, 16), envelopeSignature = decode64(e.signature, 64);
      const token = parseToken(e.token), writer = await store.getWriter(token.senderID);
      if (writer?.enabled !== true || !isSigningKey(writer.signingPublicKey)) return rejected(403, true);
      const unsigned = JSON.stringify({v:1,id:e.id,token:e.token,issued:e.issued,expires:e.expires});
      const verifiedEnvelope = await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'}, writer.signingPublicKey, envelopeSignature, enc.encode(CREATE_DOMAIN + unsigned));
      if (!verifiedEnvelope || !await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'}, writer.signingPublicKey, token.signature, token.signed)) return rejected(403, true);
      const result = await store.put({
        idHash:await hash(crypto, idBytes), requestHash:await hash(crypto, enc.encode(unsigned)),
        senderID:token.senderID, token:e.token, issued:e.issued, expires:e.expires, now:at
      });
      if (result === 'created' || result === 'exists') return response(200, {id:e.id, expires:e.expires}, true);
      return rejected(({conflict:409, limited:429, denied:403})[result] || 503, true);
    } catch (error) {
      return rejected(error instanceof BadRequest ? error.status : 503, true);
    }
  };
}
