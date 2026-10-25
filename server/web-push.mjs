// Web Push wire format: RFC 8291 (ECDH/HKDF), RFC 8188 (aes128gcm),
// RFC 8292 (VAPID). Only a lookup capability is carried, never a surname.
// WebCrypto is used in both Deno and Node; there are no runtime dependencies.
const encoder = new TextEncoder();
const MAX_TTL = 86400;
const MAX_ENDPOINT_LENGTH = 2048;
const RECORD_SIZE = 4096;
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fail = () => { throw new Error('Push configuration is invalid.'); };
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;

function bytes(value, length) {
  if (typeof value !== 'string' || value.length !== Math.ceil(length * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) fail();
  let result;
  try {
    const plain = value.replace(/-/g, '+').replace(/_/g, '/');
    result = Uint8Array.from(atob(plain + '='.repeat((4 - plain.length % 4) % 4)), c => c.charCodeAt(0));
  } catch { fail(); }
  if (result.length !== length || b64(result) !== value) fail();
  return result;
}
function concat(...arrays) {
  const result = new Uint8Array(arrays.reduce((n, value) => n + value.length, 0));
  let offset = 0;
  for (const value of arrays) { result.set(value, offset); offset += value.length; }
  return result;
}
function endpoint(value) {
  if (typeof value !== 'string' || value.length > MAX_ENDPOINT_LENGTH || /[\s\\]/.test(value)) fail();
  let url;
  try { url = new URL(value); } catch { fail(); }
  // Exact provider hosts, not arbitrary client-controlled network targets.
  const apple = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+push\.apple\.com$/.test(url.hostname);
  const allowed = apple || url.hostname === 'fcm.googleapis.com' || url.hostname === 'updates.push.services.mozilla.com';
  // An explicit port, including :443, is disallowed before URL normalization.
  const authority = value.match(/^https:\/\/([^/]+)/i)?.[1] || '';
  if (!allowed || url.protocol !== 'https:' || url.username || url.password || url.port ||
      authority.includes(':') || url.hash || url.search || url.pathname.length <= 1) fail();
  return url;
}

export async function validateSubscription(subscription, {crypto = globalThis.crypto} = {}) {
  try {
    if (!exact(subscription, 'endpoint,keys') && !exact(subscription, 'endpoint,expirationTime,keys')) fail();
    if ('expirationTime' in subscription && subscription.expirationTime !== null &&
        (!Number.isSafeInteger(subscription.expirationTime) || subscription.expirationTime <= 0)) fail();
    if (!exact(subscription.keys, 'auth,p256dh')) fail();
    const url = endpoint(subscription.endpoint), publicBytes = bytes(subscription.keys.p256dh, 65);
    bytes(subscription.keys.auth, 16);
    if (publicBytes[0] !== 4) fail();
    // WebCrypto import rejects invalid/infinite points, as required by RFC 8291 §7.
    await crypto.subtle.importKey('raw', publicBytes, {name:'ECDH', namedCurve:'P-256'}, false, []);
    return {endpoint:url.href, keys:{p256dh:subscription.keys.p256dh, auth:subscription.keys.auth}};
  } catch { fail(); }
}

export async function createVapidKeys({crypto = globalThis.crypto} = {}) {
  const pair = await crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, true, ['sign', 'verify']);
  return {
    publicKey:b64(await crypto.subtle.exportKey('raw', pair.publicKey)),
    privateKey:await crypto.subtle.exportKey('jwk', pair.privateKey)
  };
}

async function hkdf(crypto, ikm, salt, info, length) {
  const material = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF', hash:'SHA-256', salt, info}, material, length * 8));
}

// Exported only to make RFC known-answer interoperability checks possible.
// Production sendWebPush always generates fresh sender ECDH keys and salt.
export async function encryptPushPayload(subscription, plaintext, {
  crypto = globalThis.crypto, senderPair, salt
} = {}) {
  const normalized = await validateSubscription(subscription, {crypto});
  if (!(plaintext instanceof Uint8Array) || plaintext.length > 256) fail();
  const uaPublic = bytes(normalized.keys.p256dh, 65), auth = bytes(normalized.keys.auth, 16);
  const peer = await crypto.subtle.importKey('raw', uaPublic, {name:'ECDH', namedCurve:'P-256'}, false, []);
  const pair = senderPair || await crypto.subtle.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const shared = await crypto.subtle.deriveBits({name:'ECDH', public:peer}, pair.privateKey, 256);
  const ikm = await hkdf(crypto, shared, auth, concat(encoder.encode('WebPush: info\0'), uaPublic, asPublic), 32);
  const recordSalt = salt || crypto.getRandomValues(new Uint8Array(16));
  if (!(recordSalt instanceof Uint8Array) || recordSalt.length !== 16) fail();
  const cek = await hkdf(crypto, ikm, recordSalt, encoder.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(crypto, ikm, recordSalt, encoder.encode('Content-Encoding: nonce\0'), 12);
  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv:nonce, tagLength:128}, aesKey, concat(plaintext, Uint8Array.of(2))));
  const header = new Uint8Array(21);
  header.set(recordSalt, 0);
  new DataView(header.buffer).setUint32(16, RECORD_SIZE, false);
  header[20] = 65;
  return concat(header, asPublic, ciphertext);
}

async function vapidHeader(keys, audience, subject, now, crypto) {
  const publicBytes = bytes(keys.publicKey, 65);
  if (publicBytes[0] !== 4 || !keys.privateKey || keys.privateKey.kty !== 'EC' || keys.privateKey.crv !== 'P-256') fail();
  bytes(keys.privateKey.d, 32);
  if (b64(publicBytes.slice(1, 33)) !== keys.privateKey.x || b64(publicBytes.slice(33)) !== keys.privateKey.y) fail();
  let subjectURL;
  try { subjectURL = new URL(subject); } catch { fail(); }
  if (subjectURL.protocol !== 'https:' || subjectURL.username || subjectURL.password || subjectURL.hash) fail();
  const key = await crypto.subtle.importKey('jwk', keys.privateKey, {name:'ECDSA', namedCurve:'P-256'}, false, ['sign']);
  const header = b64(encoder.encode(JSON.stringify({typ:'JWT', alg:'ES256'})));
  const claims = b64(encoder.encode(JSON.stringify({aud:audience, exp:Math.floor(now / 1000) + 3600, sub:subjectURL.href})));
  const signingInput = header + '.' + claims;
  const signature = new Uint8Array(await crypto.subtle.sign({name:'ECDSA', hash:'SHA-256'}, key, encoder.encode(signingInput)));
  if (signature.length !== 64) fail(); // JWT ES256 uses fixed-width P1363 r || s.
  return 'vapid t=' + signingInput + '.' + b64(signature) + ', k=' + keys.publicKey;
}

export async function sendWebPush(subscription, keys, payload, {
  subject = 'https://evgk724.github.io/pso-code-viewer/', ttl = MAX_TTL,
  fetch:fetcher = globalThis.fetch.bind(globalThis), now = Date.now,
  crypto = globalThis.crypto, timeout = 6000
} = {}) {
  let timer;
  try {
    const at = typeof now === 'function' ? now() : now;
    if (!Number.isSafeInteger(at) || !Number.isInteger(ttl) || ttl < 0 || ttl > MAX_TTL ||
        !Number.isInteger(timeout) || timeout < 1 || timeout > 30000) fail();
    if (!exact(payload, 'expires,id,v') || ![1,2].includes(payload.v) || !Number.isSafeInteger(payload.expires) ||
        payload.expires <= at || payload.expires > at + MAX_TTL * 1000) fail();
    if (payload.id === null) {
      // A user's own opt-in test can open the app home without a patient link.
      if (payload.v !== 1 || payload.expires > at + 300000) fail();
    } else bytes(payload.id, 16);
    const normalized = await validateSubscription(subscription, {crypto});
    const url = endpoint(normalized.endpoint);
    const body = await encryptPushPayload(normalized, encoder.encode(JSON.stringify({v:payload.v,id:payload.id,expires:payload.expires})), {crypto});
    const authorization = await vapidHeader(keys, url.origin, subject, at, crypto);
    const controller = new AbortController();
    timer = setTimeout(() => controller.abort(), timeout);
    const response = await fetcher(url.href, {
      method:'POST', credentials:'omit', redirect:'error', referrerPolicy:'no-referrer', cache:'no-store',
      headers:{'Authorization':authorization, 'Content-Encoding':'aes128gcm', 'Content-Type':'application/octet-stream',
        'TTL':String(Math.min(ttl, Math.max(0, Math.floor((payload.expires - at) / 1000)))), 'Urgency':'normal'},
      body, signal:controller.signal
    });
    // Never log or read provider response bodies: they can repeat endpoint data.
    await response.body?.cancel().catch(() => {});
    if (response.status === 201 || response.status === 202) return {status:'accepted'};
    if (response.status === 404 || response.status === 410) return {status:'gone'};
    if (response.status === 429) return {status:'limited'};
    return {status:'failed'};
  } catch {
    return {status:'failed'};
  } finally { clearTimeout(timer); }
}
