# Yandex native adapter: staged migration

This is a separate native YDB backend for the existing signed/encrypted protocol.
It does not proxy requests to Supabase. Existing GitHub Pages and bots are not
modified by building or testing this package. No live rollout is implied.

## Stage 1: private database validation

Build with Python 3.7+:

```
python3 scripts/package-yandex.py --output /tmp/pso-yandex-runtime.zip \
  --endpoint grpcs://ydb.serverless.yandexcloud.net:2135 \
  --database /ru-central1/CLOUD_ID/DATABASE_ID
```

Use the actual lowercase IDs in the database argument. Dependencies are locked:
Node.js 22, ydb-sdk 5.11.1, @simplewebauthn/server 14.0.3. The ZIP omits
node_modules; Cloud Functions installs package.json/package-lock.json dependencies.
Entrypoint `index.handler`, 512 MiB, 120-second setup timeout, attached runtime
service account with database-scoped ydb.editor, no VPC needed for the public
TLS YDB endpoint. Use the short SETUP-RU.txt instructions for the console.

**Keep the function private.** No allUsers/allAuthenticatedUsers invocation
binding. The function service-account token authenticates to YDB, not the caller.
Cloud Functions `integration=raw` can forward an unwrapped event, so event-shape
checks alone are NOT authentication. `PSO_SETUP_MODE=on` enables only explicit
setup actions; normal HTTP stays disabled. Invoke `initialize`, then `selftest`
from the IAM-authorized console. Test fixtures never contain real patients.
The JSON KV table is `pso_state`; nullable Utf8 key/value, nullable Timestamp
expires_at, key PK, TTL on expires_at. Runtime enforces non-null keys/values and
logical expiry. Schema mismatch fails closed without altering existing tables.

Selftest tests read/write, rollback, logical expiry, cursor, concurrent increment,
recipient isolation, duplicate ID handling and revocation in a random namespace.
Failed cleanup leftovers are bounded to one hour (physical YDB TTL is asynchronous).
This is a live-store check, not end-to-end encryption/push/phone validation.

## Stage 2: dedicated origin and organizer

Create a dedicated API Gateway hostname (or dedicated custom HTTPS origin), not
a shared-origin Cloud Functions URL. Keep the function private; use a separate
invoker service account with functions.functionInvoker on this function only.
Specify Cloud Functions integration payload_format_version "1.0". Map GET/HEAD
for static assets and POST/OPTIONS `/api/pso-team`, `/api/pso-direct`,
`/api/pso-push`, `/api/pso-device-auth` to the function. Use exact routes or a
wildcard constrained by the runtime's file/route allowlist. The original Host
header must match PSO_VIEWER_ORIGIN; verify this in staging before rollout.

Set PSO_VIEWER_ORIGIN to the exact HTTPS origin with no trailing slash.
Set PSO_SETUP_MODE=off to serve the static shell. Until bootstrap, API calls
return organizer_setup_required. Install the viewer on the organizer's intended
phone and generate/copy its public card from settings → legacy exchange →
My card. The new origin has new browser keys; old non-exportable private keys
are not migrated. Verify the organizer device/card through a known channel.

The IAM operator sets PSO_ORGANIZER_CARD to that exact public card in function
environment and temporarily sets PSO_SETUP_MODE=on. Console invoke:
`{"action":"bootstrap"}`. No card from a request body is accepted. Existing
organizer/roster cannot be overwritten; an exact repeat is idempotent. The origin
and public card are pinned in config:organizer. Then set PSO_SETUP_MODE=off and
remove PSO_ORGANIZER_CARD from the active version. API runtime enforces the stored
origin pin. Keep earlier setup versions private and remove obsolete setup tags.

The organizer creates/approves invitations and signs recipients' grants in the
existing UI. A copied invitation alone does not authorize a phone. Register new
WebAuthn credentials and WebPush subscriptions on the new origin. No admin private
key, private device key, patient name or photo belongs in environment/config/logs.
VAPID private key is notification infrastructure state in YDB, not a decryption key.

## Stage 3: tests before switching any reports

Use synthetic patient strings/photos only. Check organizer bootstrap, verified
invite, neurologist review to cardiologist and ORIT, bot-only admission, wrong
recipient denial, revoked phone denial, new phone isolation, altered signatures,
expired messages, replay/idempotency, unread/read receipts, biometric unlock,
push from installed iPhone app and opening notification. Verify actual gateway
host/header behavior and all shell assets, MIME/CSP and service worker caching.
Only the shell is cached; API is no-store. Push carries generic opaque ID/expiry.

Legacy Supabase shortlinks are disabled on the new origin. Existing links/messages
stay on the old installation; old keys and ciphertext are not silently migrated.
The team route remains for invites/roles and signed legacy team protocol. New
messaging uses the direct route and independently signed recipient grants.

Configure only the NEW viewer bot's service-config.json after tests:

```
{"team_endpoint":"https://DEDICATED_HOST/api/pso-team",
 "direct_endpoint":"https://DEDICATED_HOST/api/pso-direct",
 "viewer_url":"https://DEDICATED_HOST/"}
```

Connect the new bot identity on the new origin, approve/sign its grant and verify
recipients before background start. Keep old bot configuration/state unchanged.
No bulk resend of existing reports. Old Pachca sending continues until explicitly
stopped. Database state and APIs are independent from the hospital report files.

## Operational limits and verification

Transactions retry definite ABORTED only. Ambiguous commit/transport errors are
not blindly retried; message IDs make client retry idempotent. SDK logging is
silenced, errors are canned. Driver is closed per request, cleanup wait bounded.
Large encrypted photo payloads are separate from inbox/queue metadata. Explicit
member, body, rate, daily photo and global payload limits still apply. Set billing
alerts/quotas; low usage is not a guarantee of zero billing. No patient payload
or request body logging should be enabled at the gateway/function layer.

Local checks:

```
NODE_PATH=/path/to/installed/dependencies/node_modules \
node --experimental-vm-modules --test tests/*.test.mjs server/*.test.mjs server/yandex/*.test.mjs
```

Memory-fixture tests do not prove real YDB isolation. The opt-in YDB adapter test
and private console selftest must pass. WebAuthn/push require real device tests.
Russian hosting/encryption alone do not establish legal compliance; deployment
and access policies remain a hospital responsibility.

Official references:
- https://yandex.cloud/ru/docs/functions/lang/nodejs/context
- https://yandex.cloud/ru/docs/functions/lang/nodejs/dependencies
- https://yandex.cloud/ru/docs/functions/concepts/function-invoke
- https://yandex.cloud/ru/docs/api-gateway/concepts/extensions/cloud-functions
- https://yandex.cloud/ru/docs/ydb/security/
