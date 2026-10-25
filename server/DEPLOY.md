# Direct viewer backend — deployment and verification

## v10 direct inbox deployment

The direct viewer uses the same approved project and existing device identities,
with two additional endpoints: `pso-direct` and `pso-device-auth`. The old
`pso-team`, `pso-push` and `pso-shortlinks` endpoints remain for compatibility;
the old Pachca bot and the new direct bot have separate local configuration and
state. Installing this release does not install or start a bot on a hospital PC.

Apply `device-auth-schema.sql`, then `direct-schema.sql`. If an earlier copy of
the device-auth schema with bounded regex repetitions above 255 was already
applied, also apply `direct-regex-fix.sql`; the current source schema includes
that correction. `device-auth-clock-fix.sql` updates the earlier gate definition
to use invocation time and fresh SQL state; current source also includes it.
Run `device-auth-verify.sql` and `direct-verify.sql` in their
rollback transactions. The latter deliberately refuses to run when real active
specialists exist: do not disable real members to make a test pass.

Deploy `server/device-auth-edge.ts` as `pso-device-auth` and
`server/direct-edge.ts` as `pso-direct`, including every recursive relative
dependency. Both use `verify_jwt=false` because every operation verifies its own
device signature, timestamp and one-use nonce. Keep service credentials only in
Edge environment variables. Set `PSO_VIEWER_ORIGIN` to the exact viewer origin;
the existing default is `https://evgk724.github.io`. A different origin also
changes the WebAuthn relying-party identity and requires a planned migration.

Direct messages expire within 24 hours. The private database holds encrypted
payloads, recipient-specific encrypted keys, opaque IDs, delivery/read metadata
and organizer-signed membership certificates. Surnames, comments, photos and
private device keys are not stored as plaintext by this backend. Payloads and
recipient copies are removed by `pso-direct-expiry` every five minutes; access
is denied immediately at expiry even when cleanup is delayed. Metadata audit
rows expire after seven days. Provider backups and previously downloaded copies
are outside these deletion guarantees.

Only bots create admissions; the organizer and neurologists create review
messages. The server enforces exactly the active intended specialty roster and
the client verifies its organizer-signed certificates before encryption. One
cardiologist, up to 25 intensivists and up to 25 separate bot identities are
allowed. Replacement activates the new approved key and revokes the old device
atomically; it cannot transfer decryption access to old messages. Revocation
also removes the old push subscription.

Generic notifications contain only `{v:2,id,expires}` and open `#m=id` in the
viewer. The new bot's `retry` operation drains notices from both bot admissions
and doctor reviews. Durable leases and bounded backoff prevent simultaneous
workers from claiming the same attempt. Provider acceptance is not delivery;
the separate acknowledgement records opening, never completion of a consult.
The optional passkey gate checks user verification before releasing ciphertext.
An enabled device session lasts at most ten minutes and remains bound to its
active device identity. Actual iPhone Face ID, Home Screen opening and push
delivery still require device checks.

### v10 validation record

The direct handler's eight automated tests cover real signatures/encryption,
roles, certificates, recipient isolation, revocation, expiry, unlock gating,
idempotence, push retries and replacement. The complete local release suite
passes 231 tests; the separately packaged Python bot suite passes 75 tests.

The following migrations are applied in the approved dedicated project:
`pso_optional_device_unlock`, `pso_direct_encrypted_inbox`,
`pso_device_unlock_regex_bounds` and `pso_device_unlock_live_clock`.
Both `pso-device-auth` and `pso-direct` are ACTIVE at version 1. The final
`device-auth-verify.sql` and `direct-verify.sql` rollback transactions passed
against the deployed database. These checks covered actual database privileges,
nonce replay, role restrictions, recipient isolation, expiry, access revocation,
phone replacement, acknowledgement counts and durable push leases. Their
synthetic records were rolled back and no notifications were transmitted.
Post-migration security advisors reported 21 INFO findings for deliberately
private tables with RLS and no browser policies, with no WARN or ERROR findings.
The live Python-to-Edge integration passed 29 checks using synthetic devices and
three fictitious messages. It verified correct decryption and routing,
idempotent retries, acknowledgements and denial of another recipient's access.
Live `pso-device-auth` status and enrollment-option generation also passed with
the pinned SimpleWebAuthn 14.0.3 package in the deployed runtime. These checks
did not enroll a real passkey or exercise native Face ID. No push subscriptions
were provisioned and no notifications or Pachca messages were sent. Fixture
cleanup completed and confirmed zero remaining synthetic members.
Photo encryption and metadata stripping were checked by automated tests; this
does not claim live photo delivery or native phone verification.

This release improves technical confidentiality. It is not a certification of
medical-system security or a legal anonymisation claim. The current dedicated
Supabase region is outside Russia; follow `HOSTING-MIGRATION.md` for an approved
replacement before making any claim about Russian data-localisation compliance.

## Legacy v9 team-link deployment

The approved dedicated Supabase project is `spugfikalpihorcwcdqc`. The current
role-controlled service is `pso-team`, at
`https://spugfikalpihorcwcdqc.supabase.co/functions/v1/pso-team`.
The applied migrations are `pso_team_roles_and_group_links`,
`pso_team_inviter_index` and `pso_require_team_roles_for_new_links`; the Edge
Function is deployed and ACTIVE, version 1. Legacy creation is denied; the old
resolver and its existing records remain available.
One administrator was bootstrapped from the previously verified, enabled writer.
No actual administrator identifier, public card, name or enrolment row belongs in
this public repository.

The sections labelled **legacy** below document the previous short-link creation
pipeline. They are not the enrolment or creation procedure for team links.
`pso-push` registration and subscription consent remain in use; team notifications
use a separate claim path and leave the earlier push pipeline intact.

### Verified for this deployment

- SQL integration checks passed in a rollback transaction before migration.
  They exercised the actual anonymous, authenticated and service roles, role
  approval, recipient sets, idempotency, consent, revocation, quotas and cleanup.
- The complete local Node suite passed: 160 tests. The team handler's 14 tests
  include real signature/encryption checks, delayed first creation after a
  network outage, and rejection of an unexpected push recipient.
- Safe live HTTP checks passed with a fresh synthetic identity: signed status
  returned `200`/`unregistered`, a repeated nonce returned `409`, an unregistered
  directory request returned `403`, a foreign origin returned `403`, and the
  allowed-origin preflight returned `204` with the exact origin.
- A deployed HTTP/SQL integration run passed 29 checks with five synthetic
  devices and a fictitious surname. Two intensivists independently decrypted
  different recipient ciphertexts from the same ORIT link; cross-key decryption
  and wrong-group access failed. Bot-only admissions, neurologist reviews,
  idempotent retry and rejection of incomplete/extra recipient sets passed.
  No push subscriptions were provisioned and no Pachca messages were sent.
- Security advisors reported only the expected INFO findings for private tables
  with RLS and no browser policies. The missing inviter foreign-key index was
  added. Fresh unused-index INFO findings are intentional; retain those indexes.

The team frontend is published on the existing GitHub Pages origin. An existing
browser device key and local demo decryption survived the update. The bot archive
is prepared, but installation on the hospital PC, real doctor activation and
native iPhone notification delivery remain device checks below.

### Roles and encrypted records

| Role | May create | Receives team ciphertext |
| --- | --- | --- |
| Administrator | Review links; invitations and approvals | None automatically |
| Neurologist | Review links only | None automatically |
| Bot | Admission links only | None |
| Cardiologist | Nothing | Cardiology group |
| Intensivist | Nothing | ORIT group |

In the current shared roster, at most one cardiologist and 25 bots can be active.
The ORIT group supports up to 25 active intensivists. One random link ID holds a separate existing `PSO1`
encrypted token for every active specialist in the chosen group. There is no
shared group private key. The server checks the complete current recipient set
under the same transaction lock used for approval/revocation; a stale list cannot
silently omit a newly approved recipient or include a revoked one.

Invitations expire after 48 hours. Possession of an invitation creates only a
pending, signed request bound to that device's existing key. The administrator
must verify the requesting doctor's device fingerprint through an established
channel and explicitly approve it. A forwarded invitation alone does not grant
access. Roles and device keys are not inferred from Pachca chat membership, an
email address, or the public card's display label. Each active member can read
the authenticated public-card directory so recipients can consent to known
senders for push notifications; pending and anonymous devices cannot read it.

The private team schema stores doctor display names, roles, public cards,
invitation/key bindings, hashed random IDs, signed ciphertext and expiry data.
It stores no plaintext patient surname or device private key. Push subscriptions
and VAPID material remain in the existing private push schema. This is encrypted,
role-controlled messaging, not a guarantee of legal anonymisation or a certified
medical information system. Revocation denies future team resolution; it cannot
erase plaintext or ciphertext already obtained by a recipient.

### Deployment and bootstrap procedure

1. Inspect the approved project and existing migrations. Apply the reviewed
   `team-schema.sql` through the project's migration workflow. Keep
   `pso_team_private` outside exposed Data API schemas. Its tables have RLS, no
   browser policies or grants, and service-role-only invoker RPCs. Confirm the
   single once-a-minute `pso-team-cleanup` job exists and runs successfully.
2. Bootstrap exactly the previously verified administrator through a separate
   authorised admin query. Select the approved, enabled writer's signing key
   from the existing private writer table; do not accept an arbitrary client
   claim or choose the first row without verifying its identity. Insert the team
   administrator with that known device ID and signing key. The first valid
   self-signed request binds its public card after matching the signing key.
   Keep actual bootstrap values and results out of source control, logs,
   screenshots and deployment documentation. Do not create a public bootstrap
   endpoint or issue administrator invitations.
3. Deploy these files preserving paths, with entrypoint `server/team-edge.ts`,
   function name `pso-team`, and `verify_jwt=false`:

   - `server/team-edge.ts`
   - `server/team-handler.mjs`
   - `server/web-push.mjs`
   - `docs/exchange.mjs`

   Every operation authenticates the existing device signature, fresh timestamp
   and nonce under the `PSO-TEAM-v1` signature domain before role-controlled RPCs.
   Disabling gateway JWT verification applies only to this custom-authenticated
   function. CORS allows exactly `https://evgk724.github.io`; it is not the
   authentication mechanism. Bot requests use the same Origin and signatures.
4. Keep `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` server-only. Publish only
   the public endpoint URL in the client. Keep the exact Supabase origin in CSP;
   do not broaden CSP, export a service key, or add a browser database key.
5. Run `team-verify.sql` as a rollback test before real specialist enrolment; its
   uniqueness fixtures assume there is no real active cardiologist. Do not run
   it unchanged against an already enrolled roster. Run the full Node suite and
   review security/performance advisors. Use synthetic identities and fictitious
   surnames for HTTP tests; do not use a doctor's private key or a real patient.

### Cutover order and remaining checks

1. Deploy and verify team SQL and Edge code first. Preserve the existing GitHub
   Pages origin/path, IndexedDB key stores, manifest identity and scope.
2. Publish the reviewed team-aware frontend and bot adapter. Keep the previous
   release available for rollback. Confirm the existing administrator device can
   open its team panel without clearing site data or reinstalling the PWA.
3. The administrator issues each intended doctor/bot an invitation, checks the
   pending device fingerprint, and approves its role. Only the intended
   cardiologist should hold the cardiologist role; only the ORIT specialists
   should hold the intensivist role. Configure and verify the bot's report path
   separately; a server deployment does not install code on the hospital PC.
4. With synthetic data, check one cardiology and one ORIT group link on the
   intended devices. Each specialist must decrypt their own entry; unrelated,
   pending and revoked devices must fail. Verify that only the bot can create
   admission links and neurologists can create review links. Check the existing
   admission-routing rules independently of the encryption change.
5. Once the team frontend and bot are ready, apply the separate reviewed
   `legacy-create-disable.sql`. This makes `pso_shortlink_put` deny all new legacy
   creation while preserving old records and their resolution. It is the final
   server cutover step: do not apply it before the new clients are available,
   and do not claim bot-only admission enforcement while legacy creation remains
   enabled. Do not delete the old resolver or re-enable legacy creation silently.
6. Verify a previously issued legacy link still resolves. Team resolution falls
   back to the old endpoint only on `404` (unknown/expired), never on `403` for a
   known protected link. Verify fictitious messages in native Pachca and each
   intended Home Screen app, including background notification opening and the
   copy/paste fallback. Automated tests do not establish native clipboard or
   APNs behaviour.

### Retry, expiry and push behaviour

Team links have a maximum 24-hour lifetime. Each request needs a fresh outer
signature timestamp and nonce. The inner creation payload may retain its original
timestamp while its expiry is still in the future; retries after an outage must
keep the exact ID and encrypted payload. An identical committed request returns
the existing result without extending expiry or sending push again. A conflicting
payload returns `409`/`id_conflict`. A `409`/`roster_changed` explicitly means no
link was committed and permits a new recipient snapshot and freshly encrypted
payload; network errors and other ambiguous failures do not.

The team push path uses the existing recipient subscription and explicit sender
consent. One atomic claim per link/recipient prevents duplicate notification
attempts. The payload contains only version, opaque ID and expiry. Notification
failure never rolls back the encrypted link. `accepted`, `partial` and
`unavailable` describe provider acceptance, not delivery/read receipts; identical
creation retries report `unavailable` because they do not repeat push. A provider
404/410 removes only the exact stale endpoint, preserving a newer subscription.

Server expiry denies retrieval even if cleanup is delayed. Cleanup removes
expired live links and their entries/claims, old nonce/quota records and expired
invitations. It does not promise deletion from provider backups or recipient
copies. Database quotas bound accepted requests and stored records, not total
Edge invocation costs or all denial-of-service traffic.

## Legacy single-recipient short-link deployment

The material below records the earlier deployment and historical verification.
Its writer-enrolment and creation instructions apply only to that legacy service.
For new team links, use the role-controlled procedure above.

The approved dedicated Supabase project is `spugfikalpihorcwcdqc`. Its database,
cleanup job and `pso-shortlinks` Edge Function are deployed. The configured release
uses `https://spugfikalpihorcwcdqc.supabase.co/functions/v1/pso-shortlinks` and permits
that exact origin in CSP. Keep the existing GitHub Pages origin/path and browser
key stores. This status does not itself assert frontend publication.

### Legacy verification status

- [x] Local client, crypto, UI, hosting and generic handler suite: 134 tests passed,
  including a receiver-sensitive browser-fetch regression test.
- [x] Live HTTP create/resolve and recipient decryption using synthetic devices;
  `ShortLinkClient` produced a 67-character URL. Wrong-recipient decryption failed.
- [x] Both envelope and enclosed-token signature checks; unknown and disabled
  writers returned 403; identical retries were idempotent; changed requests for
  an existing ID returned 409; stale creation time returned 400.
- [x] Live CORS/preflight; another origin returned 403, GET returned 405 and an
  oversized request returned 413.
- [x] Twelve concurrent live creation requests yielded exactly ten successes and
  two quota rejections. SQL checks also passed.
- [x] An expired saved record returned 404. The cleanup job subsequently removed
  it, and successful Cron runs were confirmed. The synthetic HTTP test writer
  was disabled after the checks.
- Enrol each intended sender’s existing verified public card through the admin
  procedure below. Until enrolled, a device’s creation request is denied;
  recipient-only decryption needs no writer entry. Do not publish real enrolments.
- [ ] After frontend publication and enrolment, verify a fictitious message in
  native Pachca and between the intended phones. HTTP and simulated-UI tests do
  not establish native clipboard/PWA behaviour.

The procedure below documents repeatable deployment and checks. It does not
authorise replacing this project, changing domains, or reusing another project.

### Legacy stored records

Each record contains the existing signed `PSO1` ciphertext, its server expiry,
hashed random link ID, hashed create request and sender public-key ID. The writer
allowlist contains the device's existing public signing key and enabled state.
There are no patient names, doctor names, email addresses or private keys here.
The service can nevertheless observe timing and link access. Do not describe this
as guaranteed legal anonymisation or as a certified medical information system.

Only approved existing devices may create records. The browser signs the entire
create envelope using its existing non-exportable signing key; the handler checks
both the envelope signature and the enclosed message signature. Existing contacts
and recipients remain responsible for verifying their public-card fingerprints.

### Legacy provisioning

1. For a new deployment, select and approve a **new, separate** Supabase project,
   including organisation, region and any quoted cost. Do not reuse an unrelated
   project. Inspect existing schema before applying it. Review project logging
   and backup retention. The current release uses the approved project above.
2. Apply `supabase-schema.sql` as project administrator. The private schema must
   **not** be added to exposed Data API schemas. Keep `public` available for the
   three RPC functions, whose execution grants are service-role only.
3. Enable Supabase Cron (`pg_cron`). Create exactly one once-a-minute job:

   ```sql
   select cron.schedule('pso-shortlink-cleanup', '* * * * *',
     'select pso_shortlink_private.cleanup()');
   ```

   Check `cron.job` and `cron.job_run_details` after the first run. Check retention
   of cron logs as part of deployment. API resolution denies expired records even
   if the cleanup job is delayed or stopped. Deletion from the live table does
   **not** imply deletion from provider backups or existing recipient copies.
4. Obtain each intended writer's existing verified public card by an authorised
   channel. Validate it using `importPublicCard` from `docs/exchange.mjs`, including
   its SHA-256 identity/fingerprint. Extract `sender_id` from the validated card
   identity and `signing_spki` from its `s` field. Do not hand-type the values or
   trust an unchecked claimed identity. Add it through a parameterised admin
   query to `pso_shortlink_private.writers`, setting `enabled=true`. Do not put real
   cards or allowlist rows in this public repository. There is deliberately no
   public self-enrolment endpoint. Recipient-only devices need no allowlist entry
   to read a link; cryptographic decryption still requires the recipient key.
5. Deploy `supabase-edge.ts` and `shortlink-handler.mjs` together as an Edge Function
   named `pso-shortlinks`; set the entrypoint to `supabase-edge.ts`. `verify_jwt=false`
   is needed because the handler itself authenticates device-signed creation
   requests. It must not be disabled on a different function. The exact allowed
   browser origin is `https://evgk724.github.io`. CORS is not authentication.
6. The edge adapter uses Supabase's server-only `SUPABASE_URL` and legacy
   `SUPABASE_SERVICE_ROLE_KEY` built-in environment variables. Never export those
   values into frontend code, URLs, user messages, logs or screenshots. No extra
   dependency package is required. A new project without legacy keys requires an
   adapter update to the documented secret-key API before deployment, not putting
   a secret in the browser.

### Legacy deployment and regression checks

Use a fresh synthetic test device and fictitious surname, not a doctor's private
keys or a real patient. Do not infer database correctness from JavaScript tests.

- Run the generic handler's tests and the existing client/crypto tests.
- Verify anonymous and authenticated Data API roles cannot list/read/write the
  private tables, execute any of the three RPC functions, or call cleanup.
- Verify an unknown/disabled writer, altered envelope, altered token signature,
  expired request, other browser origin, oversize body and GET request are denied.
- Create, resolve and decrypt one synthetic short link end to end. The recipient
  check and signature verification must still run in the viewer.
- Repeat exactly the same create request: return the same record without adding
  quota, overwriting the ciphertext or extending its expiry. A changed request
  using the same ID must conflict.
- Concurrently create enough synthetic requests to verify exact limits:
  10/minute/device, 200/day/device, 5000/day across writers. Counters are based on
  server UTC time and are independent of message expiry/deletion.
- Disable a writer while requests are in progress; confirm subsequent insertions
  are denied. Disabling creation is not a revocation of already-issued messages.
- Verify that server expiry denies retrieval, even with a deliberately incorrect
  client clock. Verify the cleanup job removes the expired live row.
- Run Supabase security/performance advisors and review any findings.
- Only after those checks, put the **public endpoint URL alone** into the client
  configuration. Add only that broker's exact HTTPS origin to the `connect-src`
  CSP in `docs/index.html` (the configured release permits `'self'` and the exact
  dedicated broker origin).
  Verify the browser's actual fetch/preflight, then publish the frontend. Do not
  replace the CSP with a wildcard. No Supabase browser API key is needed.

Database quotas bound accepted writes and storage. They do not provide a complete
edge-request DDoS defence or bound the provider's total invocation cost; review the
project's gateway controls, service limits and billing alerts before general use.

### Legacy implementation notes

`pso_shortlink_put` uses one transaction advisory lock for low-volume admission.
This intentionally serializes accepted writes so global and per-writer counters
cannot race across Edge Function instances. Reads are indexed by the SHA-256 hash
of the raw 16-byte random link ID. There is no user-supplied destination URL and no
redirect, listing or overwrite API. JSON responses are no-store, and request IDs
are sent in POST bodies, not URL paths/query strings.

The SQL file is the tested schema definition, not a generated migration history
entry. Follow the project's Supabase workflow when recording migrations; do not
silently apply it to another project.

Documentation checked:
- https://supabase.com/docs/guides/functions/secrets
- https://supabase.com/docs/guides/api/securing-your-api
- https://supabase.com/docs/guides/cron
- https://www.postgresql.org/docs/current/explicit-locking.html


## Existing Web Push registration and legacy delivery

Registration, consent, the private VAPID key and subscription storage remain in
use by the team service. The legacy link ownership and writer checks described
below apply to `pso-push`'s earlier single-recipient notification path; team group
delivery uses `pso_team_push_claim` and `pso_team_push_finish` instead. Keep the
existing service available for subscription management and historical links.

The dedicated `pso-push` function uses the same project and exact browser origin.
It does not replace `pso-shortlinks` or change the Linux bot. Apply the reviewed
`push-schema.sql` once; the applied migration is `pso_private_web_push`. Keep
`pso_push_private` outside exposed API schemas. Its tables have RLS with no browser
policies or grants; service-role-only RPCs are the only server entry points. The
INFO advisor `rls_enabled_no_policy` is intentional for these private tables:
https://supabase.com/docs/guides/database/database-linter?lint=0008_rls_enabled_no_policy
New cleanup indexes can initially report `unused_index`; retain them for expiry
queries rather than weakening the design to silence a fresh-install advisory.

Deploy these four files preserving their paths, with entrypoint
`server/push-edge.ts`, function name `pso-push`, and `verify_jwt=false`:

- `server/push-edge.ts`
- `server/push-handler.mjs`
- `server/web-push.mjs`
- `docs/exchange.mjs`

Disabling gateway JWT verification is specific to this function: the handler
verifies each device's ECDSA signature, nonce, timestamp and operation data.
The only unsigned operation returns the public VAPID key. A P-256 VAPID pair is
created lazily and atomically stored once in the private database. Never return,
log, export or commit its private part. No new browser API key is required.

A device can register/unregister only its own subscription. Notifications require
an existing enabled short-link writer, a live link owned by that writer, and
recipient consent to that sender. The recipient comes from the stored signed
ciphertext, never a caller-supplied recipient field. Only Apple, FCM and Mozilla
HTTPS push endpoints are accepted; redirects are refused. Registration itself
sends nothing. A test sends only to the caller's own subscription.

One delivery claim per short link prevents repeat notifications. Failed sends do
not delete or modify the encrypted link, and are not automatically retried.
A provider 404/410 removes only the exact stale subscription, not a replacement.
HTTP acceptance is not a delivery/read receipt. Neither notification title/body
nor encrypted push payload contains a patient name, department or comment.
The payload contains only a version, opaque lookup ID and expiry.

`pso-push-cleanup` runs once per minute. It removes old replay entries, quotas,
claims and subscriptions not refreshed for 90 days. Check Cron run status. This
is not a promise of erasure from provider backups.

Verification:

1. Run the full Node test command from README. Transport tests include the RFC
   8291 vector and independent ciphertext/VAPID validation.
2. Run `push-verify.sql` in its rollback transaction. It checks actual SQL roles,
   ownership, consent, replay protection, rate limits, capacity, expiry and cleanup.
3. Review Supabase security and performance advisors. Do not grant browser roles
   access to private tables just to remove an informational RLS finding.
4. Check live config plus signed register/status/unregister with a fresh synthetic
   identity and subscription, without calling test or sending to a real endpoint.
   Confirm replay rejection and that an unknown writer/link cannot notify.
5. On the intended iPhone, open the existing Home Screen icon, enable notifications
   by explicit button tap, and use the self-test. Then check a fictitious link for
   a consenting second phone. Check closed/background app launch, expired link,
   and fallback copy/paste. Automated browser tests do not establish APNs delivery.

No doctor key store, IndexedDB name, origin, manifest identity or scope changes.
Do not clear site data or reinstall the PWA to update it.
