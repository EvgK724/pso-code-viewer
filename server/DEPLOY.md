# Short-link backend — deployment and verification

The approved dedicated Supabase project is `spugfikalpihorcwcdqc`. Its database,
cleanup job and `pso-shortlinks` Edge Function are deployed. The configured release
uses `https://spugfikalpihorcwcdqc.supabase.co/functions/v1/pso-shortlinks` and permits
that exact origin in CSP. Keep the existing GitHub Pages origin/path and browser
key stores. This status does not itself assert frontend publication.

## Verification status

- [x] Local client, crypto, UI, hosting and generic handler suite: 73 tests passed.
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
- [ ] Enrol intended doctors' existing verified public cards. No real doctor
  devices have been added yet. Until enrolled, a doctor's creation request is
  denied; recipient-only decryption needs no writer entry.
- [ ] After frontend publication and enrolment, verify a fictitious message in
  native Pachca and between the intended phones. HTTP and simulated-UI tests do
  not establish native clipboard/PWA behaviour.

The procedure below documents repeatable deployment and checks. It does not
authorise replacing this project, changing domains, or reusing another project.

## What is stored

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

## Provisioning

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

## Deployment and regression checks

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

## Implementation notes

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
