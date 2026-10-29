# Sender history and two-day messages

The v14 release adds a private, device-scoped sender archive. New direct-message
clients opt in by sending an additional self-addressed signed key envelope
alongside the original PSO2 ciphertext. The sender archive uses the exact same
encrypted payload as the delivered message. Recipient entries never receive the
sender envelope. The server holds neither patient plaintext nor decryption keys.

Recipient access ends at the signed `expires` value, at most 48 hours after
`issued`. Archive access ends at `issued + 90 days`. Archive expiry does not
extend recipient API access or ordinary message decryption. Archive decryption
uses a separate entry point that accepts only a message signed by and addressed
to the current device. The retained payload is still bound to the original
signed metadata, including the recipient expiry.

The backend stores the original recipient/device roster, server acceptance time,
first authenticated opening acknowledgement, and push-provider acceptance time.
These are operational records. A push-provider success is not a delivery receipt
from the phone, and an opening acknowledgement is not evidence that a clinical
action was completed. Failed acknowledgement transmission must not be displayed
as proof that the doctor never opened a message.

Archive reads require the original sender to remain active. Opening archived
content uses the existing device-unlock check; administrators have no additional
read access. A renamed recipient keeps the name/role snapshot captured at send
time. Revoked devices lose service access. Live message expiry and archive expiry
are separately enforced in all reads, even before physical YDB TTL cleanup.

Create is atomic for live delivery and the archive. Retained identifiers protect
against replay/id conflicts after the live message expires. Duplicate retries
must preserve server acceptance time, first-open time, roster and quota accounting.
Daily rate windows remain 24 hours. Archive byte accounting uses bounded time
buckets, so its 90-day retention does not force scans of all archived messages
inside a transaction. The archive storage cap is 250 MB.
The sender limit is 500 messages and 45 MB of encrypted payload per rolling
24 hours. The payload byte budget replaces the old count of 30 encrypted
payloads, so text-only group discussions are not mistaken for photo uploads.

Existing create request shapes remain valid. Old clients and the installed bot
keep sending under their old contract without opting into the new archive or its
storage cap. They cannot create decryptable sender copies retroactively. New
history operations do not change the delivery semantics of previously prepared
messages. Supabase/SQL history is unsupported.

## Automatic admissions

Bot 1.2 uses the existing OpenSSL RSA-OAEP/ECDSA implementation without adding
Python dependencies. Its new encrypted PSO1 plaintext has the exact fields
`n,d,j,i,x,g`: `j` is the 16-byte message ID and `g` is the direction. Ordinary
opening accepts this bound form for at most 48 hours, and checks its ID, group,
issued and expiry against authenticated direct-message metadata. The old
five-field PSO1 form keeps its original 24-hour limit.

The bot encrypts an additional `organizerToken` to its locally pinned organizer
card. At creation the server requires an active bot sender, `admission` kind,
cardiology/ORIT group, and an organizer ID that matches both the current configured
root and the issuer of the bot's approval. The organizer token, immutable sender
card and approval snapshot are retained for 90 days in a separate history index.
The organizer verifies that signed approval at the message's original issue time
and checks all decrypted metadata before displaying the archived surname.

Bot history is available only to the original organizer device while it remains
an active administrator. Root rotation gives the new root no access to old keys;
the original owner may retain its own old archive while still an active admin.
No bot-history privilege exposes another doctor's personal archive. Already
prepared old requests retain their exact ID, ciphertext and expiry; there is no
backfill, queue reset or repeat announcement after an upgrade.

## Group conversations

`group_reply` binds a `replyTo` ID; `discussion` starts a first-stage rehab
conversation. These PSO2 kinds are separate from the old private `reply` kind,
whose audience remains unchanged. New replies go to the current specialists of
that direction and all active PSO neurologists/administrators, excluding the
author and the bot. Only rehab1 permits standalone discussions by specialists.
Initial `review` and bot admission audiences remain unchanged.

A reply needs a live parent in the same direction and actual parent access as
an authorized recipient or its original sender. Current group membership alone
does not grant access to an old parent. The server repeats membership, signed
approvals and exact audience checks atomically. Group entry roles are captured
and checked on subsequent list/open/ack/push operations. Cross-direction access
and bot participation are denied. More than 25 target devices fails explicitly
with `group_too_large`; there is no silent partial send.

No YDB schema migration, bootstrap, setup or reinitialization is required.
Existing table TTL and transactional access are reused. Update all sender and
recipient PWAs before relying on two-day messages, because older installed
clients enforce a one-day maximum.
