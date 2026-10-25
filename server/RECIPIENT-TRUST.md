# Organizer-signed device grants

The direct-message directory alone is not trusted to select encryption keys.
Every recipient/sender device has an administrator-signed grant and clients pin
the administrator's public card during one-time enrollment. Actual organizer or
doctor cards, names, keys, tokens, and enrollment data do not belong in this repo.

## Wire format

Each directory member includes `approvalProof`:

```json
{
  "grant": {
    "v": 1,
    "subjectId": "32-byte canonical base64url device identity",
    "role": "cardiologist",
    "name": "Approved display name",
    "issued": 1790000000000,
    "expires": 1821536000000,
    "issuerId": "32-byte canonical base64url organizer identity"
  },
  "signature": "64-byte canonical base64url ECDSA P-256 P1363 signature",
  "issuerCard": "PSO-CARD1..."
}
```

The signature covers UTF-8 `PSO-RECIPIENT-GRANT-v1\0` concatenated with
compact `JSON.stringify(grant)` in precisely the field order shown above.
Python equivalent: `json.dumps(grant, ensure_ascii=False, separators=(',', ':'))`
after constructing the fields in that order. The signer uses ECDSA P-256/SHA-256.
Card identities already bind both the RSA encryption and EC signing public keys.
No patient content is present in a grant.

Validation requires exact grant/proof fields, canonical public cards and IDs,
the pinned organizer ID equal to both `issuerId` and the ID of `issuerCard`,
member ID equal to `subjectId` and its public-card identity, and exact role/name
agreement. The public-card label is not the authoritative display name. A grant
for `admin` may only authorize its own issuer. Timestamps are safe positive
integers in milliseconds, issuance is at most 30 seconds in the future, expiry
is still in the future and at most 365 days after issuance. Names are NFC,
trimmed, 1–60 Unicode code points, with no control/format characters.

## One-time trust setup

The organizer creates an invitation:
`https://viewer.example/path/#join=ID&organizer=PSO-CARD1...`.
The public card is in the fragment; it is not a private key. The intended doctor
or bot confirms the organizer fingerprint through the already known organizer
channel. The app saves that public root locally only after explicit confirmation.
The app never silently substitutes a root obtained from a directory/server reply.
Replacing the root needs a separate explicit confirmation.

The organizer may pin their own local device card, because the local private key
is already the enrollment authority. Existing doctors with old invitations need
one-time root confirmation. Existing active devices need one-time certification
by the organizer, then grants are signed automatically during approval or edits.
Names/roles changed by the organizer invalidate the previous grant. A replacement
phone gets its own new grant; old ciphertext cannot simply move to the new key.

## Server integration

`directory` returns active members including grants. Clients verify the directory
before encrypting and validate sender grants before accepting newly delivered
records. `admin_certify {id,approvalProof}` requires an already authenticated,
currently active administrator. The server verifies the grant against that
administrator's authenticated public card, matching current database ID/name/role,
then stores the grant. It must not infer administrator authority from the grant.
An update invalidates the prior proof; create fails closed for uncertified targets.
Bulk certification is an organizer action, not a backend self-signing operation.

## Limits

These grants stop a compromised directory from inserting a new attacker-controlled
key or escalating an existing key to a different role without an organizer
signature. They do not make server-managed revocation cryptographically immutable:
a malicious server can replay a still-valid old grant of a previously authorized
device. Current active-state checks remain mandatory. A previously downloaded
ciphertext remains readable by its holder; no remote deletion is claimed.
Compromised client code/hosting can still use in-browser private keys. A dedicated
origin and controlled deployments remain necessary defenses. Certificate expiry
must be clearly shown and renewed by the organizer; it is not silently extended.
