# Participant-held attachments, version 1

This optional qntm client extension carries file bytes using existing QSP-1
signed encrypted envelopes and the relay's `/v1/send` and `/v1/subscribe` paths.
It requires compatible TypeScript/Python client builds; older clients may display
the `blobref` descriptor but cannot download the file. This document and source
implementation do not constitute a published SDK release.

File parts use a fresh standard **direct** invitation and separate random relay
channel for each attachment. Only its descriptor enters the parent conversation;
parts never appear as chat messages there. The invitation is inside the parent's
signed encrypted message. The relay sees routing, ciphertext size and timing,
not filenames, MIME types, hashes, keys or file bytes. No company-document API or
Corpo server archive participates. A participant with a descriptor can retain or
forward the file; removing a member cannot revoke previously received files.
Future descriptors must use the parent's current authorized epoch after rotation.

## Wire format

The parent QSP message uses `body_type = "blobref"`. Its body is UTF-8 JSON:

```json
{
  "type": "qntm.attachment.v1",
  "name": "agreement.pdf",
  "media_type": "application/pdf",
  "size": 42000,
  "sha256": "<64 lowercase hex digits, SHA-256 of exact file bytes>",
  "parent_conv_id": "<32 lowercase hex digits>",
  "parent_epoch": 0,
  "invite_token": "<standard qntm direct invite token, base64url without padding>",
  "expires_ts": 1800000000,
  "parts": [
    {"message_id": "<32 lowercase hex digits>", "sha256": "<64 lowercase hex digits, SHA-256 of serialized QSP envelope>"}
  ]
}
```

All fields are required; unknown fields are rejected. Size and epoch are
nonnegative integers; expiry is a positive safe integer. Epoch is at most
2^32−1. Filenames are nonempty UTF-8 (at most 255 bytes), contain no slash,
backslash, ASCII control character or DEL, and are not `.` or `..`. MIME types
are at most 120 UTF-8 bytes and match
`^[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+$`.
A descriptor is at most 48 KiB. File size is at most **8 MiB**. Parts are
**32,768 bytes**, except the final part. Empty files have one empty part.
There are exactly `max(1, ceil(size/32768))` parts, at most 256, in file order;
message IDs must be unique.

Create a standard direct invite with the sender's existing identity. Derive its
conversation keys using the existing QSP invitation KDF, with epoch zero. Each
part is a standard QSP message signed by the same identity, with
`body_type = "blob.part"` and canonical CBOR body:

```
{ v: 1, index: <zero-based integer>, data: <byte string> }
```

There is no new encryption, signature, nonce or AAD scheme. Use the existing
`createMessage`/`create_message`, `serializeEnvelope`/`serialize_envelope` and
QSP validation. Part `sha256` hashes the **exact serialized envelope**, not JSON
or base64; retries reuse those exact bytes and message IDs. `expires_ts` is the
minimum signed expiry across the parts. Default message TTL is 30 days, but it
does **not** override the relay's shorter retention.

## Sending and receiving

1. Check the parent's current group authorization and rekey state.
2. Encrypt/sign all parts and the parent descriptor offline. Persist the exact
   encrypted wires privately before network writes. Do not put secret
   descriptors or bytes in the Corpo API, errors, analytics or command logs.
3. Post parts to the invite's channel, then publish the parent `blobref` only
   after every part succeeded. On ambiguous or partial failure, retry the exact
   saved envelopes; do not mark delivery successful. A sender can discard an
   unsent attempt; its orphan ciphertext expires under relay policy.
4. Recipients authenticate the parent message and enforce group membership as
   usual. Pin descriptor parent ID/epoch to that signed envelope and invite
   inviter public key to the verified parent sender; never trust a pasted
   descriptor alone as sender proof. Invite type must be direct, its ID 16 bytes
   and different from the parent ID. Do not import this channel as a chat.
5. Read the attachment channel from sequence zero using the **same configured
   relay as the parent**, never an arbitrary URL from a message. Bound replay to
   512 messages, each envelope at most 64 KiB, with a timeout. Any missing part
   is an incomplete or expired attachment, never successful empty content.
6. Resolve every referenced wire hash, verify its message ID, channel, epoch
   zero, signature, inviter/sender identity and expiry. Require the exact
   part-body fields, version, index and length. Unreferenced noise/duplicates
   cannot change the result. Reassemble in descriptor order and verify total
   length and whole-file SHA-256 before offering bytes for download. Fail closed
   on tampering, wrong key/sender, malformed/oversized input or missing parts.

Do not automatically open or execute a received attachment. Names and media
labels are untrusted descriptions even when the file is authentic. Download
verified bytes on explicit participant action; choose a safe local destination.
File hashes identify bytes, not legal approval. Approval proofs bind those exact
hashes separately.

## Retention and release

The default relay currently retains envelopes for **seven days**, with a 64 KiB
per-envelope and 512-message per-channel limit. This transport is delivery, not
permanent file hosting. Keep verified downloaded files in participant-controlled
storage. If parts have expired or been pruned, ask the sender to resend the
original file as a new attachment. Rotating group keys does not erase old files.

No relay deployment is required. The TypeScript attachment export, bounded
receive support, and equivalent Python attachment module must ship together.
Until published versions include them, applications must pin reviewed local
artifacts with source provenance and report that release dependency explicitly.
