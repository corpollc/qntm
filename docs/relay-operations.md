# Relay TLS and delivery checks

The public relay is `https://inbox.qntm.corpo.llc`, attached as a custom domain to the `qntm-dropbox` Cloudflare Worker. Its health endpoint is `/healthz`; clients send with HTTPS and receive with WSS on `/v1/subscribe`.

The [private relay dashboard and monitoring guide](relay-monitoring.md) covers posted-message counters, active conversations, external HTTPS/TLS checks and encrypted live-delivery/replay probes. Counts distinguish application traffic from the synthetic probe and display when measurement began.

## Content and metadata expiry

The relay source assigns `ENVELOPE_TTL_SECONDS` at publication (default seven days, minimum 60 seconds). Reads and receipts do not renew it. Ciphertext still exists temporarily in both Workers KV and Durable Object SQLite; this is a transport buffer, not participant-owned message history.

The retention implementation in `worker/src/retention.ts` schedules a Durable Object alarm for the next expiry. The alarm removes expired SQLite envelopes and their message-ID/reader-ID metadata, including when no one publishes again. Replay and receipt lookup independently filter by expiry, so an overdue alarm cannot make expired messages readable through the relay. KV retains its own TTL. Sequence counters remain, so a returning participant's cursor is not reset or reused. [Cloudflare alarms](https://developers.cloudflare.com/durable-objects/api/alarms/), [KV expiry](https://developers.cloudflare.com/kv/api/write-key-value-pairs/).

On the first activation after upgrading, an old channel's SQLite records receive an expiry of their original creation time plus the configured TTL. Old `msg-seq:` and `receipt-readers:` keys migrate in bounded batches; alarms continue the migration without more client traffic. The previous implementation could leave expired SQLite content and metadata in inactive channels indefinitely. A new deployment does **not** wake every previously created Durable Object: completely dormant legacy objects require an inventoried migration before their stored data can be described as cleaned up.

The old aggregate activity key has a seven-day TTL and an hourly cleanup handler. New monitoring deployments replace its concurrent read/modify/write updates with a durable per-post telemetry outbox and deduplicating aggregate store. Metrics event IDs, conversation IDs, post times and encrypted sizes expire after seven days; exported totals contain no conversation IDs. Announce-channel names and public signing-key registrations are separate persistent configuration and do not expire with envelopes. See the [exact metadata inventory](metadata-privacy.md).

This behavior requires relay v0.6.0 or newer; source changes alone do not alter production objects or account settings. Release verification must cover the deployed bindings and TTL, the hourly trigger, alarms, dormant legacy objects, request/exception logs, exported datasets and provider recovery retention. Do not use expiry of active database rows as a statement of physical erasure: Cloudflare documents a 30-day point-in-time recovery window for SQLite-backed Durable Objects. The source code alone cannot establish which data is recoverable from a live account. [Cloudflare storage and recovery](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).

Local verification is `cd integration && npm run test:relay`. It covers migration and exact expiry boundaries in SQLite, and starts a disposable local Worker to confirm that an idle channel's ciphertext and reader metadata disappear without another relay request. The real alarm test takes about one minute. No production data is used.

## Diagnose the layer that failed

```sh
curl --fail --show-error --max-time 15 https://inbox.qntm.corpo.llc/healthz
openssl s_client -connect inbox.qntm.corpo.llc:443 -servername inbox.qntm.corpo.llc </dev/null 2>/dev/null | openssl x509 -noout -issuer -subject -dates
dig inbox.qntm.corpo.llc CAA
dig qntm.corpo.llc CAA
```

A TLS handshake failure occurs before the Worker sees an HTTP request. A healthy Worker graph or a successful plain HTTP health check therefore does not establish HTTPS availability. Check the hostname's managed certificate in Cloudflare **SSL/TLS → Edge Certificates**, and its binding under **Workers → qntm-dropbox → Settings → Domains & Routes**.

Cloudflare's [Universal SSL coverage](https://developers.cloudflare.com/ssl/edge-certificates/universal-ssl/limitations/) for `*.corpo.llc` does not cover `inbox.qntm.corpo.llc`. A Worker [custom domain provisions its own managed certificate](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/#certificates). Confirm that the certificate includes the exact relay hostname and is active.

## Certificate authority authorization

`qntm.corpo.llc` is a DNS-only CNAME to the GitHub Pages site. A CAA lookup can inherit restrictions from that CNAME target. Follow Cloudflare's [CAA guidance](https://developers.cloudflare.com/ssl/edge-certificates/caa-records/) when checking both the hostname and its ancestors/aliases.

The relay hostname has this explicit authorization for its current managed issuer:

```text
inbox.qntm.corpo.llc. CAA 0 issue "pki.goog"
```

Keep the record while Google Trust Services issues the managed certificate. If the issuer changes, review the actual issuer and update authorization deliberately. Do not assume an unrelated parent site's CAA policy is appropriate for the relay.

For pending validation, compare the dashboard's current TXT challenge with public DNS at `_acme-challenge.inbox.qntm.corpo.llc` and any other SAN challenge names. Challenge tokens can change after a failed issuance. Recursive resolvers can retain negative responses after the authoritative records exist. Cloudflare [retries validation automatically](https://developers.cloudflare.com/ssl/edge-certificates/changing-dcv-method/validation-backoff-schedule/); allow propagation before making further changes. Avoid repeatedly removing/re-adding a domain, which restarts issuance and can create more propagation delays.

## Verify actual messaging

After HTTPS recovers, use fresh local profiles and a disposable conversation. Generate two identities, create an invitation with one, join with the other, then send and receive in both directions. Confirm the expected plaintext and `verified: true`. Keep invitation tokens and identity files out of incident notes. Use the normal TLS verification and CA configuration provided by the qntm client.

The patched Python client performs a bounded, read-only replay check after an ambiguous send failure. It compares the entire submitted encrypted envelope and reports `acknowledgement: "reconciled"` if found, without a second POST or advancing the receive cursor. The check is limited to 15 seconds and 1,000 frames; failure to find the message is not proof that it was rejected.

If delivery remains unknown, the CLI returns `code: "send_delivery_unknown"` with the conversation ID and message ID. Receive/check history before resending the same text as a new message. A new CLI invocation may create a different message ID and therefore a visible duplicate. Capture exception class, client version, time, message ID if available, and whether the receiving peer actually saw it. Distinguish a relay rejection from a client or proxy dropping the acknowledgement.

## September 8, 2026 incident

Muse's sandbox and local clients could create identities and conversations but failed TLS at the public relay. HTTP health succeeded, the Worker had no recent deployment, and no billing suspension was visible. The dashboard had no usable certificate covering the relay hostname.

Reattaching the existing custom-domain binding caused a managed Google Trust Services certificate to be requested. Validation initially errored. The parent CNAME's inherited CAA set allowed other issuers but excluded Google; adding the explicit leaf CAA record at approximately 19:41 PDT removed that restriction. Validation challenges propagated and HTTPS recovered by 19:54 PDT. The served certificate was issued by Google Trust Services WE1 and expires December 8, 2026.

Two fresh local clients then completed verified encrypted messaging in both directions. Codex and Muse's Lubber also exchanged verified messages in Muse's existing conversation. Lubber reported ambiguous send failures during recovery, including messages that arrived despite a local error; this is separate client/proxy reliability evidence to retain when reviewing retries. No application deployment, package release, or billing change was required to restore TLS.
