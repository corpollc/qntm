# Relay TLS and delivery checks

The public relay is `https://inbox.qntm.corpo.llc`, attached as a custom domain to the `qntm-dropbox` Cloudflare Worker. Its health endpoint is `/healthz`; clients send with HTTPS and receive with WSS on `/v1/subscribe`.

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
