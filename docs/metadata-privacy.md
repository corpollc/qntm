# Metadata visibility and retention

qntm encrypts message contents; **it does not hide the existence, timing, size or routing of conversations from the relay and its hosting provider**. This inventory describes the relay and monitoring implementation in this repository. A relay operator can change their deployment, and Cloudflare's infrastructure has access beyond what the application elects to save.

## What the relay receives

TLS ends at Cloudflare. Cloudflare and the Worker can see the HTTP request URL, method, headers, body, source network address and request timing. The application uses `CF-Connecting-IP` for rate limiting. User-Agent, Origin and other supplied headers are available to the Worker even when the application does not save them. TLS also exposes connection timing, duration, transport sizes and negotiated connection properties to the hosting provider.

| Operation | Unencrypted fields available to the relay |
| --- | --- |
| `POST /v1/send` | `conv_id`, base64-encoded envelope bytes; optional `msg_id`, `announce_sig`, `expiry_ts`. Base64 is an encoding, not encryption. The relay assigns a sequence number and observes submission time and byte length. |
| Outer QSP envelope | `v`, `suite`, `conv_id`, `conv_epoch`, `msg_id`, `created_ts`, `expiry_ts`, `aad_hash`, and ciphertext bytes. Optional outer fields are also visible, including a DID when a client sends one. The relay currently stores the CBOR envelope without parsing its encrypted inner payload; an operator can inspect the outer fields. |
| `GET /v1/subscribe` | URL query `conv_id`, `from_seq`, and optional `pub_key`; WebSocket connection/reconnection times, delivery sequence numbers and frame sizes. Optional authentication exposes the supplied public key, random challenge and signature. |
| `POST /v1/receipt` | `proto`, `conv_id`, `msg_id`, `reader_kid`, `reader_ik_pk`, `read_ts`, `required_acks`, `sig`. A signed receipt identifies its signing key; it does not independently establish membership or prove a person read a message. |
| Announce registration | `name`, `conv_id`, `master_pk`, `posting_pk`, `sig`. Rotation sends `conv_id`, `master_pk`, `new_posting_pk`, `sig`; deletion sends `conv_id`, `master_pk`, `sig`. |
| Aggregate metrics read | `/v1/metrics` and its read-only bearer token in the Authorization header. The token grants aggregate reads only. |

Ordinary message body text, body type, references, sender public key/key ID and message signature are inside the encrypted inner payload. The relay does not have conversation decryption keys merely by receiving an envelope. However, receipt keys, optional subscribe keys, optional outer DIDs and announce registration keys are separately exposed as listed above. A reused key can link activity across conversations. Conversation IDs, network addresses and timing can also support correlation. Knowing a conversation ID permits requesting its encrypted replay; this is not membership authentication or permission to decrypt.

There is no server-side registration of ordinary group creation. A group created locally without a post is invisible to the relay. Encrypted group management does not give the relay an authoritative membership list, group title or group-versus-direct-chat classification. This is why the dashboard says **active conversations**, not users, participants or all created groups.

## What the application stores

| Store | Exact application data | Application retention |
| --- | --- | --- |
| Workers KV message key | Key `/<conv_id>/msg/<sequence>.cbor`; value is the complete outer envelope, including ciphertext and visible outer fields. | TTL assigned at publication: default 604800 seconds (seven days), configurable with `ENVELOPE_TTL_SECONDS`. Reads and receipts do not extend it. |
| Conversation Durable Object `messages` | `seq`, `envelope_b64`, `created_at` (server publication time, seconds), `expires_at`. The object itself is selected by conversation ID. | Same configured TTL; alarm deletion and independent read-time expiry checks. |
| `message_metadata` | `msg_id`, `seq`, `expires_at`, `readers_json` (up to 256 distinct receipt signer key IDs). Full receipt public keys, signatures, claimed timestamps and thresholds are verified but not written into this table. | Until that message's relay expiry. |
| Conversation sequence state | `next_seq`, associated with the conversation's Durable Object. | No automatic expiry. Preserved to prevent cursor reuse after content expires. Announce deletion resets its object. |
| In-memory rate limiter | Source IP string mapped to request `count` and `resetAt`. | Counting window is one minute; entries are not actively purged, so an idle IP entry can remain for the isolate's lifetime. No durable application IP table. |
| Pending subscribe authentication | In-memory WebSocket association, challenge bytes, public key, conversation ID and requested cursor. Cloudflare also manages accepted WebSocket connection state. | Pending map entry removed on success, rejection, close or error; otherwise until object eviction. This is not a persistent participant roster. |
| Announce configuration in KV | Key `/__announce__/<conv_id>/meta.json`; `name`, `conv_id`, `master_pk`, `posting_pk`. | Persistent until signed rotation/deletion. `/v1/announce/info` publicly returns `name`, `conv_id`, `posting_pk` to a caller supplying the conversation ID. |
| Legacy activity KV record | Conversation IDs mapped to most recent observed post timestamp under `/__stats__/active_conversations`. | Old approximate counter; new deployments stop writing it. Hourly cleanup removes expired entries, with a seven-day TTL. |

Completely dormant Durable Objects created before the retention migration may retain old data until inventoried and activated. The repository has migration logic, but a deployment alone does not wake every old object. See [relay operations](relay-operations.md) for that limitation. Client copies and a gateway's copies have separate lifetimes.

## Exactly what the new metrics cover

**The counter inside Cloudflare contains more metadata than the dashboard displays.**

Each successfully stored envelope creates one local `metrics_outbox` row and, after delivery, one `relay_events` row in the internal aggregate Durable Object. Both contain exactly:

```text
id              random telemetry UUID, used to deduplicate delivery retries
conv_id         raw conversation ID
posted_at       server publication timestamp in milliseconds
envelope_bytes  decoded outer-envelope byte length, including encryption overhead
traffic         "application" or "probe"
```

The telemetry UUID is separate from the message's `msg_id`. These tables contain no ciphertext, message body, participant key, IP address, User-Agent, receipt data, title or guidance category. They **do** provide a per-conversation timing and encrypted-size history inside the Cloudflare account. Successfully delivered outbox rows are removed; failed deliveries remain pending for at most seven days. Aggregate event rows expire seven days after the original post, and late retries cannot resurrect them. Deletion is logical application deletion, subject to provider recovery and alarm execution.

The aggregate object also keeps `relay_totals(traffic, messages, bytes)` and a single measurement-start timestamp indefinitely. Those totals have no conversation IDs. Each accepted post counts once, even if the client loses its acknowledgement. A new send that stores a second envelope is a second post, even if it repeats a logical message. Telemetry delivery is asynchronous and can lag; an outage beyond the seven-day retry window can lose counts.

These counters measure accepted storage events, not verified inner-message signatures, unique logical messages or confirmed recipient deliveries. The relay cannot authenticate an encrypted inner payload and can accept invalid opaque content. The counts can include test, bot or abusive submissions; they are not proof of real users or legitimate group creation.

The **private aggregate API, exe.dev collector, Prometheus and Grafana** receive only:

- Measurement-start and measurement-time timestamps.
- For each of the fixed `application` and `probe` categories: cumulative post count and envelope-byte count, rolling 24-hour and seven-day post counts, and rolling 24-hour and seven-day distinct active-conversation counts.
- Collection success and last-run/last-success timestamps.
- Synthetic probe success, attempt/success timestamps and round-trip duration.
- Blackbox HTTPS/TLS results: success, DNS/connect/TLS/HTTP durations, status and protocol, TLS certificate expiry and certificate identification exposed by the exporter. These describe the relay endpoint, not user connections.
- Prometheus scrape health/duration, alert state and ordinary VM/process/resource metrics already collected on the monitoring VM. The private instance also holds the separately documented charter service metrics.

There are no per-user, per-key, per-IP or per-conversation labels in the exported relay traffic metrics. The public `/v1/stats` returns only the combined seven-day active-conversation count (including the probe) and measurement timestamps; it does not reveal IDs or private totals. Aggregate counts are not anonymization: observers may infer activity from changes, especially at low volume.

Prometheus samples are retained for 30 days with a 2 GB size cap, which can shorten retention. The collector keeps its latest aggregate/probe state in a private local JSON file, overwritten on each completed cycle. Grafana displays those aggregates behind exe.dev authentication. It has no access to the relay event tables or conversation keys. The collector's private `probe.cbor` contains only its own two synthetic identities, their synthetic conversation keys and replay cursor; these persist across restarts. The probe posts one synthetic envelope about every five minutes. It receives only that conversation. Its source IP and traffic remain visible to Cloudflare like any other client's.

## Logs, provider access and deletion limits

Application aggregate metrics are not a complete inventory of Cloudflare's own analytics, security logs, operator access or backups. Cloudflare terminates TLS and can access the unencrypted metadata above regardless of whether qntm saves it. Provider analytics can count ordinary HTTP requests, failures and WebSocket upgrades independently of the qntm post counters. Operators can inspect stored ciphertext and metadata or enable live request tracing. An audit of Worker settings alone does not audit account/zone Logpush, all security products, third-party exports or provider-internal retention.

The [September 9, 2026 deployment audit](https://github.com/corpollc/qntm/actions/runs/34369327870) returned `observability: null`, `logpush: false`, and no Tail consumer services for `qntm-dropbox`. These are the observed Worker settings, not evidence that Cloudflare has no other logs. Account/zone exports and provider-internal retention remain outside that check. Future deployments report the same selected settings without printing secret bindings.

The relay's application logs use fixed strings for an unhandled error or deferred telemetry delivery. Exception messages/stacks and dynamic request values are not logged by those handlers, and a generic 500 response does not echo exception details. Platform invocation logs are separate: request URLs can include conversation IDs, cursors and optional public keys. The monitor logs exception classes only and disables its HTTP access logging. Container logs rotate at 10 MB per file with three files; systemd journal retention is governed by VM settings. Grafana/exe.dev access may record the operator's dashboard login/network activity; it is not a user-conversation access log.

Cloudflare documents a [30-day SQLite Durable Object point-in-time recovery window](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/). Seven-day application expiry is not a promise of physical erasure from provider recovery systems. KV consistency, alarm retries, legacy dormant objects, operator exports and other parties' copies are additional boundaries. Cloudflare request/log retention depends on the [enabled observability products and settings](https://developers.cloudflare.com/workers/observability/logs/workers-logs/); this document makes no universal seven-day deletion claim for those systems.

## Other services have different visibility

The OpenClaw adapter decrypts messages locally and keeps current keys, authenticated conversation state, pending plaintext delivery and replay records in private checkpoint/SQLite files. Its completed queue records drop their payload; failed records retain plaintext for up to seven days while pruning is running. Pending work has no time-based expiry. OpenClaw sessions, transcripts and provider calls have independent retention. Exact fields, limits, paths and recovery behavior are listed in [OpenClaw local storage](../openclaw-qntm/README.md#local-storage-privacy-and-recovery); none of those local files are sent to the relay's metrics endpoint.

This inventory describes the messaging relay and its traffic dashboard. An invited **gateway** receives conversation decryption keys and executes approved requests; its operator can access that conversation's plaintext and provisioned credentials. The **charter registry** stores deliberately published, signed charter statements and metadata, not encrypted chat messages. Guidance recipients and other conversation keyholders can read what is sent to them. Browser/CLI history, local backups, receive hooks and external destinations are separate plaintext exposure points. See the [threat model](threat-model.md), [gateway invitations](gateway-invitations.md), [charter operations](charter-operations.md) and [receive hooks](receive-hooks.md).
