# Relay traffic and availability dashboard

The private [relay dashboard](https://qntm-charter.exe.xyz:3000/d/qntm-relay) shares Grafana with the charter dashboard. Access requires the operator's exe.dev login. Grafana receives only aggregate counters and synthetic probe results.

Read the [field-by-field metadata visibility and retention inventory](metadata-privacy.md). It distinguishes the per-post metadata kept inside Cloudflare from exported totals, and covers connection metadata, receipt/authentication keys, logs and provider recovery limits.

## Counts and their limits

| Metric | Meaning |
| --- | --- |
| Messages posted, 24 hours / 7 days | Envelopes stored by the Cloudflare relay within the rolling window. Resent copies count as posts. |
| Active conversations, 24 hours / 7 days | Distinct conversation IDs with a stored envelope in that window. Includes direct chats and groups. |
| Posts since monitoring began | Durable aggregate counter beginning at the displayed start time. No historical backfill. |
| Probe traffic | The dedicated synthetic conversation, excluded from application counts and shown separately in the rate chart. |

Conversations are created locally. Post counts cannot count groups that have never posted, determine complete membership, or distinguish a group from a direct chat. Other relay paths can reveal participant keys, as detailed in the metadata inventory. The dashboard therefore does not claim a lifetime count of all created groups. Windows remain partial for the first 24 hours or seven days after deployment. The old shared KV activity record could lose concurrent updates and is not used to seed the new counters.

Counts represent accepted relay storage events, not verified inner messages or confirmed deliveries. Invalid opaque submissions, resent copies, tests and bots can contribute to application traffic.

The relay records a metadata-only outbox entry in the same SQLite transaction as each envelope. It delivers bounded batches to an internal `RelayMetricsDO`. Duplicate telemetry deliveries count once, including a lost acknowledgement followed by a retry. Pending deliveries retry through Durable Object alarms. Network failures in aggregation do not hold up message delivery; counters may lag during recovery. Outbox entries and aggregate event IDs/conversation IDs/timestamps expire after seven days; an outage exceeding that recovery window can leave an undercount. Aggregate totals retain no conversation IDs. Cloudflare's underlying recovery retention still applies.

This is a small-deployment aggregator: one SQLite-backed Durable Object serializes updates and computes rolling windows from a seven-day event table. Measure load before using it for high-volume accounting. See Cloudflare's [SQLite transactions](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/) and [alarm behavior](https://developers.cloudflare.com/durable-objects/api/alarms/).

The public `/v1/stats` returns the active-conversation count plus measurement times. Detailed totals require a separate read-only bearer token at `GET /v1/metrics`. It grants only aggregate reads, with no message, gateway or charter administration access. No ingestion endpoint is publicly routed. This endpoint is distinct from Cloudflare's [Worker request analytics](https://developers.cloudflare.com/workers/observability/metrics-and-analytics/), which include other HTTP operations.

## External checks

The collector runs on `qntm-charter.exe.xyz`, outside Cloudflare and independently of the operator's Mac. It shares the charter VM's failure domain: a total failure of that VM also removes this dashboard and monitor.

- Blackbox exporter verifies public HTTPS, DNS and the served certificate every 15 seconds.
- The Python monitor fetches aggregate counters approximately once per minute.
- Every five minutes, two dedicated synthetic identities authenticate a receive WebSocket, post one encrypted message, verify its live delivery, then reconnect and verify persisted replay. The probe uses the published Python package and retains its own keys and cursor across restarts. It receives only its synthetic conversation.
- Probe traffic is one envelope per check, about 288 per day. Relay transport retention still applies.

Grafana hides stale traffic totals and displays failing/stale probe state. Prometheus retains 30 days of local samples. Alert rules cover HTTPS failure, a certificate within 14 days of expiry, failed/stale encrypted probes, and unavailable traffic telemetry. **No email or paging recipient is configured yet.** Rules are visible in Prometheus and the dashboard; choose notification delivery separately.

## Deployment and operation

Source is in `monitoring/`; Grafana, Prometheus and alert configuration live under `charter-registry/deploy/`.

1. Initialize a private synthetic profile with the published dependencies installed:
   ```sh
   python monitoring/relay_monitor.py --init --state-dir /private/relay-monitor
   ```
   The command prints only its conversation ID. Keep `probe.cbor` private and preserve it across deployments.
2. Set the relay's `MONITOR_CONVERSATION_ID` to that ID. Set a random `METRICS_READ_TOKEN` Worker secret. The GitHub relay deployment workflow can provision it from the `QNTM_RELAY_METRICS_READ_TOKEN` repository secret. Never put the token in Git, URLs, screenshots or command output.
3. Stage `monitoring/` on the dedicated VM alongside `probe.cbor` and a private `config.json`:
   ```json
   {
     "relay_url": "https://inbox.qntm.corpo.llc",
     "metrics_read_token": "REPLACE_WITH_PRIVATE_RANDOM_TOKEN",
     "probe_interval_seconds": 300
   }
   ```
4. Run `sudo sh install.sh` in that staging directory. It installs the pinned dependencies and hardened `qntm-relay-monitor.service`, preserving an existing probe profile. The profile ID must match the relay's configured exclusion. Deploy the updated monitoring Compose/config files and reload Prometheus/Grafana.

The exporter listens only on `127.0.0.1:9191`. Its config is `/etc/qntm-relay-monitor/config.json` (root-owned, monitor-group readable); state is `/var/lib/qntm-relay-monitor/` (0700). Use `systemctl status qntm-relay-monitor` and `journalctl -u qntm-relay-monitor` for service health. Errors log exception classes, not bearer tokens or message payloads.

For a bounded manual collection, run the service's Python interpreter and `relay_monitor.py --once` as its service user. It prints aggregate Prometheus metrics. Repeated runs within the probe interval do not post another message. Rotate the read token in both the Worker and the private collector config, then restart the collector. Reinstalling retains the synthetic profile and cursor.

Tests cover concurrent posts against a real local Worker, private/public route boundaries, transaction rollback, lost telemetry acknowledgements, expiry/restart, stale collector state, and the complete encrypted probe against the local relay. Manual-deploy CI runs the full client acceptance gate before production rollout.

The September 9, 2026 deployment passed that full gate. The installed exe.dev collector then verified authenticated live delivery and persisted replay against the public relay. Counting begins at the timestamp displayed in Grafana; earlier traffic is not reconstructed.
