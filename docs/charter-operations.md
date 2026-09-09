# Hosted charter registry

The experimental v0.2 registrar runs at **https://charter.qntm.corpo.llc** on the dedicated exe.dev VM `qntm-charter.exe.xyz`. It is separate from the relay and gateway. Signed statements authorize writes; there is no operator admission token or requirement to involve a human governor.

The service is public: publish only charter metadata intended for public retrieval. The draft remains unratified and the registrar has no independent witnesses. Its signatures and Merkle proofs establish recorded history, not compliance with a charter.

## Client configuration

Use this operator-published pin through your trusted configuration channel. Do not automatically adopt a key returned by the server you are trying to authenticate.

```ts
const trust = {
  registry: 'charter.qntm.corpo.llc',
  registrar: {
    kid: '1b111489c3b5599644117c5f6cc3c81b',
    pubkey: 'U7809nuKxI8PvyNdifwRKoqLk7F1PMjn0paWWVtPsNA',
  },
};
const registry = new CharterRegistryClient('https://charter.qntm.corpo.llc', trust);
```

See the [TypeScript example](../charter-registry/README.md#typescript-client) or [Python example](../charter-registry/README.md#python-client) for submitting a self-charter, publishing a statement and verifying its evidence. Python charter support is unreleased. Both clients use this same pin and audience. Retain checkpoints locally and compare consistency across updates.

## TLS and network boundary

Cloudflare hosts a **DNS-only** CNAME from `charter.qntm.corpo.llc` to `qntm-charter.exe.xyz`. exe.dev registers that custom domain, terminates HTTPS, manages certificate renewal, and redirects HTTP to HTTPS. The certificate covers the exact public hostname. The initial certificate expires on December 8, 2026; monitor renewal rather than pinning that leaf certificate.

Only VM port 8000 is public. Nginx forwards `/v1/` and `/healthz` to the Go service at `127.0.0.1:8085`. Private metrics and signing-key-bearing backups listen on `127.0.0.1:9085` and are never forwarded by Nginx. Grafana uses exe.dev's authenticated alternate port 3000; it must not become the public proxy port. Do not add an unauthenticated public route to monitoring or administrative listeners.

The Nginx global budget is three requests/second with a burst of twelve, twenty concurrent connections, and a 1 MiB request body limit. It returns 429 when throttled. The Go service allows four concurrent requests and rejects excess work with 503 and `Retry-After`. Initial storage capacity is 2,000 accepted entries or 16 MiB of encoded log data. At capacity, appends return 503 `registry_capacity_reached`; existing history stays readable. These conservative limits bound a reference implementation that rebuilds trees in memory. Raising them requires load testing and storage planning.

## Monitoring

Open **https://qntm-charter.exe.xyz:3000/d/qntm-charter** and sign into exe.dev with VM access. The provisioned Grafana dashboard is read-only and shows public HTTPS health, TLS days remaining, HTTP status counts, p95 latency, log capacity, service uptime, VM CPU/memory/disk, and local backup age. Grafana's anonymous Viewer mode is behind exe.dev authentication; direct Internet access is not authorized.

Prometheus scrapes every fifteen seconds and retains up to thirty days or 2 GiB locally. Alert rules detect service/HTTPS failure, imminent certificate expiry, storage capacity, low disk, and stale local backups. **No email, SMS, or paging destination is configured.** Alerts are visible in the dashboard and Prometheus; notification routing needs an operator-selected destination. The HTTPS probe runs on this VM, so an independent external availability check remains useful.

Logs contain status, duration and HTTP method without request bodies, agent IDs, client addresses or query strings. Container logs rotate at 10 MiB × three files per service; Ubuntu's Nginx logrotate handles access logs.

```sh
ssh qntm-charter.exe.xyz 'sudo systemctl status qntm-charter --no-pager'
ssh qntm-charter.exe.xyz 'sudo journalctl -u qntm-charter --since today --no-pager'
ssh qntm-charter.exe.xyz 'docker compose -f /opt/qntm-charter-monitoring/compose.yml ps'
ssh -L 9090:127.0.0.1:9090 qntm-charter.exe.xyz
```

The last command makes Prometheus available at `http://127.0.0.1:9090` while SSH is connected. Local metrics do not establish independent registrar witnessing.

## Backups and recovery

The bbolt database at `/var/lib/qntm-charter/registry.db` holds **both all history and the registrar signing seed**. It is private to the service user. `qntm-charter-backup.timer` makes a transactionally consistent snapshot daily in `/var/backups/qntm-charter`, retaining roughly seven days with mode 0600. It does not interrupt writes. Same-VM snapshots do not protect against VM loss.

Pull an encrypted off-host copy from the operator machine:

```sh
uv run --project python-dist python scripts/backup_charter.py
```

This creates AES-256-GCM snapshots under `~/.qntm-backups/charter/`. Its private `encryption.key` stays on the operator machine; keep a separate protected recovery copy. A deployment snapshot is taken off-host and restore-checked. **Off-host copies are currently operator-triggered, not scheduled.**

```sh
uv run --project python-dist python scripts/backup_charter.py --decrypt PATH_TO_SNAPSHOT --output /private/restore/registry.db
```

Restore into an isolated data directory first. Start the same binary with the original registry audience, verify the public pin, compare historical signed checkpoints, and audit the log from TypeScript. Then stop the production service and replace the database with correct ownership/mode before restarting. Never run two writers on one bbolt file. Never silently create a new identity or serve a rolled-back log under the existing name: an older backup may omit acknowledged writes, and external retained checkpoints must be reconciled first.

## Deployments

Deployment files are in [`charter-registry/deploy/`](../charter-registry/deploy/). Build and test the exact release source, then copy its Linux binary and configuration to this dedicated VM. The installer preserves the database, signing identity, monitoring volumes, and Grafana administrative password. It requires Ubuntu, Nginx and Docker Compose, already installed on this VM.

```sh
cd charter-registry
go test -race ./...
go vet ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /tmp/qntm-charter ./cmd/charter-registry
cd ..
ssh qntm-charter.exe.xyz 'mkdir -p /home/exedev/qntm-charter-deploy'
scp charter-registry/deploy/* /tmp/qntm-charter qntm-charter.exe.xyz:/home/exedev/qntm-charter-deploy/
ssh qntm-charter.exe.xyz 'sudo sh /home/exedev/qntm-charter-deploy/install.sh'
curl --fail https://charter.qntm.corpo.llc/healthz
```

Only initial provisioning needs `ssh exe.dev share port qntm-charter 8000`, `ssh exe.dev share set-public qntm-charter`, and `ssh exe.dev domain add qntm-charter charter.qntm.corpo.llc`. Routine releases do not change visibility, DNS or the registrar key. Compare the deployed binary hash with the built artifact and repeat a pinned TypeScript read after restart.
