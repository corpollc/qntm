#!/bin/sh
set -eu
umask 077
backup_dir=/var/backups/qntm-charter
mkdir -p "$backup_dir"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
temporary=$(mktemp "$backup_dir/.partial.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
curl --fail --silent --show-error --max-time 60 http://127.0.0.1:9085/backup -o "$temporary"
test -s "$temporary"
mv "$temporary" "$backup_dir/registry-$stamp.db"
# Keep seven daily snapshots; these contain the registrar private key.
find "$backup_dir" -type f -name 'registry-*.db' -mtime +7 -delete
mkdir -p /var/lib/qntm-charter-metrics
printf 'qntm_charter_backup_timestamp_seconds %s\n' "$(date +%s)" > /var/lib/qntm-charter-metrics/backup.prom.tmp
chmod 0644 /var/lib/qntm-charter-metrics/backup.prom.tmp
mv /var/lib/qntm-charter-metrics/backup.prom.tmp /var/lib/qntm-charter-metrics/backup.prom
