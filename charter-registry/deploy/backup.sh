#!/bin/sh
set -eu
umask 077
backup_dir=/var/backups/qntm-charter
mkdir -p "$backup_dir"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
temporary=$(mktemp "$backup_dir/.partial.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
install -m 0600 /var/lib/qntm-charter/snapshot.db "$temporary"
test -s "$temporary"
size=$(wc -c < "$temporary" | tr -d ' \t\n')
test "$size" -ge 8192
magic=$(od -An -tx1 -j 16 -N 4 "$temporary" | tr -d ' \t\n')
case "$magic" in
    edda0ced|ed0cdaed) ;;
    *) echo "invalid bbolt snapshot header" >&2; exit 1 ;;
esac
mv "$temporary" "$backup_dir/registry-$stamp.db"
# Keep seven daily snapshots; these contain the registrar private key.
find "$backup_dir" -type f -name 'registry-*.db' -mtime +7 -delete
mkdir -p /var/lib/qntm-charter-metrics
printf 'qntm_charter_backup_timestamp_seconds %s\n' "$(date +%s)" > /var/lib/qntm-charter-metrics/backup.prom.tmp
chmod 0644 /var/lib/qntm-charter-metrics/backup.prom.tmp
mv /var/lib/qntm-charter-metrics/backup.prom.tmp /var/lib/qntm-charter-metrics/backup.prom
