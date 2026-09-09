#!/bin/sh
# Run on the dedicated Ubuntu VM with a prebuilt binary and these config files.
# This does not change exe.dev visibility or DNS.
set -eu
test "$(id -u)" = 0
cd "$(dirname "$0")"
id qntm-charter >/dev/null 2>&1 || useradd --system --home-dir /var/lib/qntm-charter --shell /usr/sbin/nologin qntm-charter
install -d -m 0700 -o qntm-charter -g qntm-charter /var/lib/qntm-charter
install -d -m 0700 /var/backups/qntm-charter
install -d -m 0755 /var/lib/qntm-charter-metrics /usr/local/lib/qntm-charter /etc/qntm-charter /opt/qntm-charter-monitoring
install -m 0755 qntm-charter /usr/local/bin/qntm-charter
install -m 0755 backup.sh /usr/local/lib/qntm-charter/backup.sh
install -m 0644 qntm-charter.service qntm-charter-backup.service qntm-charter-backup.timer /etc/systemd/system/
install -m 0644 nginx.conf /etc/nginx/conf.d/qntm-charter.conf
# Only this new dedicated VM uses this installer.
rm -f /etc/nginx/sites-enabled/default
install -m 0644 compose.yml prometheus.yml alerts.yml blackbox.yml grafana-datasources.yml grafana-dashboards.yml charter-dashboard.json relay-dashboard.json /opt/qntm-charter-monitoring/
if [ ! -f /etc/qntm-charter/grafana-admin-password ]; then
    (umask 077; openssl rand -base64 48 > /etc/qntm-charter/grafana-admin-password)
    chown 472:472 /etc/qntm-charter/grafana-admin-password
    chmod 0400 /etc/qntm-charter/grafana-admin-password
fi
nginx -t
systemctl daemon-reload
systemctl enable qntm-charter nginx qntm-charter-backup.timer
systemctl restart qntm-charter nginx
systemctl start qntm-charter-backup.timer
curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:8085/healthz
systemctl start qntm-charter-backup.service
docker compose -f /opt/qntm-charter-monitoring/compose.yml up -d
