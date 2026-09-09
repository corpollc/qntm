#!/bin/sh
# Dedicated monitoring VM. Supply private config and probe state separately.
set -eu
test "$(id -u)" = 0
cd "$(dirname "$0")"
test -f config.json
test -f probe.cbor
id qntm-monitor >/dev/null 2>&1 || useradd --system --home-dir /var/lib/qntm-relay-monitor --shell /usr/sbin/nologin qntm-monitor
install -d -m 0755 /opt/qntm-relay-monitor
install -d -m 0750 -o root -g qntm-monitor /etc/qntm-relay-monitor
install -d -m 0700 -o qntm-monitor -g qntm-monitor /var/lib/qntm-relay-monitor
install -m 0644 relay_monitor.py requirements.txt /opt/qntm-relay-monitor/
install -m 0640 -o root -g qntm-monitor config.json /etc/qntm-relay-monitor/config.json
if [ ! -f /var/lib/qntm-relay-monitor/probe.cbor ]; then
    install -m 0600 -o qntm-monitor -g qntm-monitor probe.cbor /var/lib/qntm-relay-monitor/probe.cbor
fi
if [ ! -x /opt/qntm-relay-monitor/venv/bin/python ]; then
    uv venv --python python3 /opt/qntm-relay-monitor/venv
fi
uv pip install --python /opt/qntm-relay-monitor/venv/bin/python -r requirements.txt
install -m 0644 qntm-relay-monitor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable qntm-relay-monitor
systemctl restart qntm-relay-monitor
