#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
for command in swift node npm python3 curl; do
  command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 1; }
done
[[ -x worker/node_modules/.bin/wrangler && -x gateway-worker/node_modules/.bin/wrangler && -f client/dist/index.js ]] || {
  echo 'Install worker/gateway-worker/client npm dependencies and build client before running.' >&2; exit 1;
}
relay_port=${QNTM_SWIFT_RELAY_PORT:-8798}
gateway_port=${QNTM_SWIFT_GATEWAY_PORT:-8799}
target_port=${QNTM_SWIFT_TARGET_PORT:-8800}
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/qntm-swift-integration.XXXXXX")
pids=()
cleanup() {
  code=$?
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  if [[ $code -ne 0 ]]; then
    for log in "$run_dir"/*.log; do echo "Log: $log"; tail -80 "$log"; done
    echo "Retained integration logs at $run_dir" >&2
  else rm -rf "$run_dir"; fi
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
export WRANGLER_SEND_METRICS=false
export QNTM_TEST_RELAY_URL="http://127.0.0.1:$relay_port"
export QNTM_SWIFT_TEST_RELAY="$QNTM_TEST_RELAY_URL"
export QNTM_TEST_GATEWAY_URL="http://127.0.0.1:$gateway_port"
export QNTM_TEST_GATEWAY_TARGET_URL="http://127.0.0.1:$target_port"
export QNTM_SWIFT_INTEROP=1
# Fail before launch if a selected port is already owned by another process.
python3 - "$relay_port" "$gateway_port" "$target_port" <<'PY'
import socket,sys
for port in sys.argv[1:]:
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.bind(('127.0.0.1',int(port)))
PY
vault_key=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
(
  cd worker
  exec node node_modules/wrangler/bin/wrangler.js dev --local --port "$relay_port" --ip 127.0.0.1 --inspector-port 0 --persist-to "$run_dir/relay" --var RATE_LIMIT_PER_MIN:5000
) >"$run_dir/relay.log" 2>&1 &
pids+=("$!")
(
  cd gateway-worker
  exec node node_modules/wrangler/bin/wrangler.js dev --local --port "$gateway_port" --ip 127.0.0.1 --inspector-port 0 --persist-to "$run_dir/gateway" --var "DROPBOX_URL:$QNTM_TEST_RELAY_URL" --var POLL_INTERVAL_MS:250 --var "GATE_VAULT_KEY:$vault_key"
) >"$run_dir/gateway.log" 2>&1 &
pids+=("$!")
unset vault_key
python3 -u - "$target_port" >"$run_dir/target.log" 2>&1 <<'PY' &
from http.server import HTTPServer,BaseHTTPRequestHandler
import json,sys
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.end_headers();self.wfile.write(b'ok')
    def do_POST(self):
        body=self.rfile.read(int(self.headers.get('Content-Length',0)))
        self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers()
        self.wfile.write(json.dumps({'ok':True,'received':body.decode(),'credential':self.headers.get('X-Qntm-Demo')}).encode())
HTTPServer(('127.0.0.1',int(sys.argv[1])),Handler).serve_forever()
PY
pids+=("$!")
for url in "$QNTM_TEST_RELAY_URL/healthz" "$QNTM_TEST_GATEWAY_URL/health" "$QNTM_TEST_GATEWAY_TARGET_URL/"; do
  ready=false
  for _ in {1..120}; do
    if curl --silent --fail --max-time 1 "$url" >/dev/null; then ready=true; break; fi
    sleep 0.25
  done
  [[ "$ready" == true ]] || { echo "Local service did not start: $url" >&2; exit 1; }
done
swift test "$@"
python3 swift/scripts/verify-cli.py --relay "$QNTM_TEST_RELAY_URL"
