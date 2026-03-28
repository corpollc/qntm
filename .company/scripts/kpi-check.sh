#!/bin/bash
# KPI Check Script — qntm
# Polls relay stats, health, and echo bot status
# Appends to kpis.jsonl when run with --append
# Usage: ./kpi-check.sh [--append]

set -euo pipefail

RELAY_URL="https://inbox.qntm.corpo.llc"
ECHO_BOT_URL="https://qntm-echo-bot.peter-078.workers.dev"
KPIS_FILE="$(dirname "$0")/../kpis.jsonl"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== qntm KPI Dashboard ==="
echo "Time: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo ""

# 1. Relay health
RELAY_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${RELAY_URL}/healthz" 2>/dev/null || echo "000")
if [ "$RELAY_STATUS" = "200" ]; then
    echo -e "Relay: ${GREEN}OPERATIONAL${NC} (HTTP ${RELAY_STATUS})"
    RELAY_UP="true"
else
    echo -e "Relay: ${RED}DOWN${NC} (HTTP ${RELAY_STATUS})"
    RELAY_UP="false"
fi

# 2. Stats endpoint
STATS_RAW=$(curl -s "${RELAY_URL}/v1/stats" 2>/dev/null || echo '{}')
ACTIVE_CONVOS=$(echo "$STATS_RAW" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('active_conversations_7d', 'N/A'))" 2>/dev/null || echo "N/A")
echo "Active conversations (7d): ${ACTIVE_CONVOS}"

# Show conversation details
echo "$STATS_RAW" | python3 -c "
import json, sys, datetime
d = json.load(sys.stdin)
for c in d.get('conversations', []):
    ts = c.get('last_message_ts', 0)
    dt = datetime.datetime.fromtimestamp(ts/1000, tz=datetime.timezone.utc)
    age_min = (datetime.datetime.now(datetime.timezone.utc) - dt).total_seconds() / 60
    print(f'  {c[\"conv_id\"][:8]}... last msg {age_min:.0f}m ago ({dt.strftime(\"%H:%M UTC\")})')
" 2>/dev/null || true

# 3. Echo bot health  
ECHO_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${ECHO_BOT_URL}" 2>/dev/null || echo "000")
if [ "$ECHO_STATUS" = "200" ]; then
    echo -e "Echo bot: ${GREEN}LIVE${NC} (HTTP ${ECHO_STATUS})"
    ECHO_UP="true"
else
    echo -e "Echo bot: ${YELLOW}CHECK${NC} (HTTP ${ECHO_STATUS})"
    ECHO_UP="false"
fi

# 4. GitHub stats
GH_STATS=$(curl -s "https://api.github.com/repos/corpollc/qntm" 2>/dev/null || echo '{}')
STARS=$(echo "$GH_STATS" | python3 -c "import json,sys; print(json.load(sys.stdin).get('stargazers_count','?'))" 2>/dev/null || echo "?")
FORKS=$(echo "$GH_STATS" | python3 -c "import json,sys; print(json.load(sys.stdin).get('forks_count','?'))" 2>/dev/null || echo "?")
echo "GitHub: ${STARS} stars, ${FORKS} forks"

# 5. Published CLI check — test if polling API still returns 410
CLI_RESPONSE=$(curl -s -X POST "https://inbox.qntm.corpo.llc/v1/poll" 2>/dev/null || echo '{}')
CLI_ERROR=$(echo "$CLI_RESPONSE" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null || echo "")
if echo "$CLI_ERROR" | grep -q "polling has been removed"; then
    echo -e "Published CLI: ${RED}BROKEN${NC} (poll returns 410)"
    CLI_BROKEN="true"
else
    echo -e "Published CLI: ${GREEN}OK${NC}"
    CLI_BROKEN="false"
fi

# 6. A2A engagement count
echo ""
echo "=== External Presence ==="
echo "A2A engagements: 3 (#1575, #1667, #1606)"
echo "External users: 0"
echo "Design partners: 0"

echo ""
echo "=== Blockers ==="
if [ "$CLI_BROKEN" = "true" ]; then
    echo -e "${RED}P0: Published CLI (v0.3) is BROKEN — recv returns 410${NC}"
fi
echo "PyPI publish: REQUIRES_APPROVAL"
echo "Public posting: DENIED"
