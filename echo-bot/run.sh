#!/usr/bin/env bash
# qntm Echo Bot — proves encrypted messaging works in real-time
# Run: ./echo-bot/run.sh
# Anyone can join with the invite token in the README and exchange encrypted messages.

set -euo pipefail

CONFIG_DIR="$(cd "$(dirname "$0")/.qntm" && pwd)"
CONVO_ID="48055654db4bb0f64ec63089b70e1bf4"
POLL_INTERVAL=5  # seconds between polls
LAST_SEQ_FILE="$CONFIG_DIR/.last_seq"

# Track last processed sequence to avoid re-echoing
last_seq=0
if [[ -f "$LAST_SEQ_FILE" ]]; then
  last_seq=$(cat "$LAST_SEQ_FILE")
fi

echo "🔒 qntm echo bot starting..."
echo "   Config: $CONFIG_DIR"
echo "   Conversation: $CONVO_ID"
echo "   Polling every ${POLL_INTERVAL}s"
echo "   Last processed seq: $last_seq"
echo ""

# Our own key_id so we skip our own messages
MY_KID=$(uvx qntm identity show --config-dir "$CONFIG_DIR" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['key_id'])")
echo "   My key_id: $MY_KID"
echo ""
echo "🤖 Listening for messages..."

while true; do
  # Receive new messages
  recv_output=$(uvx qntm recv --config-dir "$CONFIG_DIR" "$CONVO_ID" 2>/dev/null || echo '{"ok":false}')
  
  if echo "$recv_output" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('ok') else 1)" 2>/dev/null; then
    # Parse messages
    messages=$(echo "$recv_output" | python3 -c "
import sys, json
data = json.load(sys.stdin)
msgs = data.get('data', {}).get('messages', [])
for m in msgs:
    # Output: sender_kid|body
    body = m.get('unsafe_body', m.get('body', ''))
    kid = m.get('sender_kid', '')
    mid = m.get('message_id', '')
    print(f'{kid}|{mid}|{body}')
" 2>/dev/null || true)
    
    if [[ -n "$messages" ]]; then
      while IFS= read -r line; do
        sender_kid=$(echo "$line" | cut -d'|' -f1)
        msg_id=$(echo "$line" | cut -d'|' -f2)
        body=$(echo "$line" | cut -d'|' -f3-)
        
        # Skip our own messages
        if [[ "$sender_kid" == *"$MY_KID"* ]] || [[ "$sender_kid" == "${MY_KID}"* ]]; then
          continue
        fi
        
        # Skip empty messages
        if [[ -z "$body" ]]; then
          continue
        fi
        
        echo "📩 Received from ${sender_kid:0:8}...: $body"
        
        # Echo it back with encryption badge
        echo_msg="🔒 echo: $body"
        send_result=$(uvx qntm send --config-dir "$CONFIG_DIR" "$CONVO_ID" "$echo_msg" 2>/dev/null || echo '{"ok":false}')
        
        if echo "$send_result" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('ok') else 1)" 2>/dev/null; then
          echo "📤 Echoed: $echo_msg"
        else
          echo "❌ Failed to echo message"
        fi
      done <<< "$messages"
    fi
  fi
  
  sleep "$POLL_INTERVAL"
done
