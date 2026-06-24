#!/bin/bash
LOG="/var/ossec/logs/active-responses.log"

# Wazuh 4.x Stateful Active Response Protocol
# Step 1: Read the alert JSON from execd via STDIN (-r preserves backslashes)
read -r INPUT
echo "$(date) custom-block.sh received command" >> $LOG

# Step 2: Save to temp file for reliable JSON parsing
TMPFILE=$(mktemp)
printf '%s' "$INPUT" > "$TMPFILE"

# Step 3: Extract all fields in one python3 call
eval $(python3 -c "
import json,sys
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    srcip = d.get('parameters',{}).get('alert',{}).get('data',{}).get('srcip','unknown')
    ruleid = d.get('parameters',{}).get('alert',{}).get('rule',{}).get('id','unknown')
    cmd = d.get('command','unknown')
    print(f'SRCIP={srcip} RULEID={ruleid} CMD={cmd}')
except:
    print('SRCIP=unknown RULEID=unknown CMD=unknown')
" "$TMPFILE" 2>/dev/null) || { SRCIP=unknown; RULEID=unknown; CMD=unknown; }

# Step 4: Send check_keys message to STDOUT
echo '{"version":1,"origin":{"name":"custom-block","module":"active-response"},"command":"check_keys","parameters":{"keys":["'"$SRCIP"'"]}}'

# Step 5: Read continue/abort response from execd
read -r RESPONSE

echo "$(date) ACTION: $CMD srcip:$SRCIP rule:$RULEID" >> $LOG

if command -v iptables &>/dev/null && [ "$SRCIP" != "unknown" ] && [ "$SRCIP" != "" ]; then
  if [ "$CMD" = "add" ]; then
    iptables -I INPUT -s "$SRCIP" -j DROP 2>/dev/null
    iptables -I FORWARD -s "$SRCIP" -j DROP 2>/dev/null
    echo "$(date) BLOCKED $SRCIP via iptables (rule:$RULEID)" >> $LOG
  elif [ "$CMD" = "delete" ]; then
    iptables -D INPUT -s "$SRCIP" -j DROP 2>/dev/null
    iptables -D FORWARD -s "$SRCIP" -j DROP 2>/dev/null
    echo "$(date) UNBLOCKED $SRCIP via iptables (rule:$RULEID)" >> $LOG
  fi
fi

rm -f "$TMPFILE"
exit 0
