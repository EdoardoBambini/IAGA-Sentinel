#!/usr/bin/env bash
# IAGA Sentinel live demo driver (Linux/macOS). Requires curl + jq.
#
# Secondary to the primary Windows version scripts/demo_run.ps1. Drives the
# three real seeded scenarios (Allow -> Review -> Block) through the live
# pipeline under one shared sessionId, asserts each verdict, then exports the
# signed receipt chain and verifies it offline with iaga-verify.
#
# Usage:  ./scripts/demo_run.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

BASE="${BASE_URL:-http://localhost:4010}"
SID="${SESSION_ID:-demo-session-iaga}"
PAUSE="${PAUSE_SEC:-5}"
CHAIN="${CHAIN_FILE:-chain.json}"
IAGA="$REPO_ROOT/target/release/iaga"
VERIFY="$REPO_ROOT/target/release/iaga-verify"

command -v jq >/dev/null || { echo "this script needs jq (sudo apt install jq)"; exit 2; }

echo "== IAGA SENTINEL - LIVE GOVERNANCE (one signed session) =="
echo "Session: $SID  (all 3 beats chain into one run, run_id=<agentId>:$SID)"

# Determinism guard: reset adaptive weights (open mode = implicit admin).
curl -fsS -X POST "$BASE/v1/risk/weights/reset" >/dev/null 2>&1 || true

# Pull the real seeded scenarios from the running server.
SCEN="$(curl -fsS "$BASE/v1/demo/scenarios")"

fail=0
run_beat() { # $1=index(0..2) $2=expect $3=label
  local idx="$1" exp="$2" label="$3" req resp dec score
  req="$(echo "$SCEN" | jq -c --arg sid "$SID" ".[$idx].request + {metadata:{sessionId:\$sid}}")"
  resp="$(curl -fsS -X POST "$BASE/v1/inspect" -H 'content-type: application/json' -d "$req")"
  dec="$(echo "$resp" | jq -r .decision)"
  score="$(echo "$resp" | jq -r .risk.score)"
  echo ""
  echo ">> BEAT $((idx + 1))/3  ABOUT TO: $label  | expected: $exp"
  echo ">> VERDICT: $(echo "$dec" | tr '[:lower:]' '[:upper:]')  risk=$score"
  if [[ "$dec" != "$exp" ]]; then
    echo "   ASSERTION FAILED: expected $exp, got $dec"
    fail=1
  fi
}

run_beat 0 allow  "Safe MCP-aligned repo read";   sleep "$PAUSE"
run_beat 1 review "Shell + secret -> review";      sleep "$PAUSE"
run_beat 2 block  "rm -rf -> blocked";             sleep 2

if [[ $fail -ne 0 ]]; then
  echo ""
  echo "STOP: verdict assertion failed - do NOT use this take."
  exit 1
fi

echo ""
echo "== MONEY SHOT - OFFLINE PROOF (no server, no DB, just a file + a key) =="
"$IAGA" replay "$SID" --export "$CHAIN"
PUB="$(jq -r .signer_verifying_key "$CHAIN")"
RUN="$(jq -r .run_id "$CHAIN")"
CNT="$(jq '.receipts | length' "$CHAIN")"
echo "  run_id=$RUN  receipts=$CNT  (seq 0,1,2 = Allow, Review, Block)"
echo "> iaga-verify $CHAIN"
"$VERIFY" "$CHAIN"
echo "> iaga-verify $CHAIN --key <pinned>"
"$VERIFY" "$CHAIN" --key "$PUB"
echo "CHAIN OK (offline) - terminal verdict BLOCK, run_id=$RUN"
