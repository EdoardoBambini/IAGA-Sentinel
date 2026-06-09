#!/usr/bin/env bash
# IAGA Sentinel - Claude Code PreToolUse hook (Bash variant, Unix/macOS).
#
# Reads a PreToolUse event on stdin, asks the IAGA Sentinel sidecar to govern
# the action (POST /v1/inspect), and emits a permission decision on stdout.
# One signed, offline-verifiable receipt per tool call. Requires: curl, jq.
#
# The cross-platform reference is iaga_claude_hook.py; this script mirrors it
# for users who prefer a pure-shell hook. Env vars are identical.
#
#   IAGA_BASE_URL    sidecar base URL          (default: http://localhost:4010)
#   IAGA_AGENT_ID    agentId on the receipt    (default: claude-code)
#   IAGA_FRAMEWORK   framework label           (default: claude-code)
#   IAGA_API_KEY     bearer token, if required (default: none)
#   IAGA_TIMEOUT     request timeout, seconds  (default: 5)
#   IAGA_FAIL_CLOSED truthy -> deny when the sidecar is unreachable
#                    (default: fail-open - the action proceeds, no receipt)
set -u

BASE_URL="${IAGA_BASE_URL:-http://localhost:4010}"
AGENT_ID="${IAGA_AGENT_ID:-claude-code}"
FRAMEWORK="${IAGA_FRAMEWORK:-claude-code}"
TIMEOUT="${IAGA_TIMEOUT:-5}"

emit_allow() { echo '{}'; exit 0; }            # do not interfere; normal flow
emit() {                                       # $1=decision $2=reason
  jq -cn --arg d "$1" --arg r "$2" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:$d,permissionDecisionReason:$r}}'
  exit 0
}
is_truthy() { case "${1:-}" in 1|true|TRUE|yes|on) return 0 ;; *) return 1 ;; esac; }

payload="$(cat)"
tool_name="$(jq -r '.tool_name // "unknown"' <<<"$payload" 2>/dev/null || echo unknown)"
session_id="$(jq -r '.session_id // empty' <<<"$payload" 2>/dev/null || echo '')"

case "$tool_name" in
  Bash)                              action_type="shell" ;;
  Read|Glob|Grep)                    action_type="file_read" ;;
  Write|Edit|MultiEdit|NotebookEdit) action_type="file_write" ;;
  WebFetch|WebSearch)                action_type="http" ;;
  *)                                 action_type="custom" ;;
esac

request="$(jq -cn \
  --arg agentId "$AGENT_ID" --arg framework "$FRAMEWORK" \
  --arg type "$action_type" --arg toolName "$tool_name" \
  --arg sessionId "$session_id" \
  --argjson input "$(jq -c '.tool_input // {}' <<<"$payload" 2>/dev/null || echo '{}')" \
  '{agentId:$agentId, framework:$framework,
    action:{type:$type, toolName:$toolName, payload:$input}}
   + (if $sessionId == "" then {} else {metadata:{sessionId:$sessionId}} end)')"

if [ -n "${IAGA_API_KEY:-}" ]; then
  verdict="$(curl -s --max-time "$TIMEOUT" -X POST "${BASE_URL}/v1/inspect" \
    -H 'Content-Type: application/json' -H "Authorization: Bearer ${IAGA_API_KEY}" \
    -d "$request")" || verdict=""
else
  verdict="$(curl -s --max-time "$TIMEOUT" -X POST "${BASE_URL}/v1/inspect" \
    -H 'Content-Type: application/json' -d "$request")" || verdict=""
fi

if [ -z "$verdict" ] || ! jq -e . >/dev/null 2>&1 <<<"$verdict"; then
  if is_truthy "${IAGA_FAIL_CLOSED:-}"; then
    emit "deny" "IAGA Sentinel unreachable (fail-closed)"
  fi
  emit_allow
fi

decision="$(jq -r '.decision // "allow"' <<<"$verdict")"
reason="$(jq -r '(.risk.reasons // []) | join("; ")' <<<"$verdict")"

case "$decision" in
  block)  emit "deny" "${reason:-blocked by IAGA Sentinel}" ;;
  review) emit "ask" "${reason:-IAGA Sentinel requires human review}" ;;
  *)      emit_allow ;;
esac
