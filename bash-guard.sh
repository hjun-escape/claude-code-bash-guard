#!/usr/bin/env bash
# PreToolUse(Bash): prod / shared-history gate + Bash-write parity with the Edit/Write guards (bash_guard.py).
# Fast path: Python only runs when the raw input mentions a trigger word, so ordinary commands cost ~10 ms.
in=$(cat)
acct="${BASH_GUARD_PROD_ACCOUNT:-111111111111}"
case "$in" in
  *"$acct"*|*prod*|*release*|*workflow*|*merge*|*push*|*rerun*|*commit*|*.env*|*stacks-map*|*key.properties*|*.pem*|*.p12*|*.keystore*|*.jks*|*certs/*|*lock*) ;;
  *) exit 0 ;;
esac
dir=$(cd "$(dirname "$0")" && pwd)
if out=$(printf '%s' "$in" | python3 "$dir/bash_guard.py" 2>&1); then
  printf '%s' "$out"
else
  # Fail closed for candidate commands only: a crashed guard asks instead of silently allowing.
  jq -n --arg r "bash-guard crashed — confirm this command yourself. $(printf '%s' "$out" | tail -1)" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $r}}'
fi
exit 0
