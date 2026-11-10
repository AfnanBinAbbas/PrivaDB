#!/bin/bash
# Recurring campaign-results sync: every $INTERVAL seconds, regenerate
# campaign_results/stageA, commit, push. Stops after the final sync
# once the Stage-A campaign completes (sync exit code 99).
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="$REPO/venv/bin/python"
INTERVAL="${1:-1800}"   # default: every 30 minutes
LOG="${2:-/tmp/opencode/results_sync.log}"
echo "[loop] start $(date -Is) interval=${INTERVAL}s log=$LOG" >> "$LOG"
while true; do
  "$PY" "$REPO/scripts/sync_campaign_results.py" >> "$LOG" 2>&1
  rc=$?
  echo "[loop] sync rc=$rc at $(date -Is)" >> "$LOG"
  if [ "$rc" -eq 99 ]; then
    echo "[loop] campaign complete — exiting" >> "$LOG"
    break
  fi
  if [ "$rc" -ge 2 ] && [ "$rc" -ne 99 ]; then
    echo "[loop] sync error rc=$rc — continuing after interval" >> "$LOG"
  fi
  sleep "$INTERVAL"
done
