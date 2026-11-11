#!/bin/bash
# Priority sequence (operator instruction): FIRST re-crawl the 439
# pre-wipe IDB-active sites (analyses destroyed by the run_scale rmtree
# incident — REPORT Phase 13.2), THEN resume the main Top-10k campaign
# where it left off (4126+ done). The sync loop keeps running
# independently (30-min commits); both phases write analyses into the
# shared data/scale/results/ dir, so paper_comparison.py event-level
# tables fill in as the redo lands.
#
# Usage: nohup bash scripts/run_idb_redo_then_resume.sh >/dev/null 2>&1 &
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="$REPO/venv/bin/python"
LOGD="$REPO/campaign_results/logs"
REDO_LOG="$LOGD/54-idb-redo.log"
MAIN_LOG="$LOGD/44-stageA-campaign-resume.log"
COMMON=(--engine foxhound --workers 2 --iterations 1 --timeout 300
        --attempts 2 --max-cpu 50 --prune-raw --sample 10000)

echo "[wrapper] redo start $(date -Is)" >> "$REDO_LOG"
"$PY" "$REPO/Web/src/engine/scale.py" \
  --list "$REPO/campaign_results/stageA/idb_redo_list.csv" \
  --db "$REPO/Web/src/engine/data/scale/stageA_idb_redo.jsonl" \
  "${COMMON[@]}" >> "$REDO_LOG" 2>&1
rc=$?
echo "[wrapper] redo finished rc=$rc $(date -Is)" >> "$REDO_LOG"

# Refresh the paper comparison with the restored analyses, then commit
# the batch via the normal sync (commit+push).
"$PY" "$REPO/scripts/paper_comparison.py" >> "$REDO_LOG" 2>&1
"$PY" "$REPO/scripts/sync_campaign_results.py" >> "$REDO_LOG" 2>&1
echo "[wrapper] comparison+sync done $(date -Is)" >> "$REDO_LOG"

# Resume the main campaign (resume skips its own done rows — the 439
# stay done there; they were re-crawled via the redo store).
echo "[wrapper] resuming main campaign $(date -Is)" >> "$REDO_LOG"
nohup "$PY" "$REPO/Web/src/engine/scale.py" \
  --list "$REPO/Web/src/engine/data/tranco_10000.csv" \
  --db "$REPO/Web/src/engine/data/scale/stageA_10k.jsonl" \
  "${COMMON[@]}" >> "$MAIN_LOG" 2>&1 &
echo "[wrapper] main campaign pid=$! $(date -Is)" >> "$REDO_LOG"
