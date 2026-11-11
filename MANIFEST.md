# MANIFEST — artifact index (branch `buildout/full-plan`)

Every artifact below was produced by the commands shown; caveats noted.
Regenerate measurements: `PAPER_REPORT.md` §9 has the full sequence.

## Reports (curated)

| Artifact | Produced by | Notes |
|---|---|---|
| `REPORT.md` | hand-written from verified findings | trace: every table row cites its phase commit or test output |
| `PAPER_REPORT.md` | `python Web/src/engine/paper_report.py` | auto-generated; every figure names its source JSON |
| `Web/src/engine/testbed/evaluate_report.json` | `testbed/evaluate.py --engine foxhound --headless` | **Phase 13**: dual-page (transforms + idb_workers), 28 scored flows / 2 benign; includes per-page tables, per-mechanism breakdown, worker-coverage checks; `--no-worker-injection` = true BEFORE, `--skip-crawl` reuses saved crawls + `evaluate_sink_log.json` |
| `Web/src/engine/testbed/consent_report.json` | `testbed/run_consent.py --engine foxhound` | misbehaving-banner page (`?misbehave=1`) by design |
| `Web/src/engine/testbed/storage_report.json` | `testbed/run_storage.py --engine chrome --headless` | respawn proof = cookie name `respawn_restored` |
| `Web/src/engine/testbed/smoke_report.json` | `testbed/run_smoke.py --engine foxhound` | last run 15/15 (foxhound); chrome run 14/14 (G3 taint is foxhound-only) |
| `Web/src/engine/testbed/scale_report.json` | `testbed/run_scale.py --engine chrome --headed` | store mode `jsonl` — this venv's Python lacks `_sqlite3`; SQLite path unit-verified under system Python |
| `Web/src/engine/testbed/partition_report_chrome.json` `..._foxhound.json` | `testbed/run_partition.py --engine <e>` | verdict specific to the localhost/127.0.0.1 top-level pair |
| `Web/backend/tests/*` | `python -m pytest Web/backend/tests -q` | 26 passed (SSRF + disclosure/gap + legacy policy + report/GRC + paper UID) |
| `Web/src/engine/testbed/samples/scan_report_sample.html` | rendered from the evaluation crawl (real testbed flows) | standards checklist verified; raw leaked values + source/sink columns (sensitive) |
| `Web/src/engine/testbed/samples/bulk_report_sample.html` | rendered from two analyses | counts-only executive view |
| `.github/workflows/ci.yml` | — | runs compileall + pytest + `tsc --noEmit` + `npm run build` |

## Ground truth / testbed pages

| Artifact | Role |
|---|---|
| `Web/src/engine/testbed/pages/smoke.html` | IDB→fetch/XHR/pixel, localStorage→beacon, inflow, 3P writer, FP control |
| `Web/src/engine/testbed/pages/consent.html` | fake OneTrust banner; tracker gated on accept, fires after reject when `?misbehave=1` |
| `Web/src/engine/testbed/pages/storage.html` | localStorage exfil, sessionStorage control, cookie↔IDB respawn cycle |
| `Web/src/engine/testbed/pages/transforms.html` | 7 transform variants × 5 sinks + benign controls + volatile record |
| `Web/src/engine/testbed/pages/idb_workers.html` | Phase 13: IDB writes (window) + orchestration of dedicated/shared/service workers |
| `Web/src/engine/testbed/pages/wk.js` | dedicated worker: IDB read → 11 transforms + xhr + beacon-equivalent + benign controls |
| `Web/src/engine/testbed/pages/wk-shared.js` | shared worker: IDB read → raw + base64 (blob-bootstrap injected) |
| `Web/src/engine/testbed/pages/wk-sw.js` | service worker: raw + base64 — **environment-dark**, sink-proven only, unscored |
| `Web/src/engine/testbed/ground_truth.py` | declarative FLOWS/WORKER_FLOWS/NON_IDENTIFIERS + md5 vector self-check |
| `Web/src/engine/testbed/evaluate_crawl.json` `evaluate_workers_crawl.json` | saved 2-iteration crawls powering `--skip-crawl` evaluation runs |
| `Web/src/engine/testbed/evaluate_sink_log.json` | persisted sink-receipt log (SW browser-side proof survives `--skip-crawl` process boundaries) |

## Engine additions (source)

| File | Phase | Purpose |
|---|---|---|
| `Web/src/engine/schema.py` | 0 | unified event schema (all mechanisms) |
| `Web/src/engine/transforms.py` | 3 | variant expansion + full request search + scoring |
| `Web/src/engine/consent.py` | 4 | CMP detection/act with explicit outcome states |
| `Web/src/engine/entities.py` | 5 | PSL + Disconnect + CNAME cloaking (data: `data/disconnect_services.json`) |
| `Web/src/engine/tranco.py` | 8 | ranked-list load/sample/download (data: `data/tranco_top1000.csv`) |
| `Web/src/engine/store.py` | 8 | SQLite/JSONL job store |
| `Web/src/engine/scale.py` | 8 | parallel resumable batch runner |
| `Web/src/engine/paper_report.py` | 11 | report generator |
| `Web/backend/security.py` | 10 | SSRF guard |
| `Web/src/engine/grc.py` | 12 | GRC checks (GDPR/ePrivacy/CCPA/ISO 27001) + header/policy collectors |
| `Web/src/engine/report_html.py` | 12 | standalone HTML renderers (single + bulk) |
| `Web/src/engine/uid.py` | UID | paper §4.1 client-identifier heuristic (IDB-only, 5 conditions) |
| `Web/backend/tests/test_uid.py` | UID | 7 pytest cases for the paper heuristic |
| `scripts/patch_playwright_ff.py` | UID | guards Playwright FF `pageError.location` driver crash (run after pip/playwright upgrades) |
| `Web/backend/policy_scanner/disclosure.py` `gap.py` | 9 | disclosure extraction + compliance gap (snapshots: `policy_scanner/snapshots/`) |

## Data vendored

| File | Source | Notes |
|---|---|---|
| `Web/src/engine/data/disconnect_services.json` | disconnect-me/disconnect-tracking-protection `services.json` | 379 KB; categories are **lists** of `{company: {url: [domains]}}` |
| `Web/src/engine/data/tranco_top1000.csv` | tranco-list.eu `top-1m.csv.zip` (first 1000) | full list via `tranco.py --download` |
| `Web/requirements.lock.txt` | `pip freeze` of the working venv | regenerate when deps change |

## Commands (verification)

```bash
# backend tests (14)
cd Web/backend && python -m pytest tests/ -q

# type check + build frontend
cd Web && npx tsc --noEmit && npm run build

# report endpoints (server must run)
curl -s localhost:8000/scan/<id>/report -o report.html
curl -s "localhost:8000/reports/bulk?live=1" -o bulk.html

# measurement suites (browsers + Git-LFS foxhound required)
cd Web/src/engine
python testbed/run_smoke.py   --engine foxhound
python testbed/run_consent.py --engine foxhound
python testbed/run_storage.py --engine chrome --headless
python testbed/run_partition.py --engine chrome --headless
python testbed/run_scale.py   --engine chrome --headed
python testbed/evaluate.py    --engine foxhound
python paper_report.py        # → PAPER_REPORT.md

# Phase 13 (worker-context hook closure) — all headless
python scripts/probe_worker_injection.py    # Q1–Q8 injection feasibility
python scripts/probe_worker_injection2.py   # Q9–Q13 shared/blob-SW
python scripts/probe_worker_injection3.py   # Q14–Q19 blob fallback
python testbed/evaluate.py --engine foxhound --headless --no-worker-injection  # BEFORE
python testbed/evaluate.py --engine foxhound --headless                        # AFTER

# Docker build (NOT run here — needs docker group/sudo)
sudo docker build -f Docker/Dockerfile.backend  -t privadb-backend  .
sudo docker build -f Docker/Dockerfile.frontend -t privadb-frontend .
```

## Phase 13 workspace (logs/ + raw/, AGENTS.md layout)

| Artifact | Produced by | Notes |
|---|---|---|
| `logs/01-env-inventory.log` … `logs/42-final-verify.log` | every Phase-13/13.1 command, header = step + exact invocation | numbered, ANSI-free, reproducible standalone |
| `logs/03-worker-injection-probe.log` `04-probe2` `05-probe3` | `scripts/probe_worker_injection{,2,3}.py` | injection-feasibility verdicts (Q1–Q19) |
| `logs/06-evaluate-baseline-before.log` | `evaluate.py --headless` pre-change | reproduces the published Phase-7 numbers exactly |
| `logs/11-evaluate-BEFORE-noinjection.log` `logs/17-evaluate-AFTER-v2.log` | `evaluate.py --no-worker-injection` / `--headless` | the before/after pair cited by REPORT.md Phase 13 |
| `logs/18-final-delta.log` | delta computation over `raw/11` + `raw/17` | per-method/per-mechanism Δ table |
| `logs/27`–`logs/42` | revalidation after the Phase-13.1 blob rework | `27` foxhound smoke · `28` chrome evaluate (phantom discovery) · `32`–`35` cross-origin reproducers · `36` both smokes · `38`/`39` both-engine evaluates (exit 0, WC 7/7) · `41` live braze/reddit spot check · `42` skip-crawl + CI |
| `raw/03-worker-injection-probe.json` `raw/04-probe2.json` `raw/05-probe3.json` | probe outputs (unmodified) | injection-feasibility verdicts Q1–Q19 (historical: route path superseded by blob rework) |
| `raw/06-evaluate-baseline-BEFORE.json` | pre-change evaluate_report | regression anchor |
| `raw/38-sinklog-foxhound.json` `raw/39-sinklog-chrome.json` | evaluate sink logs after rework | **99 hits each; all 18 worker-context paths physically arrived** (phantom-bug regression guard) |
| `raw/11-evaluate-BEFORE-noinjection.json` `raw/17-evaluate-AFTER-final.json` | evaluate_report snapshots | before/after numbers behind REPORT tables |
| `scripts/probe_worker_injection{,2,3}.py` | hand-written probes | reusable feasibility harness for other browser stacks |

## Caveats

- Measurement suites bind fixed ports **18765/18766** — one suite at a time.
- Testbed verdicts (partitioning, consent) are specific to the fixture pages/hosts used; production claims need a Tranco run + human labels.
- `results/` outputs are gitignored (privacy); committed reports are the durable record.
- This venv Python (3.12 custom build) lacks `_sqlite3`; `store.py` auto-falls back to JSONL — both paths tested.
- Foxhound binary provenance: `Web/foxhound/application.ini` BuildID `20251126175156` (Firefox 137.0 base), recorded per crawl in `run_meta.foxhound_build_id`.
- **Playwright FF driver must be patched** (`python scripts/patch_playwright_ff.py`) after every playwright install/upgrade — unpatched, live pages with location-less page errors crash the driver and silently empty all JS-based extraction (batches then report `identifiers: 0` despite network capture).
- Paper §4.1 UID detection needs `iterations ≥ 2` (fresh profiles) + reload pass (`UID_RELOAD_CHECK`); with `iterations=1` the classifier reports `evaluated: false` instead of guessing.
- Live study artifacts: pilot committed under `campaign_results/live15/`; raw working copies in `data/scale/` (job stores are gitignored) and `results/` (gitignored) with per-site HTML reports in `results/<Engine>/reports/`.
- Campaign CPU policy: run with `--max-cpu 50` — the governor holds new scan launches while aggregate CPU is above the cap (in-flight drains; floor of 1 for progress when the host baseline itself is above the cap). Watch the `⏳ CPU … throttled` lines in the batch log.
- `--prune-raw` removes raw crawl JSONs after analysis (run_meta embedded); pruned sites cannot be re-analyzed via `detect_only` — keep raw for sites you plan to re-run.
- **Phase 13 injection caveats (post-13.1 rework)**: dedicated + shared workers run from **blob: bootstraps** (core + importScripts with absolute rebasing; `location` is a blob: URL; CSP `worker-src` without `blob:` falls back to the untouched constructor with a `blob_blocked` gap; site-authored blob/data workers pass through untouched with a `non_http` gap); **service workers are left unmarked on both engines** (FF: route bypass; Chromium: route-fulfilling the SW script breaks its cross-origin fetches — `net::ERR_FAILED`, logs/32–35) so SW flows are sink-proven/unscored with a per-crawl `no_hello` gap; Firefox workers expose no `navigator.sendBeacon` (GT uses `fetch+keepalive`); route-based injection was **removed** after producing phantom requests on Chromium (logs/28–39); live sites may unwrap hooks — detected via `__tamper_check` (braze.com example, logs/41).
