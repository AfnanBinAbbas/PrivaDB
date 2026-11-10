# MANIFEST — artifact index (branch `buildout/full-plan`)

Every artifact below was produced by the commands shown; caveats noted.
Regenerate measurements: `PAPER_REPORT.md` §9 has the full sequence.

## Reports (curated)

| Artifact | Produced by | Notes |
|---|---|---|
| `REPORT.md` | hand-written from verified findings | trace: every table row cites its phase commit or test output |
| `PAPER_REPORT.md` | `python Web/src/engine/paper_report.py` | auto-generated; every figure names its source JSON |
| `Web/src/engine/testbed/evaluate_report.json` | `testbed/evaluate.py --engine foxhound` | 12 flows / 2 benign ground truth; crawl reused via `--skip-crawl` after the final ablation change |
| `Web/src/engine/testbed/consent_report.json` | `testbed/run_consent.py --engine foxhound` | misbehaving-banner page (`?misbehave=1`) by design |
| `Web/src/engine/testbed/storage_report.json` | `testbed/run_storage.py --engine chrome --headless` | respawn proof = cookie name `respawn_restored` |
| `Web/src/engine/testbed/smoke_report.json` | `testbed/run_smoke.py --engine foxhound` | last run 15/15 (foxhound); chrome run 14/14 (G3 taint is foxhound-only) |
| `Web/src/engine/testbed/scale_report.json` | `testbed/run_scale.py --engine chrome --headed` | store mode `jsonl` — this venv's Python lacks `_sqlite3`; SQLite path unit-verified under system Python |
| `Web/src/engine/testbed/partition_report_chrome.json` `..._foxhound.json` | `testbed/run_partition.py --engine <e>` | verdict specific to the localhost/127.0.0.1 top-level pair |
| `Web/backend/tests/*` | `python -m pytest Web/backend/tests -q` | 19 passed (SSRF + disclosure/gap + legacy policy + report/GRC) |
| `Web/src/engine/testbed/samples/scan_report_sample.html` | rendered from the evaluation crawl (real testbed flows) | standards checklist verified; values hashed |
| `Web/src/engine/testbed/samples/bulk_report_sample.html` | rendered from two analyses | counts-only executive view |
| `.github/workflows/ci.yml` | — | runs compileall + pytest + `tsc --noEmit` + `npm run build` |

## Ground truth / testbed pages

| Artifact | Role |
|---|---|
| `Web/src/engine/testbed/pages/smoke.html` | IDB→fetch/XHR/pixel, localStorage→beacon, inflow, 3P writer, FP control |
| `Web/src/engine/testbed/pages/consent.html` | fake OneTrust banner; tracker gated on accept, fires after reject when `?misbehave=1` |
| `Web/src/engine/testbed/pages/storage.html` | localStorage exfil, sessionStorage control, cookie↔IDB respawn cycle |
| `Web/src/engine/testbed/pages/transforms.html` | 7 transform variants × 5 sinks + benign controls + volatile record |
| `Web/src/engine/testbed/ground_truth.py` | declarative FLOWS/NON_IDENTIFIERS + md5 vector self-check |
| `Web/src/engine/testbed/evaluate_crawl.json` | saved 2-iteration crawl powering `--skip-crawl` evaluation runs |

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

# Docker build (NOT run here — needs docker group/sudo)
sudo docker build -f Docker/Dockerfile.backend  -t privadb-backend  .
sudo docker build -f Docker/Dockerfile.frontend -t privadb-frontend .
```

## Caveats

- Measurement suites bind fixed ports **18765/18766** — one suite at a time.
- Testbed verdicts (partitioning, consent) are specific to the fixture pages/hosts used; production claims need a Tranco run + human labels.
- `results/` outputs are gitignored (privacy); committed reports are the durable record.
- This venv Python (3.12 custom build) lacks `_sqlite3`; `store.py` auto-falls back to JSONL — both paths tested.
- Foxhound binary provenance: `Web/foxhound/application.ini` BuildID `20251126175156` (Firefox 137.0 base), recorded per crawl in `run_meta.foxhound_build_id`.
