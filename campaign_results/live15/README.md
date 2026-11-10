# campaign_results — measured outputs committed to the repository

## live15/ — pilot campaign (2026-11-10)

15 live websites scanned with **Foxhound dynamic taint analysis**
(PrivaDB staged campaign pilot before the Tranco Top-10k run).

| File | What it is |
|---|---|
| `summary_table.md` | headline table: per-site IDB dbs/records, §4.1 confirmed identities, taint/hook/storage-exfil counts + totals |
| `store_live15c.jsonl` | resumable job-store for the 15-site batch (status/attempts/small counts — no raw values) |
| `store_braze.jsonl` | job-store of the Braze supplement run |
| `foxhound_bulk_latest.html` | aggregate executive report (counts only, no raw values) |
| `reports/*.html` | **per-site standalone reports — contain RAW leaked values with source→sink provenance. SENSITIVE** (they are the operator's own measured tracker identifiers from these visits) |

### Run parameters

```bash
python scale.py --urls <15 sites> --engine foxhound --workers 2 \
  --iterations 2 --timeout 240 --attempts 2 \
  --db data/scale/live15c.sqlite
# braze supplement: --urls https://www.braze.com/ --db data/scale/braze_uid.sqlite
```

Prerequisites on the crawler host: `python scripts/patch_playwright_ff.py`
(unpatched Playwright FF driver crashes on live sites and silently
empties all JS-based extraction), Git-LFS Foxhound binary,
`playwright install firefox` NOT required (custom executable).

### Findings (14/15 completed — youtube.com timed out ×2)

- **4,344+ taint flows**, **2,912+ storage exfils** — identity leakage
  from these sites happens overwhelmingly via **localStorage/cookies**,
  not IndexedDB.
- **0 §4.1-confirmed IndexedDB client identifiers** on landing views —
  rejections were correct per the paper (reddit boilerplate static
  sim=1.0 → C5 fail; linkedin sequenceNumber → C2+C5 fail; braze
  attribution sim=0.97 → C5 fail; billabong/omtechlaser open 5 IDB
  stores each with empty stores pre-interaction).

### Status

- **Stage A (Tranco Top-10k, iterations=1, `--max-cpu 50
  --prune-raw`)**: launched from the same runner — see
  `data/scale/stageA_10k.sqlite` on the crawler host (gitignored).
- **Stage B (§4.1 on IDB-active sites)**: input generated with
  `tranco.py --select-idb data/scale/results --out stageB.csv`.
