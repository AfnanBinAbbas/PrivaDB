# Pilot results — 15 live sites via Foxhound dynamic taint analysis

Generated: 2026-11-10 · engine: foxhound · iterations=2 (fresh profile per iteration, paper §4.1) · driver patch applied (scripts/patch_playwright_ff.py)

| # | site | IDB dbs | IDB recs | iters | §4.1 confirmed IDs | taint flows | idb-hook flows | storage exfils | exfil events |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | www.billabong.com | 5 | 0 | 2 | **0** | 3052 | 0 | 1113 | 0 |
| 2 | www.braze.com | 6 | 4 | 2 | **0** | 550 | 151 | 3610 | 266 |
| 3 | firearmsdepot.com | 0 | 0 | 2 | **0** | 234 | 0 | 690 | 0 |
| 4 | www.netflix.com | 0 | 0 | 2 | **0** | 196 | 0 | 31 | 0 |
| 5 | www.twitch.tv | 0 | 0 | 2 | **0** | 187 | 0 | 44 | 0 |
| 6 | www.reddit.com | 1 | 2 | 2 | **0** | 176 | 0 | 108 | 0 |
| 7 | www.linkedin.com | 1 | 1 | 2 | **0** | 170 | 0 | 85 | 0 |
| 8 | omtechlaser.com | 5 | 0 | 2 | **0** | 154 | 0 | 541 | 0 |
| 9 | calculojuridico.com.br | 0 | 0 | 2 | **0** | 117 | 0 | 214 | 0 |
| 10 | www.instagram.com | 0 | 0 | 2 | **0** | 17 | 0 | 24 | 0 |
| 11 | x.com | 0 | 0 | 2 | **0** | 16 | 0 | 38 | 0 |
| 12 | www.facebook.com | 0 | 0 | 2 | **0** | 11 | 0 | 13 | 0 |
| 13 | www.wikipedia.org | 0 | 0 | 2 | **0** | 8 | 0 | 7 | 0 |
| 14 | www.amazon.com | 0 | 0 | 2 | **0** | 6 | 0 | 1 | 0 |
| 15 | chem25.aparsclassroom.com | 0 | 0 | 2 | **0** | 0 | 0 | 0 | 0 |

**Totals (14/15 completed — youtube.com timed out ×2):** taint flows=4894, storage exfils=6519, IDB databases=18, IDB records=7, §4.1-confirmed IndexedDB identities=0.

**Reading:** these sites leak identifiers mainly through localStorage/cookies (storage exfils) — the IndexedDB column is the scope of this project, and §4.1 found 0 confirmed identities on landing views (correct rejections: static/ephemeral values fail C5/C2; billabong/omtechlaser open IDB stores that are empty pre-interaction). Per-site reports with raw leaked values + source/sink: `reports/` (sensitive — contains the operator's own measured tracker identifiers).

Reproduce: `scale.py --urls <15 sites> --engine foxhound --workers 2 --iterations 2 --timeout 240 --attempts 2 --db data/scale/live15c.sqlite` (plus Stage-A governor flags `--max-cpu 50 --prune-raw` for the 10k campaign).
