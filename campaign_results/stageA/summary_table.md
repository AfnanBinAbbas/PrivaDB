# Stage A — Tranco Top 10k × Foxhound dynamic taint analysis

Progress: **126/10000** terminal (125 done, 1 failed) · running/pending: 9874

Run: foxhound · iterations=1 (leak pass — §4.1 identity confirmation deferred to Stage B) · workers=2 · --max-cpu 50 (CPU governor) · --prune-raw · headless · last sync 2026-11-10T12:46:43+00:00

| metric | total |
|---|---:|
| taint flows | 14520 |
| storage exfils | 19003 |
| IndexedDB databases | 39 |
| IndexedDB records | 318 |
| exfil events | 563 |
| idb-hook flows | 212 |
| §4.1 confirmed identities (Stage B only) | 0 |

Top sites by taint flows:

| site | taint flows |
|---|---:|
| adobe.com | 1621 |
| dropbox.com | 1384 |
| msn.com | 745 |
| tiktok.com | 690 |
| webex.com | 683 |
| adobe.io | 547 |
| intuit.com | 537 |
| sharepoint.com | 535 |
| digicert.com | 521 |
| samsung.com | 508 |
| amazonvideo.com | 505 |
| amazonaws.com | 472 |
| azure.com | 468 |
| nginx.com | 432 |
| f5.com | 414 |

Sites with IndexedDB records (mission scope):

| site | IDB records |
|---|---:|
| dropbox.com | 140 |
| pinterest.com | 88 |
| tiktok.com | 59 |
| qq.com | 11 |
| vimeo.com | 5 |
| sharepoint.com | 4 |
| spotify.com | 3 |
| reddit.com | 2 |
| linkedin.com | 2 |
| amazonvideo.com | 2 |
| nginx.com | 1 |
| f5.com | 1 |

Failed sites (1): youtube.com

Full per-site counts: `site_results.csv` · job store: `store_stageA.jsonl` (resumable) · per-site reports (IDB-active sites): `reports/` · aggregate: `bulk_stageA.html` (every 1000 completions).

Stage B plan: `tranco.py --select-idb <results dir> --out stageB.csv` then `scale.py --list stageB.csv --iterations 2` for paper §4.1 identity confirmation.
