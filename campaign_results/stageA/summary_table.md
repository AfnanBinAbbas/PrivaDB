# Stage A — Tranco Top 10k × Foxhound dynamic taint analysis

Progress: **1083/10000** terminal (1082 done, 1 failed) · running/pending: 8917

Run: foxhound · iterations=1 (leak pass — §4.1 identity confirmation deferred to Stage B) · workers=2 · --max-cpu 50 (CPU governor) · --prune-raw · headless · last sync 2026-11-10T17:19:32+00:00

| metric | total |
|---|---:|
| taint flows | 243676 |
| storage exfils | 253697 |
| IndexedDB databases | 979 |
| IndexedDB records | 1775 |
| exfil events | 5240 |
| idb-hook flows | 820 |
| §4.1 confirmed identities (Stage B only) | 0 |

Top sites by taint flows:

| site | taint flows |
|---|---:|
| php.net | 35583 |
| zillow.com | 14657 |
| sharethrough.com | 8574 |
| hostgator.com.br | 7160 |
| zoho.com | 4466 |
| capcut.com | 3480 |
| ups.com | 2605 |
| afternic.com | 2123 |
| gamepass.com | 1871 |
| adobe.net | 1840 |
| adobe.com | 1621 |
| theverge.com | 1495 |
| imgur.com | 1444 |
| xboxlive.com | 1435 |
| biblegateway.com | 1393 |

Sites with IndexedDB records (mission scope):

| site | IDB records |
|---|---:|
| theverge.com | 178 |
| dropbox.com | 140 |
| speedtest.net | 136 |
| pinterest.com | 88 |
| businessinsider.com | 75 |
| pinimg.com | 74 |
| cnn.com | 66 |
| accuweather.com | 65 |
| independent.co.uk | 63 |
| washingtonpost.com | 60 |
| tiktok.com | 59 |
| flightradar24.com | 39 |
| aol.com | 38 |
| biblegateway.com | 35 |
| atlassian.net | 35 |

Failed sites (1): youtube.com

Full per-site counts: `site_results.csv` · job store: `store_stageA.jsonl` (resumable) · per-site reports (IDB-active sites): `reports/` · aggregate: `bulk_stageA.html` (every 1000 completions).

Stage B plan: `tranco.py --select-idb <results dir> --out stageB.csv` then `scale.py --list stageB.csv --iterations 2` for paper §4.1 identity confirmation.
