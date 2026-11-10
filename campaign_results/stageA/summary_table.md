# Stage A — Tranco Top 10k × Foxhound dynamic taint analysis

Progress: **569/10000** terminal (568 done, 1 failed) · running/pending: 9431

Run: foxhound · iterations=1 (leak pass — §4.1 identity confirmation deferred to Stage B) · workers=2 · --max-cpu 50 (CPU governor) · --prune-raw · headless · last sync 2026-11-10T14:48:55+00:00

| metric | total |
|---|---:|
| taint flows | 125104 |
| storage exfils | 120029 |
| IndexedDB databases | 416 |
| IndexedDB records | 974 |
| exfil events | 3018 |
| idb-hook flows | 608 |
| §4.1 confirmed identities (Stage B only) | 0 |

Top sites by taint flows:

| site | taint flows |
|---|---:|
| php.net | 35583 |
| capcut.com | 3480 |
| afternic.com | 2123 |
| gamepass.com | 1871 |
| adobe.net | 1840 |
| adobe.com | 1621 |
| xboxlive.com | 1435 |
| salesforce.com | 1386 |
| dropbox.com | 1384 |
| npr.org | 1371 |
| avast.com | 1358 |
| force.com | 1335 |
| arubanetworks.com | 1333 |
| aliyun.com | 1327 |
| sohu.com | 1265 |

Sites with IndexedDB records (mission scope):

| site | IDB records |
|---|---:|
| dropbox.com | 140 |
| speedtest.net | 136 |
| pinterest.com | 88 |
| businessinsider.com | 75 |
| cnn.com | 66 |
| washingtonpost.com | 60 |
| tiktok.com | 59 |
| aol.com | 38 |
| atlassian.net | 35 |
| issuu.com | 34 |
| globo.com | 24 |
| bbc.com | 24 |
| netangels.ru | 14 |
| mts.ru | 14 |
| medium.com | 14 |

Failed sites (1): youtube.com

Full per-site counts: `site_results.csv` · job store: `store_stageA.jsonl` (resumable) · per-site reports (IDB-active sites): `reports/` · aggregate: `bulk_stageA.html` (every 1000 completions).

Stage B plan: `tranco.py --select-idb <results dir> --out stageB.csv` then `scale.py --list stageB.csv --iterations 2` for paper §4.1 identity confirmation.
