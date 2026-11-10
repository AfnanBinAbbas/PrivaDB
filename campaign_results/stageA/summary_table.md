# Stage A — Tranco Top 10k × Foxhound dynamic taint analysis

Progress: **1210/10000** terminal (1209 done, 1 failed) · running/pending: 8790

Run: foxhound · iterations=1 (leak pass — §4.1 identity confirmation deferred to Stage B) · workers=2 · --max-cpu 50 (CPU governor) · --prune-raw · headless · last sync 2026-11-10T17:49:48+00:00

| metric | total |
|---|---:|
| taint flows | 270569 |
| storage exfils | 287911 |
| IndexedDB databases | 1122 |
| IndexedDB records | 2043 |
| exfil events | 5624 |
| idb-hook flows | 831 |
| §4.1 confirmed identities (Stage B only) | 0 |

Top sites by taint flows:

| site | taint flows |
|---|---:|
| php.net | 35583 |
| zillow.com | 14657 |
| sharethrough.com | 8574 |
| hostgator.com.br | 7160 |
| zoho.com | 4466 |
| amap.com | 3636 |
| capcut.com | 3480 |
| ups.com | 2605 |
| siemens.com | 2448 |
| afternic.com | 2123 |
| vnexpress.net | 2102 |
| clarin.com | 1968 |
| gamepass.com | 1871 |
| adobe.net | 1840 |
| battle.net | 1649 |

Sites with IndexedDB records (mission scope):

| site | IDB records |
|---|---:|
| theverge.com | 178 |
| dropbox.com | 140 |
| speedtest.net | 136 |
| pinterest.com | 88 |
| businessinsider.com | 75 |
| pinimg.com | 74 |
| clarin.com | 70 |
| cnn.com | 66 |
| accuweather.com | 65 |
| independent.co.uk | 63 |
| washingtonpost.com | 60 |
| lanacion.com.ar | 60 |
| tiktok.com | 59 |
| cricinfo.com | 42 |
| flightradar24.com | 39 |

Failed sites (1): youtube.com

Full per-site counts: `site_results.csv` · job store: `store_stageA.jsonl` (resumable) · per-site reports (IDB-active sites): `reports/` · aggregate: `bulk_stageA.html` (every 1000 completions).

Stage B plan: `tranco.py --select-idb <results dir> --out stageB.csv` then `scale.py --list stageB.csv --iterations 2` for paper §4.1 identity confirmation.
