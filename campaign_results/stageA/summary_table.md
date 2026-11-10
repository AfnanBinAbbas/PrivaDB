# Stage A — Tranco Top 10k × Foxhound dynamic taint analysis

Progress: **1369/10000** terminal (1368 done, 1 failed) · running/pending: 8631

Run: foxhound · iterations=1 (leak pass — §4.1 identity confirmation deferred to Stage B) · workers=2 · --max-cpu 50 (CPU governor) · --prune-raw · headless · last sync 2026-11-10T18:19:55+00:00

| metric | total |
|---|---:|
| taint flows | 296470 |
| storage exfils | 328436 |
| IndexedDB databases | 1236 |
| IndexedDB records | 2427 |
| exfil events | 6162 |
| idb-hook flows | 1097 |
| §4.1 confirmed identities (Stage B only) | 0 |

Top sites by taint flows:

| site | taint flows |
|---|---:|
| php.net | 35583 |
| zillow.com | 14657 |
| sharethrough.com | 8574 |
| hostgator.com.br | 7160 |
| cdiscount.com | 5049 |
| zoho.com | 4466 |
| amap.com | 3636 |
| capcut.com | 3480 |
| blizzard.com | 3005 |
| ups.com | 2605 |
| siemens.com | 2448 |
| afternic.com | 2123 |
| vnexpress.net | 2102 |
| clarin.com | 1968 |
| gamepass.com | 1871 |

Sites with IndexedDB records (mission scope):

| site | IDB records |
|---|---:|
| theverge.com | 178 |
| hola.com | 170 |
| dropbox.com | 140 |
| speedtest.net | 136 |
| cnnbrasil.com.br | 98 |
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

Failed sites (1): youtube.com

Full per-site counts: `site_results.csv` · job store: `store_stageA.jsonl` (resumable) · per-site reports (IDB-active sites): `reports/` · aggregate: `bulk_stageA.html` (every 1000 completions).

Stage B plan: `tranco.py --select-idb <results dir> --out stageB.csv` then `scale.py --list stageB.csv --iterations 2` for paper §4.1 identity confirmation.
