# Stage A — Tranco Top 10k × Foxhound dynamic taint analysis

Progress: **2169/10000** terminal (2168 done, 1 failed) · running/pending: 7831

Run: foxhound · iterations=1 (leak pass — §4.1 identity confirmation deferred to Stage B) · workers=2 · --max-cpu 50 (CPU governor) · --prune-raw · headless · last sync 2026-11-10T21:20:38+00:00

| metric | total |
|---|---:|
| taint flows | 401680 |
| storage exfils | 487472 |
| IndexedDB databases | 1803 |
| IndexedDB records | 3385 |
| exfil events | 8955 |
| idb-hook flows | 1669 |
| §4.1 confirmed identities (Stage B only) | 0 |

Top sites by taint flows:

| site | taint flows |
|---|---:|
| php.net | 35583 |
| zillow.com | 14657 |
| sharethrough.com | 8574 |
| posthog.com | 8481 |
| hostgator.com.br | 7160 |
| norton.com | 6599 |
| cdiscount.com | 5049 |
| zoho.com | 4466 |
| iqiyi.com | 4309 |
| amap.com | 3636 |
| capcut.com | 3480 |
| blizzard.com | 3005 |
| ups.com | 2605 |
| akamai.com | 2599 |
| betika.com | 2510 |

Sites with IndexedDB records (mission scope):

| site | IDB records |
|---|---:|
| theverge.com | 178 |
| cronista.com | 177 |
| hola.com | 170 |
| dropbox.com | 140 |
| speedtest.net | 136 |
| cnnbrasil.com.br | 98 |
| vice.com | 88 |
| pinterest.com | 88 |
| index.hr | 78 |
| businessinsider.com | 75 |
| pinimg.com | 74 |
| clarin.com | 70 |
| cnn.com | 66 |
| accuweather.com | 65 |
| sapo.pt | 64 |

Failed sites (1): youtube.com

Full per-site counts: `site_results.csv` · job store: `store_stageA.jsonl` (resumable) · per-site reports (IDB-active sites): `reports/` · aggregate: `bulk_stageA.html` (every 1000 completions).

Stage B plan: `tranco.py --select-idb <results dir> --out stageB.csv` then `scale.py --list stageB.csv --iterations 2` for paper §4.1 identity confirmation.
