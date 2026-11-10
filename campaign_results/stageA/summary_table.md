# Stage A — Tranco Top 10k × Foxhound dynamic taint analysis

Progress: **359/10000** terminal (358 done, 1 failed) · running/pending: 9641

Run: foxhound · iterations=1 (leak pass — §4.1 identity confirmation deferred to Stage B) · workers=2 · --max-cpu 50 (CPU governor) · --prune-raw · headless · last sync 2026-11-10T13:47:47+00:00

| metric | total |
|---|---:|
| taint flows | 86359 |
| storage exfils | 76179 |
| IndexedDB databases | 165 |
| IndexedDB records | 508 |
| exfil events | 1430 |
| idb-hook flows | 251 |
| §4.1 confirmed identities (Stage B only) | 0 |

Top sites by taint flows:

| site | taint flows |
|---|---:|
| php.net | 35583 |
| afternic.com | 2123 |
| gamepass.com | 1871 |
| adobe.com | 1621 |
| salesforce.com | 1386 |
| dropbox.com | 1384 |
| avast.com | 1358 |
| arubanetworks.com | 1333 |
| alidns.com | 1250 |
| amplitude.com | 1079 |
| cisco.com | 1011 |
| meraki.com | 1001 |
| xiaomi.com | 920 |
| branch.io | 908 |
| cnn.com | 901 |

Sites with IndexedDB records (mission scope):

| site | IDB records |
|---|---:|
| dropbox.com | 140 |
| pinterest.com | 88 |
| cnn.com | 66 |
| tiktok.com | 59 |
| bbc.com | 24 |
| mts.ru | 14 |
| medium.com | 14 |
| launchdarkly.com | 12 |
| xiaomi.com | 11 |
| qq.com | 11 |
| linktr.ee | 9 |
| canva.com | 9 |
| datadoghq.com | 8 |
| sciencedirect.com | 6 |
| ok.ru | 6 |

Failed sites (1): youtube.com

Full per-site counts: `site_results.csv` · job store: `store_stageA.jsonl` (resumable) · per-site reports (IDB-active sites): `reports/` · aggregate: `bulk_stageA.html` (every 1000 completions).

Stage B plan: `tranco.py --select-idb <results dir> --out stageB.csv` then `scale.py --list stageB.csv --iterations 2` for paper §4.1 identity confirmation.
