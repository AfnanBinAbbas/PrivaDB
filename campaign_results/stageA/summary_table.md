# Stage A — Tranco Top 10k × Foxhound dynamic taint analysis

Progress: **252/10000** terminal (251 done, 1 failed) · running/pending: 9748

Run: foxhound · iterations=1 (leak pass — §4.1 identity confirmation deferred to Stage B) · workers=2 · --max-cpu 50 (CPU governor) · --prune-raw · headless · last sync 2026-11-10T13:16:54+00:00

| metric | total |
|---|---:|
| taint flows | 30653 |
| storage exfils | 42108 |
| IndexedDB databases | 114 |
| IndexedDB records | 458 |
| exfil events | 791 |
| idb-hook flows | 243 |
| §4.1 confirmed identities (Stage B only) | 0 |

Top sites by taint flows:

| site | taint flows |
|---|---:|
| afternic.com | 2123 |
| adobe.com | 1621 |
| salesforce.com | 1386 |
| dropbox.com | 1384 |
| amplitude.com | 1079 |
| cisco.com | 1011 |
| meraki.com | 1001 |
| xiaomi.com | 920 |
| cnn.com | 901 |
| msn.com | 745 |
| bbc.com | 694 |
| tiktok.com | 690 |
| webex.com | 683 |
| bbc.co.uk | 571 |
| soundcloud.com | 565 |

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
| xiaomi.com | 11 |
| qq.com | 11 |
| sciencedirect.com | 6 |
| vimeo.com | 5 |
| sharepoint.com | 4 |
| spotify.com | 3 |
| unity3d.com | 2 |
| reddit.com | 2 |

Failed sites (1): youtube.com

Full per-site counts: `site_results.csv` · job store: `store_stageA.jsonl` (resumable) · per-site reports (IDB-active sites): `reports/` · aggregate: `bulk_stageA.html` (every 1000 completions).

Stage B plan: `tranco.py --select-idb <results dir> --out stageB.csv` then `scale.py --list stageB.csv --iterations 2` for paper §4.1 identity confirmation.
