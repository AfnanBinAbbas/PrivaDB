# Stage A — Tranco Top 10k × Foxhound dynamic taint analysis

Progress: **4134/10000** terminal (4133 done, 1 failed) · running/pending: 5866

Run: foxhound · iterations=1 (leak pass — §4.1 identity confirmation deferred to Stage B) · workers=2 · --max-cpu 70 (CPU governor) · --prune-raw · headless · last sync 2026-11-11T19:00:33+00:00

| metric | total |
|---|---:|
| taint flows | 690652 |
| storage exfils | 806172 |
| IndexedDB databases | 2813 |
| IndexedDB records | 9233 |
| exfil events | 13754 |
| idb-hook flows | 2775 |
| §4.1 confirmed identities (Stage B only) | 0 |

Top sites by taint flows:

| site | taint flows |
|---|---:|
| php.net | 35583 |
| dola.com | 15112 |
| doubao.com | 14694 |
| zillow.com | 14657 |
| sharethrough.com | 8574 |
| posthog.com | 8481 |
| zoho.eu | 8434 |
| hostgator.com.br | 7160 |
| norton.com | 6599 |
| cdiscount.com | 5049 |
| clickup.com | 4910 |
| idealo.de | 4720 |
| zoho.com | 4466 |
| kahoot.it | 4316 |
| iqiyi.com | 4309 |

Sites with IndexedDB records (mission scope):

| site | IDB records |
|---|---:|
| mastodon.social | 3967 |
| netscape.com | 258 |
| dropbox.com | 187 |
| theverge.com | 178 |
| cronista.com | 177 |
| hola.com | 170 |
| speedtest.net | 136 |
| globalnews.ca | 126 |
| newscientist.com | 120 |
| ria.ru | 100 |
| cnnbrasil.com.br | 98 |
| rian.ru | 96 |
| vice.com | 88 |
| qq.com | 86 |
| tomshardware.com | 84 |

Failed sites (1): youtube.com

Full per-site counts: `site_results.csv` · job store: `store_stageA.jsonl` (resumable) · per-site reports (IDB-active sites): `reports/` · aggregate: `bulk_stageA.html` (every 1000 completions).

Stage B plan: `tranco.py --select-idb <results dir> --out stageB.csv` then `scale.py --list stageB.csv --iterations 2` for paper §4.1 identity confirmation.
