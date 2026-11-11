# Stage A — Tranco Top 10k × Foxhound dynamic taint analysis

Progress: **2979/10000** terminal (2978 done, 1 failed) · running/pending: 7021

Run: foxhound · iterations=1 (leak pass — §4.1 identity confirmation deferred to Stage B) · workers=2 · --max-cpu 50 (CPU governor) · --prune-raw · headless · last sync 2026-11-11T01:23:35+00:00

| metric | total |
|---|---:|
| taint flows | 510118 |
| storage exfils | 599039 |
| IndexedDB databases | 2143 |
| IndexedDB records | 8128 |
| exfil events | 10356 |
| idb-hook flows | 2173 |
| §4.1 confirmed identities (Stage B only) | 0 |

Top sites by taint flows:

| site | taint flows |
|---|---:|
| php.net | 35583 |
| doubao.com | 14694 |
| zillow.com | 14657 |
| sharethrough.com | 8574 |
| posthog.com | 8481 |
| hostgator.com.br | 7160 |
| norton.com | 6599 |
| cdiscount.com | 5049 |
| clickup.com | 4910 |
| idealo.de | 4720 |
| zoho.com | 4466 |
| iqiyi.com | 4309 |
| amap.com | 3636 |
| capcut.com | 3480 |
| blizzard.com | 3005 |

Sites with IndexedDB records (mission scope):

| site | IDB records |
|---|---:|
| mastodon.social | 3967 |
| netscape.com | 258 |
| theverge.com | 178 |
| cronista.com | 177 |
| hola.com | 170 |
| dropbox.com | 140 |
| speedtest.net | 136 |
| newscientist.com | 120 |
| ria.ru | 100 |
| cnnbrasil.com.br | 98 |
| vice.com | 88 |
| pinterest.com | 88 |
| index.hr | 78 |
| businessinsider.com | 75 |
| pinimg.com | 74 |

Failed sites (1): youtube.com

Full per-site counts: `site_results.csv` · job store: `store_stageA.jsonl` (resumable) · per-site reports (IDB-active sites): `reports/` · aggregate: `bulk_stageA.html` (every 1000 completions).

Stage B plan: `tranco.py --select-idb <results dir> --out stageB.csv` then `scale.py --list stageB.csv --iterations 2` for paper §4.1 identity confirmation.
