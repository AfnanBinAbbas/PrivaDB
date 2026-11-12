# Stage A — Tranco Top 10k × Foxhound dynamic taint analysis

Progress: **6818/10000** terminal (6782 done, 36 failed) · running/pending: 3182

Run: foxhound · iterations=1 (leak pass — §4.1 identity confirmation deferred to Stage B) · workers=2 · --max-cpu 70 (CPU governor) · --prune-raw · headless · last sync 2026-11-12T07:05:37+00:00

| metric | total |
|---|---:|
| taint flows | 1241851 |
| storage exfils | 1466047 |
| IndexedDB databases | 5413 |
| IndexedDB records | 15790 |
| exfil events | 23089 |
| idb-hook flows | 7728 |
| §4.1 confirmed identities (Stage B only) | 0 |

Top sites by taint flows:

| site | taint flows |
|---|---:|
| php.net | 35583 |
| irctc.co.in | 26500 |
| dola.com | 15112 |
| doubao.com | 14694 |
| canadiantire.ca | 14681 |
| zillow.com | 14657 |
| vivo.com.br | 11497 |
| work.ua | 10991 |
| tomsguide.com | 10755 |
| searchenginejournal.com | 9999 |
| sharethrough.com | 8574 |
| posthog.com | 8481 |
| zoho.eu | 8434 |
| hostgator.com.br | 7160 |
| iqiyipic.com | 6871 |

Sites with IndexedDB records (mission scope):

| site | IDB records |
|---|---:|
| mastodon.social | 3967 |
| newrepublic.com | 432 |
| netscape.com | 258 |
| sprig.com | 255 |
| kooora.com | 230 |
| sbnation.com | 225 |
| washingtontimes.com | 221 |
| getdropbox.com | 207 |
| bell-labs.com | 193 |
| dropbox.com | 187 |
| popsci.com | 180 |
| theverge.com | 178 |
| cronista.com | 177 |
| hola.com | 170 |
| tn.com.ar | 168 |

Failed sites (36): youtube.com, taobao.com, comcast.com, character.ai, tagesschau.de, ovhcloud.com, nu.nl, ovh.com, cam.ac.uk, mechacomic.jp, thscore99.com, xfinity.com, hostinger.com, customer.io, coinmarketcap.com, adguard.com, faz.net, sketchfab.com, cutt.ly, irishtimes.com, simplisafe.com, vtex.com, franceinfo.fr, bybit.com, ardmediathek.de…

Full per-site counts: `site_results.csv` · job store: `store_stageA.jsonl` (resumable) · per-site reports (IDB-active sites): `reports/` · aggregate: `bulk_stageA.html` (every 1000 completions).

Stage B plan: `tranco.py --select-idb <results dir> --out stageB.csv` then `scale.py --list stageB.csv --iterations 2` for paper §4.1 identity confirmation.
