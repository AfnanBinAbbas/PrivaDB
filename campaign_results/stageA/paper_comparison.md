# Paper comparison — PrivaDB vs *What Storage?* (IndexedDB context)

Generated: `2026-11-11T16:59:42+00:00` · regenerate: `venv/bin/python scripts/paper_comparison.py`

Paper: Zubair Ahmad, Samuele Casarin, Stefano Calzavara — *What Storage? An Empirical Analysis of Web Storage in the Wild* (Tranco Top 5k, Jalangi dynamic taint). Source: `References/What Storage An Empirical Analysis of.pdf` §IV.B + Tables II–IV.

## 0. Instrument differences (read before comparing)

| axis | paper | PrivaDB Stage A |
|---|---|---|
| list | Tranco Top 5k (2021-12-14) | Tranco Top 10k (current) |
| client | Puppeteer + Jalangi JS instrumentation | Foxhound (Firefox 137) taint + in-page flow hooks |
| render budget | 60 s | 8 s idle (IDLE_WAIT) |
| storage scope | localStorage/sessionStorage `getItem`/`setItem` flows | **IndexedDB** + all other stores (cookies, LS/SS, caches, SW) |
| flow unit | one taint flow | identifier-matched exfil event `(id, destination, location, url)` + dynamic flows |
| tracker lists | EasyList/EasyPrivacy script URL | Disconnect entity list + CNAME-cloaking checks |

Counts are therefore *framework-aligned* (same confinement/tracking/cross-site taxonomy), not 1:1 reproductions of the paper's taint-flow unit.

## A. Headline comparison (count level, all completed sites)

*Source: `data/scale/stageA_10k.jsonl` store summaries (4131/10000 sites done)*

| metric | paper (Top 5k) | PrivaDB (Top 10k, 4131 done) |
|---|---:|---:|
| sites with usable data | 3324 (66.5% of 5k) | 4131 (41.3% of 10k, in progress) |
| sites with storage/IDB activity | 837 (25%) LS/SS | 1974 (47.8%) other-store exfil · **442 (10.7%) IndexedDB** |
| total flows (paper unit ≈ our exfil events) | 3207 filtered | 13,754 exfil events + 806,142 storage exfils |
| dynamic (taint) flows | n/a (their taint IS the flow) | 690,602 taint + 2,775 idb_hook |
| §4.1 confirmed IDB client identifiers | n/a (not in paper) | 0 (Stage B pending) |

## B. Classification tables (paper Tables II–IV equivalents)

*Source: `compute_paper_metrics` over 115 per-site analyses (grows as the campaign (re)produces them)*

| metric | paper | PrivaDB |
|---|---:|---:|
| total flows analysed | 3207 | 2772 |
| confidentiality (outflow) | 531 | 2656 |
| integrity (inflow) | 2676 | 116 |
| external | 1053 (33%) | 1850 (66.7%) |
| external = tracking | 78% | n/a% |
| cross-site (of external) | 84–98% of external (per class) | 82.1% |

## C. IndexedDB context — what the paper does NOT cover

*Source: store summaries (same as §A)*

| IDB metric | value |
|---|---:|
| sites using IndexedDB | 442 / 4131 (10.7%) |
| IDB databases observed | 2,815 |
| IDB records observed | 9,128 |
| candidate identifiers extracted | 34,314 |
| IDB→network exfil events | 13,754 on 122 sites |
| idb_hook provenance flows | 2,775 |
| §4.1 confirmed client identifiers | 0 (needs Stage B: 2 fresh profiles) |

The paper's sources/sinks table ends at `localStorage.getItem`/`setItem` — **no IndexedDB measurement exists in it**; these rows are PrivaDB's extension, instrument-validated at P/R 0.875/1.000 on the 28-flow ground truth (`evaluate_report.json`).

## D. Gaps before paper-grade completeness

1. **Campaign completion** — Stage A running (4131/10000); event tables in §B only cover analyses on disk.
2. **Re-crawl phase** — the 4,121 pre-campaign sites need re-crawling (store says `done` but analyses were lost to the run_scale rmtree bug) so Tables II–IV span the full Top-10k sample: build `missing.csv` from dead result_paths + a fresh store, run `scale.py --list missing.csv --db stageA_recrawl.jsonl …`.
3. **Stage B** — `iterations=2` over IDB-active sites for paper §4.1 client-identifier confirmation (`tranco.py --select-idb` → `scale.py --list stageB.csv --iterations 2`).
4. **Human labels** — two-annotator κ on a sample of exfil events (`export_labeling.py`/`score_labels.py`) for real-world precision (testbed P/R is not site precision).
5. **Render budget** — paper used 60 s; ours is 8 s. Late-loading trackers are under-sampled vs the paper.

