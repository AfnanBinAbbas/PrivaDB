# PrivaDB — Measurement Report (generated)

Generated: `2026-11-10T10:04:38+00:00` · generator: `Web/src/engine/paper_report.py`

Every figure below is read from the JSON artifacts produced by the testbed suites and detector runs; the source file is named in each section.

## 0. Provenance (run_meta)

*Source: newest crawl's `run_meta`*

- **source**: `results/Foxhound/crawled/localhost:18765.json`
- **engine**: `foxhound`
- **browser_version**: `137.0`
- **foxhound_build_id**: `20251126175156`
- **playwright_version**: `1.62.0`
- **python_version**: `3.12.7`
- **platform**: `Linux-7.1.5+kali-amd64-x86_64-with-glibc2.43`
- **user_agent**: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`
- **captured_at**: `2026-11-10T10:04:27.645157Z`

## 1. Headline metrics (site-level)

*Source: `results/<engine>/analysis/summary.json`*

- **chrome**: 1 site analyses — 0 (0.0%) with IndexedDB data; 0 with exfiltration flows; 0 sending identifiers to third parties; 0 dynamic (taint/hook) flows total
- **foxhound**: 1 site analyses — 1 (100.0%) with IndexedDB data; 1 with exfiltration flows; 0 sending identifiers to third parties; 892 dynamic (taint/hook) flows total

## 2. Method comparison — the core contribution

*Source: `testbed/evaluate_report.json`*

Ground truth: **12 must-detect flows**, **2 benign controls** (testbed/pages/transforms.html).

| method | predicted | TP | FP | FN | precision | recall |
|---|---:|---:|---:|---:|---:|---:|
| substring (baseline) | 7 | 5 | 2 | 7 | 0.714 | 0.417 |
| transforms (full) | 14 | 12 | 2 | 0 | 0.857 | 1.000 |
| dynamic (taint+hooks) | 17 | 12 | 5 | 6 | 0.706 | 0.500 |

Ablations:

| variant | predicted | FP | FN | precision | recall |
|---|---:|---:|---:|---:|---:|
| ID_SCORE_THRESHOLD=0.0 | 14 | 2 | 0 | 0.857 | 1.000 |
| ID_SCORE_THRESHOLD=0.5 | 13 | 1 | 0 | 0.923 | 1.000 |
| ID_SCORE_THRESHOLD=0.7 | 1 | 0 | 11 | 1.000 | 0.083 |
| MIN_ID_LENGTH=4 | 14 | 2 | 0 | 0.857 | 1.000 |
| MIN_ID_LENGTH=8 | 14 | 2 | 0 | 0.857 | 1.000 |
| MIN_ID_LENGTH=12 | 14 | 2 | 0 | 0.857 | 1.000 |
| diff=off(1it) | 14 | 2 | 0 | 0.857 | 1.000 |
| diff=fixed(2it) | 14 | 2 | 0 | 0.857 | 1.000 |
| diff=legacy(2it) | 2 | 0 | 10 | 1.000 | 0.167 |

Run-to-run noise: counts=[14, 14, 14] mean=14.0 σ=0.0

## 3. Consent state (tracking without consent)

*Source: `testbed/consent_report.json`*

Banner detected: **True** · pre-consent writes: **3** · post-reject writes: **1** · tracking-without-consent: **True**

| condition | 3rd-party exfils | writes | pre-click |
|---|---:|---:|---:|
| accept | 2 | 2 | 1 |
| none | 0 | 1 | 1 |
| reject | 2 | 2 | 1 |

Banner failures surfaced (never silently downgraded): []

## 4. Storage comparison (IDB vs everything else)

*Source: `testbed/storage_report.json`*

| store | identifiers | exfil events | third-party |
|---|---:|---:|---:|
| caches | 0 | 0 | 0 |
| cookies | 1 | 0 | 0 |
| indexeddb | 2 | 0 | 0 |
| localStorage | 1 | 1 | 1 |
| service_workers | 0 | 0 | 0 |
| sessionStorage | 2 | 0 | 0 |

Respawn candidates (value present in cookie ∩ IDB): **1** — [['respawn_restored']]

## 5. Cross-site storage partitioning (per engine)

*Source: `testbed/partition_report_<engine>.json`*

- **chrome**: NOT partitioned — iframe localStorage visible across different top-level sites (cross-site tracking vector)
- **foxhound**: NOT partitioned — iframe localStorage visible across different top-level sites (cross-site tracking vector)

## 6. Scale readiness

*Source: `testbed/scale_report.json`*

Batch verification: **7/7** checks · store backend: `jsonl` · final counts: {'done': 4}

## 7. Ground-truth suite status

*Source: `testbed/smoke_report.json`*

Ground-truth smoke suite: **15/15** checks passed (engine=foxhound)

## 8. Limitations

- **Automation fingerprint.** Sites may serve different content to Playwright-driven browsers (bot detection); headless-vs-headed effects are not quantified.
- **Single vantage point.** All measurements ran from one host/region; regional (GDPR vs non-GDPR) comparisons require repeat runs from tagged vantage points.
- **HttpOnly cookies are invisible** to in-page capture (document.cookie) — cookie-side numbers are lower bounds.
- **IDB is a taint blackout** in Foxhound (reads are not taint sources); IDB→network provenance therefore comes from the in-page hook layer, whose matching is substring-based unless the transform matcher corroborates it.
- **Real-site precision is pending human labels.** Automatic ground truth covers the testbed only; real-site flows are exported via `testbed/export_labeling.py` for two-annotator scoring (`testbed/score_labels.py`, Cohen's κ).
- **Docker images were not build-verified on the authoring host** (no docker-group access); Dockerfiles carry fixes (sys.path, PRIVADB_HOST, pinned requirements) but need a `docker build` run by a privileged user.
- **License.** The repository is currently proprietary; an open license for the paper artifact is an owner decision and has NOT been changed by this work.

## 9. Reproducing

```bash
cd Web/src/engine
python testbed/run_smoke.py --engine foxhound
python testbed/run_consent.py --engine foxhound
python testbed/run_storage.py --engine chrome --headless
python testbed/run_partition.py --engine chrome --headless
python testbed/run_scale.py --engine chrome --headed
python testbed/evaluate.py --engine foxhound
python paper_report.py --out ../../PAPER_REPORT.md
```
