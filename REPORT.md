# REPORT — PrivaDB full build-out (branch `buildout/full-plan`)

Scope: take PrivaDB from "claims taint tracking, does substring matching"
to a working, measured, verifiable IndexedDB-tracking measurement
platform, following the 11-phase research plan. All work is local on
branch `buildout/full-plan` (base: `3be2f58b`, tagged
`baseline-substring` at the Phase-0 commit `0130ca4d`).

## What was actually broken (verified, not assumed)

| # | Finding | Evidence | Fixed in |
|---|---|---|---|
| 1 | `test_cases.py` imported `config` (renamed `app_config` in `e6de403d`) — test harness crashed | `ModuleNotFoundError` | Phase 0 |
| 2 | README: venv activated at wrong path, `requirements.txt` path wrong, project tree stale, "Safe" label not computed by detector | file reads | Phase 0 |
| 3 | Docker backend crashed at boot: `uvicorn backend.server:app` couldn't import `policy_scanner` (backend dir not on `sys.path`) | import test | Phase 0 |
| 4 | `max_pages` accepted by `/scan`, silently ignored (always 3 iterations) | API test | Phase 0 |
| 5 | Backend bound `0.0.0.0:8000` with `CORS *` | code | Phase 0 |
| 6 | `.gitmodules` broken (`foxhound-engine` gitlink w/o mapping → `git submodule status` fatal; dead `submodules/foxhound` entry) | git error | Phase 0 |
| 7 | Dead `_check_string_value` (uuid/hex/base64 logic never called) | grep | Phase 0 (wired as classifier) |
| 8 | Flow hooks **dropped primitive IDB reads** (`get()` returning a string hit the object-only filter) | code + hook logs | Phase 1 |
| 9 | `caller()` stack parser Chrome-only → all `fn/loc` empty under Foxhound; wrapper frames (`proto[op]`, `debugger eval code`, `<anonymous>`) never skipped | raw crawl JSON | Phase 2 |
| 10 | Swapped `matched_url/matched_leaf` in inflow matcher | ground-truth fail G6 | Phase 2 |
| 11 | Foxhound sink labels carry suffixes (`XMLHttpRequest.open(url)`) → sink map missed them; several sinks unlisted | 348-event sink census | Phase 1 |
| 12 | `img.src` hook never performed the real image load → pixel requests **never sent** | evaluate FN on `/v/pixel` | Phase 7 |
| 13 | **Legacy changed-records filter**: any volatile record (timestamps) drops every static id with entropy ≤4.5 — production runs (3 iterations) always active → recall 1.0 → 0.167 | ablation row `diff=legacy(2it)` | Phase 7 (fixed filter; legacy kept measurable via `LEGACY_DIFF_FILTER`) |
| 14 | `other_storage` missing from combined crawl output → detector saw empty store | storage suite 0-capture | Phase 6 |
| 15 | Disconnect list schema mis-read (categories are lists) → 0 entities loaded | loader count | Phase 5 |
| 16 | `requests`/`beautifulsoup4`/`pyyaml` used but undeclared in requirements | grep | Phase 9 |
| 17 | Duplicate `httpx`/glued line in requirements | file read | Phase 0/9 |
| 18 | Hand-rolled page MD5 (two attempts) produced wrong digests — replaced with node-verified RFC1321 impl; Python-side vectors self-checked every evaluate run | node vs hashlib | Phase 7 |

## What was built (per phase — commits tell the story)

- **Phase 0** (`0130ca4d`, tag `baseline-substring`): bug fixes 1–7, unified event schema (`schema.py`), `run_meta` reproducibility block (engine/browser/playwright/python/platform/UA).
- **Phase 1** (`bf56cfcd`): hook fix 8, sink normalization 11, real `source_class` provenance, mechanism corroboration (substring ↔ taint/hook), ground-truth smoke page + runner — **Foxhound 8/8 → now 15/15**.
- **Phase 2** (`4f110c37`): write-side hooks (`put/add/cursor.update` with stack + `t_rel`), response capture, `analyze_idb_writes()` (writer 1P/3P attribution; inflow only when a written leaf appears in a captured response — replaces the heuristic guess, kept as tagged fallback), fixes 9–10 — **13/13**.
- **Phase 3** (`96d521fa`): `transforms.py` (11-variant expansion: raw/urlencode×2/base64±pad/hex/case/md5/sha1/sha256/lower+hash/JSON-escape/trunc16/32) matching URL, decoded URL, POST raw/JSON/form, **all** headers, WebSocket frames; dedup key `(id, destination, location, URL)` (old: one event per domain); scored identifier model; non-string IDB serialization; truncation reporting.
- **Phase 4** (`ddd82676`): `consent.py` (11 CMP selector families + text heuristics, explicit `banner_failed` state), 3-condition study in fresh contexts with pre/post IDB snapshots + click `t_rel`, `_analyze_consent()` per-condition exfil comparison — **12/12**, headline `third_party_exfils {accept:2, none:0, reject:2}`.
- **Phase 5** (`b7eb4378`): PSL same-party (`tldextract`, offline snapshot; fixes `.co.uk`/`.com.pk`; ports/IPs/localhost semantics), vendored Disconnect list (3,593+ domains → companies/categories), CNAME-cloaking classification (cached `dig`, `DNS_CNAME_CHECKS` toggle), entity attribution on every event.
- **Phase 6** (`ede2801a`): multi-store capture (localStorage/sessionStorage/cookies/caches/service workers per frame), same matching on every store → `storage_analysis.comparison` axis, **respawn detection** (cookie deleted → restored from IDB → `respawn_restored` flagged), cross-site **partition probe** (two top-level sites, same iframe) — both engines: NOT partitioned for this host pair.
- **Phase 7** (`70965060`): comprehensive ground-truth page (7 transforms × 5 sinks + benign controls + volatile record), declarative truth registry, `evaluate.py` with 3-method P/R + 8 ablations + run-to-run noise; fixes 12–13; labeling export/scoring tooling for human annotation (kappa).
- **Phase 8** (`76ae0ce6`): Tranco loader + vendored top-1000, dual-backend job store (SQLite when available — verified under system Python; JSONL fallback for this venv which lacks `_sqlite3`), `scale.py` parallel spawned workers + timeout + retries + implicit resume + single-threaded report pass — **7/7**.
- **Phase 9** (`12e9f339`): `disclosure.py` (structured storage/vendor/purpose extraction sharing the Disconnect vocabulary, whitespace-normalized, snapshot persistence), `gap.py` (received − disclosed companies, IndexedDB observed-but-undisclosed verdict, category→purpose gap), `POST /policy/gap`, fixture tests — **14/14 backend tests** incl. legacy.
- **Phase 10** (`e3026bc8`): SSRF guard (schemes, literals + DNS-resolved private/metadata; `PRIVADB_ALLOW_PRIVATE_TARGETS` lab override, metadata never allowed) live-verified on `/scan`; CI workflow (compileall + pytest + tsc + build); Docker `PRIVADB_HOST` fix; `requirements.lock.txt`; foxhound `BuildID` pin in `run_meta`.
- **Phase 11** (`c2fa6a0f`): `paper_report.py` → `PAPER_REPORT.md` (every figure traced to a JSON artifact), this report, `MANIFEST.md`.
- **Phase UID** (this commit): paper-faithful client-identifier detection — `uid.py` implements Ahmad et al. IJIS 2024 §4.1 (the Chen-et-al. heuristic the paper states was "originally proposed **for cookies**", adapted to **IndexedDB only**): C1 persistence (inherent), C2 same-session reload (new crawler reload pass, `UID_RELOAD_CHECK`), C3 length≥8, C4 same key on fresh-profile visits (≥2 iterations), C5 significantly-different values (timestamp strip → recursive LCS strip → Ratcliff–Obershelp <66%); confirmed vs candidate vs rejected verdicts stamped on IDB identifiers + exfil events (CSV column `client_identifier`); cookie/localStorage pools stay comparison-only and are never labelled client identifiers. **Ground truth: 3/3 checks** (per-profile `instance_uid` confirmed; static `tid` rejected). Driver fix: Playwright FF `pageError.location.*` unguarded-field crash (coreBundle.js) silently emptied all JS-based extraction on live sites — patched (6 refs, `scripts/patch_playwright_ff.py`, node-verified, backup kept); `context.close()` failures no longer discard collected crawls. Live measurement: 15 sites × 2 fresh profiles through Foxhound (14/15 done, YouTube timed out×2) — **0 confirmed IDB client identifiers** (correct: reddit `v2_event_boiler_plate` static sim=1.0 rejected, linkedin `sequenceNumber` ephemeral rejected, braze `attrib` sim=0.97 rejected) while **4,344 taint + 2,912 storage exfils** show IDs live in localStorage/cookies (out of the IDB-only scope). Tests: **26/26**.
- **Phase 12** (prior commit): HTML reporting — `grc.py` (14 evidence-driven checks across GDPR/ePrivacy/CCPA/ISO 27001 with risk scoring + framework rollups, header/policy collectors SSRF-guarded) and `report_html.py` (standalone single + bulk renderers: HTML5 semantics, skip-link, captioned/scope tables, print CSS, zero JS, hash-only values, provenance + disclaimer); auto-generated after each scan, `GET /scan/{id}/report`, `GET /reports`, `GET /reports/bulk[?live=1]`; scale writes per-site + bulk HTML; dashboard links added; tests: 19/19 backend.

## Headline measurements (details: PAPER_REPORT.md)

Method comparison on 12 ground-truth flows + 2 benign controls:

| method | precision | recall |
|---|---:|---:|
| substring baseline (pre-Phase-3) | 0.714 | 0.417 |
| **transforms (full pipeline)** | **0.857** | **1.000** |
| dynamic (taint + hooks) | 0.706 | 0.500 |

- The 2 remaining FP are exactly the benign controls (CSRF/version) — the honest cost of a length-gated identifier model; `ID_SCORE_THRESHOLD=0.5` removes one at no recall cost (0.923/1.000).
- Legacy diff filter: recall **1.000 → 0.167**; fixed filter holds 1.000.
- Consent study: reject-conditions still exfiltrate (2 third-party flows) and pre-consent writes occur (3) → `tracking_without_consent: true`.
- Respawn: 1 candidate (`respawn_restored` cookie regenerated from IDB after deletion).
- Partition probe: both engines expose iframe localStorage across top-level sites for the measured host pair.
- Variance: [14,14,14], σ=0.

## Deliberately NOT done (needs a human)

1. **License**: still proprietary. Open-s relicensing is the copyright holder's decision — not changed.
2. **Real-site human labels**: tooling ready (`export_labeling.py`/`score_labels.py`); two annotators must produce the files.
3. **Docker build verification**: authoring host lacks docker-group/sudo; run the command in MANIFEST.md.
4. **Tranco top-N production run**: infrastructure ready (`scale.py`); the large crawl is an operator decision (runtime/ethics).

## Reproduce

See `PAPER_REPORT.md` §9 and `MANIFEST.md`.
