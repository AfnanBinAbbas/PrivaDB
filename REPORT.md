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
- **Phase 12** (prior commit): HTML reporting — `grc.py` (14 evidence-driven checks across GDPR/ePrivacy/CCPA/ISO 27001 with risk scoring + framework rollups, header/policy collectors SSRF-guarded) and `report_html.py` (standalone single + bulk renderers: HTML5 semantics, skip-link, captioned/scope tables, print CSS, zero JS, provenance + disclaimer; report-template fix: per-site reports now show **raw leaked values (clipped) + hash in a unified Direction/Source/Leaked-value/Sink table** across all five mechanisms incl. inflow, marked sensitive — bulk stays aggregates-only); auto-generated after each scan, `GET /scan/{id}/report`, `GET /reports`, `GET /reports/bulk[?live=1]`; scale writes per-site + bulk HTML; dashboard links added; tests: 19/19 backend.

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

## Phase 13 — worker-context hook closure (the IndexedDB caveat)

Scope (approved plan): close the hook-layer blind spots for Web Workers /
SharedWorkers while holding taint + window hooks constant, ground-truth
the new coverage, and report before/after per mechanism — all runs
headless (`--headless`), branch `buildout/full-plan`.

### Verified first (3 probes, headless Foxhound; `logs/03`–`05`, `raw/03–05`)

| question | verdict |
|---|---|
| route sees dedicated-worker script fetch + prelude runs (Q1/Q3a/Q18) | **yes** |
| route sees SharedWorker script (Q9) / ServiceWorker registration (Q2) | **no / no** |
| blob-URL worker + importScripts(abs) works: dedicated + shared (Q14/Q15/Q16) | **yes** |
| BroadcastChannel worker/shared/SW → page (Q5/Q5b/Q13) | **yes** |
| blob:-URL service-worker registration | **rejected** (scheme must be http/https, probe2 Q11) |
| network visibility: dedicated-worker fetch (Q4) / shared fetch (Q17) / SW fetch | **yes / no / no** |
| `navigator.sendBeacon` in worker scope (step 16) | **undefined** in Firefox workers |

### Built

- `HOOK_CORE_EXPR` (crawler.py): one wrap core for window/dedicated/
  shared/service contexts — IDB read+write wraps, fetch/XHR/beacon/img,
  token-filtered BroadcastChannel relay, per-frame token, non-enumerable
  `__prividb_hooks` (defineProperty), `__tamper_check()` refs.
- Injection: route prelude on `__privadb_tok=` marked URLs (dedicated),
  blob bootstrap `core + importScripts(abs)` (SharedWorker; constructor
  identity preserved via per-URL blob cache), SW `register()` tagging +
  per-crawl gap accounting.
- `detector.synthesize_network_from_hooks()`: hook-only sends (invisible
  to Playwright for shared/SW/dedicated-XHR) become network entries
  tagged `synthetic=true`; `idb_hook` flows carry a `context` field.
- Ground truth: `pages/idb_workers.html` + `wk.js` / `wk-shared.js` /
  `wk-sw.js`; `ground_truth.WORKER_FLOWS` = 16 scored flows (11
  transforms + sink diversity from the dedicated worker, raw+b64 from
  shared, one window flow) + 2 SW flows kept **unscored** (sink-proven).
- `evaluate.py`: dual-page crawl, per-page + union method tables,
  `--no-worker-injection` (true BEFORE: window hooks+taint on), per-
  mechanism breakdown, 7 worker-coverage checks, sink-log persistence
  for `--skip-crawl`. Config switches: `FLOW_HOOKS_ENABLED`,
  `FLOW_WORKER_INJECTION_ENABLED` (both default on).

### Before → AFTER (headless; `logs/11`, `logs/17`, `logs/18`, `raw/11`, `raw/17`)

| page · method | BEFORE p/r | AFTER p/r | Δrecall |
|---|---|---|---|
| transforms · substring | 0.714/0.417 | 0.714/0.417 | +0.000 |
| transforms · transforms | 0.857/1.000 | 0.857/1.000 | +0.000 |
| transforms · dynamic | 0.706/0.500 | 0.706/0.500 | +0.000 |
| **workers · transforms** | 0.857/0.750 | **0.889/1.000** | **+0.250** |
| **workers · dynamic** | 1.000/0.062 | **0.875/0.438** | **+0.375** |
| union · transforms | 0.857/0.857 | **0.875/1.000** | +0.143 |
| union · dynamic | 0.722/0.250 | **0.788/0.464** | +0.214 |

- Worker-page `idb_hook` events: **1 → 16**; flows corroborated by >1
  mechanism: **7 → 13** (union); transforms-page numbers reproduce the
  Phase-7 baseline exactly (zero regression) and variance stays σ=0.
- Coverage: **7/7 PASS** (route_injections=2, dedicated+shared hellos,
  only gap = SW, no tampering, synth=3 contexts [dedicated, shared], SW
  sink proof); UID **3/3**; `exit=0` (`logs/17`).
- Remaining dynamic FNs are transformed-only URLs (raw-needle matching
  by design) — the transforms method covers them (union FN = 0).

### Regressions after the refactor (all headless; `logs/07`–`09`, `19`–`20`)

smoke **15/15** · storage **7/7** · consent **12/12** · scale **7/7** ·
backend pytest **26/26** · compileall OK.

### Measured limitations (never reported as coverage)

1. **Service workers are environment-dark** on Playwright+Firefox:
   registration fetch bypasses `context.route`, blob: registration is
   rejected, SW fetches emit no request events. Every crawl records the
   gap (`no_hello:…/wk-sw.js`); the GT page proves the SW exfil
   browser-side via the sink (`sw_sink_seen=true`) and the flows stay
   out of WORKER_FLOWS so no method is credited or penalised for them.
2. **Worker `sendBeacon` is undefined** in Firefox workers (probe16) —
   the GT beacon-equivalent uses `fetch(..., {keepalive:true})`.
3. **Injection side-effects**: dedicated workers see `?__privadb_tok=`
   in `self.location`; SharedWorkers run from a `blob:` URL (per-frame
   instances, `location` contaminated) — module-typed workers are not
   injectable (recorded as gaps).
4. Hook detection is in-page JS: a determined page can tamper (now
   *detected* via `__tamper_check`, reported per frame — 0 observed).

### Phase 13.1 — injection-path rework: Chromium phantom-request fix

**Discovery (post-Phase-13 testing):** the route.fulfill worker-injection
path produced **phantom requests on Chromium** — the worker script's
request event fires (so matchers score TP) yet the request dies with
`net::ERR_FAILED` before reaching the network. Evidence chain:
Chrome evaluate claimed worker-page transforms recall 1.000 but its
sink log contained **zero `/v/w*` arrivals** (`logs/28`, `raw/28` sink
subset) while shared-worker blob-path flows (`/v/sh*`) *did* arrive;
minimal reproducers isolated the variable to **route-fulfilled worker
script + subsequent cross-origin fetch** (same-origin still works —
`logs/32` fail, `logs/33`/`34` controls pass, `logs/35` shows
REQ→FAIL on cors *and* no-cors while same-origin returns 200).
Foxhound's juggler route did not exhibit the quirk, but a single
engine-dependent injection path was unacceptable.

**Rework (`crawler.py`, `logs/36`–`39`):**
- Dedicated workers now use the **same blob bootstrap** as
  SharedWorkers (core → `importScripts` with absolute-URL rebasing of
  direct children → original script); route machinery, marker URLs and
  `WORKER_PRELUDE_FMT` removed entirely.
- Blob constructor failures (CSP `worker-src` without `blob:`) fall
  back to the untouched original constructor — site keeps working,
  `blob_blocked` gap recorded. Non-http(s) worker URLs (site-authored
  `blob:`/`data:` workers) pass through untouched (`non_http` gap).
- Service workers are **left unmarked on both engines** (FF: route
  bypass; Chromium: injection breaks their cross-origin fetches) — the
  SW runs clean so its exfil reaches the sink for browser-side proof;
  `no_hello` gap recorded every crawl.

**Sink-side re-verification (the test that catches phantoms):**
- Foxhound: **99 sink hits, all worker-context paths present**
  (`/v/w*` ×13, `/v/wwin`, `/v/sh*`, `/v/sv*`, benign controls) —
  `raw/38-sinklog-foxhound.json`.
- Chromium: **99 hits, all 18 expected worker-context paths present** —
  `raw/39-sinklog-chrome.json`.
- Both engines: evaluate exit 0, **WC 7/7** (checks reworked to
  kind-based blob hello matching + "worker sends observable" invariant
  + SW sink proof), UID 3/3, transforms page reproduces the Phase-7
  baseline exactly, worker-page transforms **1.000** / dynamic
  **0.438**, variance σ=0 (`logs/38`/`39`/`42`).
- Regressions after rework: foxhound smoke 15/15, chrome smoke 14/14
  (`logs/36`), backend pytest 26/26, compileall (`logs/42`).

**Live-site spot check (`logs/41`, 2 sites, foxhound headless):**
- `www.braze.com`: 0 crawl errors; site **actively unwrapped** the
  hooks (`tampered=['fetch','xhr_open','xhr_send']` — detection
  surfaced it, as designed); site-authored `blob:` worker passed
  through via the `non_http` guard; 9 window sends synthesized.
- `www.reddit.com`: 0 errors; `service` spawn accounted (`sw.js`,
  expected no-hello); one **third-party (google-frame) blob worker**
  logged `no_hello:blob:https://www.google.com/…` — an honest gap in a
  cross-origin ad frame (frame/worker teardown timing), not a crash.
- 286 information flows analyzed end-to-end, HTML reports generated.

## Deliberately NOT done (needs a human)

1. **License**: still proprietary. Open-s relicensing is the copyright holder's decision — not changed.
2. **Real-site human labels**: tooling ready (`export_labeling.py`/`score_labels.py`); two annotators must produce the files.
3. **Docker build verification**: authoring host lacks docker-group/sudo; run the command in MANIFEST.md.
4. **Tranco top-N production run**: infrastructure ready (`scale.py`); the large crawl is an operator decision (runtime/ethics).
5. **Engine-grade IDB taint (Foxhound rebuild) — APPROVAL-GATED, not started.** The hook layer is still self-instrumentation; SAP's `taint/` has no IndexedDB source/sink and taint cannot survive structured-clone persistence as designed. Costed plan (for approval before any work):
   - **Source/build**: checkout SAP/project-foxhound + Mozilla `mach build` toolchain (clang/rust/ccache; ~40 GB tree; first build 1–4 h, incremental 15–30 min).
   - **Patch**: `MarkTaintSource` on `IDBRequest` completion (`dom/indexedDB/*`), sinks on `put/add/update`, worker-scope parity, plus a **persistence design** for taint labels across structured clone (sidecar labels per record vs re-taint-on-read heuristic — needs a design decision).
   - **Validate**: extend the Phase-13 GT so IDB→network flows are confirmed by `mechanism=taint` (engine-grade provenance) and re-run `evaluate.py`; target: dynamic-method recall ≥ transforms on raw flows without hook corroboration.
   - **Effort/risk**: ≈2–4 engineer-weeks including pipeline setup; main risks = Gecko drift vs SAP's base, label-persistence correctness, and keeping the exporter channel compatible. Requires build-machine resources + explicit operator approval.

## Reproduce

See `PAPER_REPORT.md` §9 and `MANIFEST.md`. Phase 13 sequence:
`logs/01`–`20` (probes → baseline → evaluate before/after → regressions).
