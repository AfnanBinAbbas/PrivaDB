# GRC Policy Scanner Integration

## Goal Description

Extend PrivaDB with a modular policy compliance scanner that runs after the technical IndexedDB scan. The new feature adds:
- Backend FastAPI endpoints to fetch a website's privacy/terms page, analyse its text against configurable GRC frameworks (GDPR, CCPA, ePrivacy, etc.), and return structured findings.
- Frontend React components providing a "Run GRC Policy Scan" button, fetching the scan results, and displaying them in a polished, animated UI.
- Minimal integration patches to wire the new API into the existing FastAPI server and to embed the button into the ScanResults view.
- Comprehensive configuration, error handling, caching, and tests.

## User Review Required

> [!IMPORTANT]
> The implementation introduces new dependencies (`beautifulsoup4`, `requests`, `pyyaml`, optional `spacy`). Please confirm you are comfortable installing these on your system.
>
> The UI uses existing Tailwind/React design tokens. If you use a custom design system, let us know to adapt class names.

## Open Questions

> [!QUESTION] (Note: Use alerts only for critical items)
> - Do you want the policy scan to be performed synchronously (blocking UI until complete) or should we implement a background‑task endpoint with polling?
> - Should the policy scanner support additional frameworks beyond GDPR, CCPA, ePrivacy (e.g., ISO 27701) now, or can we add them later via `config.yaml`?
> - Would you prefer the results to be downloadable as JSON/HTML alongside the existing technical report download options?

## Proposed Changes

---
### Backend (`Web/backend/policy_scanner/`)
#### [NEW] `__init__.py`
- Empty module to mark the package.

#### [NEW] `exceptions.py`
- Defines `PolicyFetchError`, `PolicyParseError`, `AnalysisError`.

#### [NEW] `config.yaml`
- Contains timeout, user‑agents list, URL path patterns, and rule definitions for each framework.

#### [NEW] `fetcher.py`
- `PolicyFetcher` class with methods:
  - `find_policy_url(base_url)` – tries common paths, meta tags, and footer links.
  - `fetch_policy_text(url)` – GET request with rotating UA, 10 s timeout, follow redirects, returns cleaned plain text using BeautifulSoup.
- Handles network errors, 404/500 responses, redirects, and fallback to scrape homepage for privacy‑related paragraphs.

#### [NEW] `analyzer.py`
- `PolicyAnalyzer` class.
- Loads framework rule sets from `config.yaml`.
- Simple keyword‑based matching to detect presence/absence/insufficiency of required clauses.
- Returns list of `Finding` dicts (framework, clause, status, evidence, reason, remediation, severity) and a compliance score (0‑100).

#### [NEW] `api.py`
- FastAPI `APIRouter` with endpoint:
  - `POST /api/v1/policy/scan` – body `{ "base_url": "https://example.com", "frameworks": ["GDPR","CCPA"] }`
  - Calls `PolicyFetcher` → `PolicyAnalyzer` → returns JSON `{ findings: [...], scores: { GDPR: 85, ... } }`.
- Optional `GET /api/v1/policy/status/{task_id}` for background tasks (implemented but not used by default).
- Pydantic request/response models, proper logging, and exception handling.

#### [NEW] `README.md`
- Installation steps, how to extend `config.yaml`, API usage examples, and troubleshooting notes.

#### [NEW] `requirements_policy_scanner.txt`
- Lists extra dependencies.

#### [NEW] `tests/test_policy_scanner.py`
- Unit tests for `PolicyFetcher` (mocked HTTP responses) and `PolicyAnalyzer` (sample policy snippets).
- Integration test hitting a known public privacy policy URL.

---
### Frontend (`Web/src/components/PolicyScanner/`)
#### [NEW] `PolicyScanButton.tsx`
- Receives the scanned website base URL from parent (via props or context).
- Renders a styled button matching the existing UI.
- On click triggers loading state, calls backend `/api/v1/policy/scan`.
- Handles success/error, passes result to `PolicyResults`.

#### [NEW] `PolicyResults.tsx`
- Shows overall compliance summary with ✅/❌ badge.
- Displays a score gauge (simple colored circle or progress bar).
- Table of findings per framework with columns: Framework, Clause, Status, Explanation, Remediation.
- Expandable rows for detailed evidence.
- Handles "policy not found" fallback UI.

#### [NEW] `index.ts`
- Re‑exports the two components.

#### [NEW] `PolicyScannerPage.tsx` (optional wrapper)
- If the app uses a router, this page composes `PolicyScanButton` and `PolicyResults` after the technical scan view.
- Imports existing state (e.g., `currentScan.baseUrl`).

---
### Integration Patches (non‑intrusive)
#### `Web/backend/server_patch_instructions.txt`
- Add import and `app.include_router(policy_router, prefix="/api/v1")`.

#### `Web/src/integration_patch.txt`
- Instructions for the developer to import `PolicyScanButton` in `ScanResults.tsx` (or the appropriate results view) and place it next to the "Download Report" button.

---
## Verification Plan

### Automated Tests
- Run `pytest -q` – includes the new `test_policy_scanner.py` suite.
- Verify FastAPI route returns 200 with expected schema.
- Mocked fetcher tests ensure proper fallback behaviour.

### Manual Verification
- Start backend (`uvicorn backend.server:app`).
- Load the web UI, run a technical scan, then click **Run GRC Policy Scan**.
- Confirm loading spinner, then see a compliance summary.
- Test with a site that has no privacy policy – UI should show the fallback message.
- Verify error handling (e.g., network timeout) shows a user‑friendly toast.

---
## Performance & Security
- Policy fetch uses a 10 s timeout and rotates a short list of user‑agents.
- SSRF protection: only `http`/`https` URLs, reject private IP ranges via `urlparse` and IP checks.
- Simple in‑memory cache (`lru_cache` with 1‑hour TTL) to avoid refetching the same policy.
- Rate‑limit endpoint with FastAPI `Depends` (optional, can be added later).

---
**End of Implementation Plan**
