# PRIVADB: Comparative Privacy Analysis of  IndexedDB with Dynamic Taint Analysis

**Detecting Persistent Web Tracking via IndexedDB — FYP Research Project**

A three-phase dynamic analysis pipeline that crawls websites, extracts IndexedDB storage data, and detects tracking identifier exfiltration using heuristic taint analysis. Implements the analytical framework from *"What Storage: An Empirical Analysis of Web Storage in the Wild"* adapted specifically for IndexedDB.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Pipeline Phases](#pipeline-phases)
- [Installation](#installation)
- [Usage](#usage)
- [Input Formats](#input-formats)
- [Output & Results](#output--results)
- [Analytical Framework](#analytical-framework)
- [Configuration](#configuration)
- [BigQuery Integration](#bigquery-integration)
- [Blacklisted Tracker Domains](#blacklisted-tracker-domains)
- [Project Structure](#project-structure)
- [Glossary & Terminal Output Guide](#glossary--terminal-output-guide)
- [Key Metrics Explained](#key-metrics-explained)
- [Function Reference — Detailed Documentation](#function-reference--detailed-documentation)
- [Limitations](#limitations)
- [References](#references)

---

## Overview

Modern websites increasingly use **IndexedDB** — a powerful client-side NoSQL database — to store data in the browser. While designed for legitimate purposes (offline caching, app state), IndexedDB is also exploited by third-party trackers to persist unique identifiers that survive cookie clearing.

This tool:
1. **Crawls** target websites using a headless Chromium browser (Playwright)
2. **Extracts** all IndexedDB databases, object stores, and records
3. **Captures** all network requests made during the page load
4. **Detects** potential tracking identifiers stored in IndexedDB
5. **Traces** exfiltration of those identifiers via network requests (outflow flows)
6. **Detects** external data flowing into IndexedDB (inflow flows)
7. **Classifies** each flow by confinement, cross-origin status, and tracking confidence
8. **Generates** publication-quality reports, charts, and CSV exports

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        main.py (Orchestrator)                       │
│  CLI argument parsing │ Phase coordination │ Overwrite protection   │
└────────────────────┬──────────────┬──────────────┬──────────────────┘
                     │              │              │
           ┌─────────▼──────┐ ┌────▼─────────┐ ┌──▼──────────────┐
           │   PHASE 1      │ │   PHASE 2    │ │   PHASE 3       │
           │   crawler.py   │ │  detector.py │ │   reporter.py   │
           │                │ │              │ │                  │
           │ • Playwright   │ │ • ID extract │ │ • JSON reports   │
           │ • IDB extract  │ │ • Exfil find │ │ • CSV exports    │
           │ • Network cap  │ │ • Flow class │ │ • Console tables │
           │ • Raw JSON out │ │ • Inflow     │ │ • Matplotlib     │
           │                │ │ • Paper calc │ │ • Pandas DFs     │
           └────────┬───────┘ └──────┬───────┘ └────────┬─────────┘
                    │                │                   │
                    ▼                ▼                   ▼
              results/raw/     Analysis in        results/*.json
              site_data.json   memory             results/*.csv
                                                  results/charts/
                     ┌──────────────────────────────────┐
                     │         config.py                 │
                     │  Paths │ Patterns │ Thresholds    │
                     │  Tracker lists │ IDB definitions  │
                     └──────────────────────────────────┘
```

---

## Pipeline Phases

### Phase 1: Crawling (`crawler.py`)

- Opens each target URL in a headless Chromium browser via **Playwright**
- Waits for page load and network idle (configurable timeout)
- Executes JavaScript to enumerate all IndexedDB databases
- For each database: opens transactions, reads all object stores and records
- Captures every network request (URL, method, headers, POST body)
- Saves per-site JSON files to `results/raw/`

### Phase 2: Detection (`detector.py`)

- Loads each crawled JSON file
- **Identifier Extraction**: Recursively walks all IDB record values
  - Flags any dict key with a string value ≥ 8 characters (`idb_key:{name}`)
  - Pattern matching: UUID v4, hex strings, base64 blobs
  - Shannon entropy threshold (≥ 3.0 bits) for high-entropy strings
  - Large numbers (≥ 10 digits) for timestamps/counters
- **Exfiltration Detection**: Searches every captured network request for extracted identifiers
  - Checks URL parameters, POST body, and Cookie headers
  - Classifies third-party vs first-party requests
  - Cross-checks against 577+ known tracker domains
- **Inflow Detection**: Identifies external data entering IDB
  - Navigator properties (userAgent, platform, etc.) → `IDBObjectStore.put`
  - URL parameter values → `IDBObjectStore.put`
- **Flow Classification** (paper-aligned):
  - Flow direction: outflow (IDB→network) vs inflow (external→IDB)
  - Confinement: internal (same-origin) vs external (different origin)
  - Cross-origin: same-site vs cross-site for external flows
- **False Positive Reduction**:
  - Domain self-match filter (removes site's own domain matched as an ID)
  - Deduplication of identical exfiltration events

### Phase 3: Reporting (`reporter.py`)

- **`summary.json`**: Detailed per-site results with all detected events
- **`statistics.json`**: Aggregate metrics including paper-aligned calculations
- **`tracking_events.csv`**: Every flow event with all classification labels
- **`per_site_analysis.csv`**: Pandas-generated per-site summary table
- **`charts/`**: 6 publication-quality matplotlib visualizations
- **Console output**: Pandas DataFrames + numpy-formatted tables

---

## Installation

### Prerequisites

- **Python 3.10+**
- **Chromium browser** (installed automatically by Playwright)

### Setup

```bash
# Clone or navigate to the project
cd /path/to/Static-Analysis/scratch

# Install Python dependencies
pip install -r requirements.txt

# Additional dependencies (pandas + matplotlib for visualization)
pip install pandas matplotlib

# Install Playwright browsers
playwright install chromium
```

### `requirements.txt`

```
playwright>=1.40.0
numpy>=1.24.0
pandas>=2.0.0
matplotlib>=3.7.0
```

---

## Usage

### Full Pipeline (Crawl + Detect + Report)

```bash
# Default: crawl sites from sites.json
python main.py

# Custom domain list
python main.py --input-file domains.txt

# Limit to first 10 sites
python main.py --sites 10

# Use a specific chunk file with 5 sites
python main.py --input-file domains2scan/chunk_008 --sites 5
```

### Individual Phases

```bash
# Crawl only (save raw data, skip analysis)
python main.py --crawl-only

# Detect + Report only (on existing crawled data)
python main.py --detect-only

# Detect only first 20 crawled sites
python main.py --detect-only --sites 20
```

### Overwrite Control

By default, the pipeline **prompts before overwriting** existing results:

```bash
# Will prompt: "Overwrite existing results? [y/N]"
python main.py --detect-only

# Skip the prompt, overwrite silently
python main.py --detect-only --overwrite
```

### Browser Debugging

```bash
# Show the browser window (non-headless)
python main.py --no-headless --sites 3
```

### All CLI Flags

| Flag | Description | Default |
|---|---|---|
| `--input-file FILE` | Path to custom domain list (.txt or .json) | `sites.json` |
| `--sites N` | Limit to first N sites (crawl AND detect) | All |
| `--crawl-only` | Only crawl, skip detection and reporting | Off |
| `--detect-only` | Only detect/report on existing crawled data | Off |
| `--no-headless` | Show browser window for debugging | Headless |
| `--overwrite` | Overwrite existing results without prompting | Prompt |

### Test Cases (Manual Verification)

The `test_cases.py` script performs **live crawling + detection** on a small set of sites and produces a human-readable JSON report for manual verification.

```bash
# Run default test sites (~5 curated sites with known trackers)
python test_cases.py

# Test a specific URL
python test_cases.py --url https://example.com

# Test multiple URLs
python test_cases.py --url https://a.com --url https://b.com

# Show browser window
python test_cases.py --no-headless

# Run 2 crawl iterations per site (for diff analysis)
python test_cases.py --iterations 2
```

**Output:** A JSON report saved to `results/test_reports/test_report_YYYYMMDD_HHMMSS.json` containing:

- **IndexedDB key:value pairs** — actual database records for cross-checking with browser DevTools
- **Detected trackers** — domain, request URL, status code, exfiltrated value, confidence level
- **All third-party requests** — with status codes and known-tracker flags
- **Inflow flows** — external data (navigator, URL params) written into IDB
- **Pass/Fail verdict** — per site, based on whether the expected tracker was detected

---

## Input Formats

### Plain Text (`.txt`)

One URL or domain per line. Lines starting with `#` are comments.

```text
# My target sites
https://example.com
google.com
www.tracker-test.com
```

### JSON (`.json`)

Either a list of URLs or an object with a `sites` key:

```json
["https://example.com", "google.com", "facebook.com"]
```

```json
{
  "sites": [
    {"url": "https://example.com", "reason": "popular site"},
    {"url": "https://tracker-test.org", "reason": "known tracker"}
  ]
}
```

### Chunk Files (`domains2scan/chunk_NNN`)

Pre-split domain lists (500 domains per chunk, ~1000 chunks). Use with `--input-file`:

```bash
python main.py --input-file domains2scan/chunk_008 --sites 50
```

---

## Output & Results

All output is written to the `results/` directory:

```
results/
├── raw/                          # Per-site crawled data (JSON)
│   ├── google_com.json
│   ├── facebook_com.json
│   └── ...
├── summary.json                  # Detailed per-site analysis results
├── statistics.json               # Aggregate metrics + paper metrics
├── tracking_events.csv           # All flow events with classifications
├── per_site_analysis.csv         # Pandas per-site summary table
├── pipeline.log                  # Full pipeline execution log
└── charts/                       # Matplotlib visualizations (PNG)
    ├── confidence_distribution.png
    ├── top_trackers.png
    ├── confinement_analysis.png
    ├── flow_direction.png
    ├── cross_site_breakdown.png
    └── identifier_types.png
```

### Charts Generated

| Chart | Type | Description |
|---|---|---|
| `confidence_distribution.png` | Pie | HIGH / MEDIUM / LOW confidence breakdown |
| `top_trackers.png` | Horizontal Bar | Top 10 third-party tracker domains by event count |
| `confinement_analysis.png` | Pie | Internal (confined) vs External (escaped) flows |
| `flow_direction.png` | Bar | Outflow vs Inflow flow counts |
| `cross_site_breakdown.png` | Pie | Same-site vs Cross-site external flows |
| `identifier_types.png` | Bar | Distribution of identifier detection reasons |

### Console Output

The pipeline prints comprehensive tables to the console:

```
======================================================================
  IndexedDB DYNAMIC TAINT ANALYSIS — RESULTS SUMMARY
======================================================================

   SITES WITH DETECTED FLOWS (pandas DataFrame)
  ────────────────────────────────────────────────────────────────────
                 IDB DBs  Records  Net Reqs  IDs Found  Exfil  HIGH  ...
Domain
dropbox.com           2       32       255        155    144     0  ...
spotify.com           1        1       187       1157     67     9  ...
...

   AGGREGATE STATISTICS (pandas)
  ────────────────────────────────────────────────────────────────────
           Total   Mean  Max     Std
IDB DBs      183   0.27   10    0.83
Records      433   0.65   59    3.74
...
```

---

## Glossary & Terminal Output Guide

When the pipeline finishes, it prints a comprehensive summary to the terminal. Here is a plain-English, beginner-friendly explanation of exactly what each section means.

### 1. 📊 AGGREGATE STATISTICS (pandas)
This is a high-level summary of the raw data collected across all the sites you just crawled.
* **IDB DBs:** The total number of IndexedDB databases found across all sites.
* **Records:** The total number of key-value pairs stored in those databases.
* **Net Reqs:** The total number of network requests the browser made while loading all these sites.
* **IDs Found:** The number of times the detector found a potential "identifier" (a string of text that looks like a tracking ID) stored inside IndexedDB.
* **Exfil (Exfiltrations):** The number of times one of those identifiers was caught being sent out to the internet in a network request. This is the core tracking event.
* **HIGH / MED / LOW:** How confident the scanner is that these exfiltrations are actually malicious tracking. 
* **Inflow:** The number of times external data (like a URL parameter) was saved *into* IndexedDB.
* **Internal / External:** Out of the exfiltrations, how many stayed on the same website (Internal) vs. how many were sent to a completely different website (External).

### 2. 🗄️ IndexedDB KEY:VALUE RECORDS
This shows the actual data that the websites stored inside your browser's IndexedDB. 
* It shows the domain (e.g., `accuweather.com`), exactly where it was stored (`pn_store` database), the name of the key (`id`, `tz`), and the actual value that was saved (`Asia/Karachi`).
* *Note:* The terminal only shows the first 10 records so it doesn't crash your screen. All valid records are saved safely in `results/indexeddb_records.json`.

### 3. 🌐 NETWORK REQUESTS CAPTURED
A summary of all the internet traffic generated by the sites.
* **Total requests:** The raw number of HTTP requests.
* **Third-party:** The percentage of requests that went to a different domain than the one you were visiting. 
* **Top third-party domains:** Shows which external companies are collecting the most data (e.g., `www.google.com`, `m.media-amazon.com`).

### 4. ⚠️ CONFIDENCE BREAKDOWN
A summary of the scoring applied to the "Exfil" events mentioned above.
* **HIGH (🔴):** We are highly certain this is tracking (e.g., sent to a known tracker domain).
* **MEDIUM (🟡):** Suspicious, but lacks definitive proof.
* **LOW (🟢):** Low risk (likely just the website talking to its own servers for harmless reasons).

### 5. 📡 TOP TRACKER DOMAINS
This lists the specific domains that were caught receiving data *out* of IndexedDB. 
* For example, if `b.6sc.co` is listed with 25 events, it means it received IndexedDB data 25 times across your scans.

### 6. 🏷️ IDENTIFIER TYPES DETECTED
This explains *why* the detector thought a piece of data in IndexedDB was worth tracking.
* **`idb_key:userid` / `idb_key:href`:** The data was stored under a highly suspicious key name.
* **`high_entropy`:** The string was mathematically random (like a UUID or token).

### 7. 🌐 OVERALL CLASSIFICATION
A quick funnel of your entire scan journey:
* **Total sites analyzed:** How many you started with.
* **Sites with IndexedDB:** How many actually used the database API.
* **Sites with exfiltration:** How many had data leave IndexedDB and go to the network.
* **Sites with HIGH tracking:** How many had a highly confident tracker detected.

---

### "WHAT STORAGE" PAPER — ANALYTICAL FRAMEWORK RESULTS

This section formats your scan's data to exactly match the tables and math from the academic paper *"What Storage: An Empirical Analysis of Web Storage in the Wild"*, allowing you to compare your findings against their published research.

* **📄 FLOW OVERVIEW:** Breaks down the total flows into "Outflow" (data leaving the browser) and "Inflow" (data entering the database from the outside).
* **📊 TABLE III: CONFINEMENT:** Breaks down the Outflows. "Internal" means the data stayed on the same website. "External" means the data crossed origins (sent to another company).
* **📊 TABLE IV: EXTERNAL FLOWS BREAKDOWN:** Looks *only* at the External flows. It shows how many were purely "Cross-site" (sent to a totally unrelated company), and out of those, how many were confirmed blacklisted trackers.
* **📊 TRACKING vs NON-TRACKING:** Evaluates the Outflows. Shows what percentage of them hit a known blacklisted tracking domain.
* **📡 SINK CLASS DISTRIBUTION:** Tells you *how* the data left the browser (e.g., via a standard `network` request vs. stuffed into a `cookie`).
* **🗄️ TOP IndexedDB DATABASES:** The names of the specific databases that were involved in the most Outflows. (e.g., `mixpanelBrowserDb`).
* **📈 PAPER METRICS SUMMARY:** A final cheat sheet of all the key percentages that the academic paper reported, calculated using your specific dataset.

---

## Analytical Framework

This project implements the methodology from the *"What Storage"* paper, adapted for IndexedDB:

### Information Flow Types

| Flow Type | Direction | Source | Sink | Description |
|---|---|---|---|---|
| **Outflow** | IDB → Network | `IDBObjectStore.get` | `fetch_url` / `xhr_body` / `header_cookie` | Data read from IDB and sent to network |
| **Inflow** | External → IDB | `url_parameter` / `navigator_prop` | `IDBObjectStore.put` | External data written into IDB |

### Paper-Aligned Tables

- **Table III — Confinement Analysis**: Internal vs External × Outflow/Inflow
- **Table IV — External Flow Breakdown**: Same-site vs Cross-site with tracking classification

### Confidence Scoring

Each outflow flow receives a confidence level:

| Level | Criteria |
|---|---|
| 🔴 **HIGH** | Third-party + known tracker domain + high-entropy identifier |
| 🟡 **MEDIUM** | Third-party + identifier pattern (UUID, base64, etc.) |
| 🟢 **LOW** | First-party or ambiguous match |

### IndexedDB Source/Sink Definitions

**Sources** (where data originates):
- `IDB_SOURCES`: `IDBObjectStore.get`, `.getAll`, `.getKey`, `.openCursor`, `IDBIndex.get`, etc.
- `EXTERNAL_SOURCES`: `url_parameter`, `navigator_prop`, `network_response`, `document_cookie`

**Sinks** (where data flows to):
- `IDB_SINKS`: `IDBObjectStore.put`, `.add`, `.delete`, `.clear`
- `EXTERNAL_SINKS`: `xhr_url`, `fetch_url`, `xhr_body`, `fetch_body`, `sendbeacon`, `header_cookie`

---

## Configuration

All tuneable parameters are in **`config.py`**:

### Paths

| Variable | Default | Description |
|---|---|---|
| `RESULTS_DIR` | `results/` | Output directory for all reports |
| `RAW_DATA_DIR` | `results/raw/` | Crawled JSON data storage |

### Crawler Settings

| Variable | Default | Description |
|---|---|---|
| `PAGE_TIMEOUT_MS` | `30000` | Page load timeout (ms) |
| `NETWORK_IDLE_MS` | `5000` | Wait for network idle (ms) |
| `HEADLESS` | `True` | Run browser headless |

### Identifier Detection

| Variable | Default | Description |
|---|---|---|
| `MIN_ID_LENGTH` | `8` | Minimum string length to flag as potential ID |
| `ENTROPY_THRESHOLD` | `3.0` | Shannon entropy threshold for high-entropy strings |
| `UUID_V4_RE` | `(compiled)` | Regex for UUID v4 pattern |
| `HEX_STRING_RE` | `(compiled)` | Regex for hex strings (16+ chars) |
| `BASE64_RE` | `(compiled)` | Regex for base64 blobs (20+ chars) |

### Tracker Domains

| Variable | Count | Description |
|---|---|---|
| `KNOWN_TRACKER_DOMAINS` | ~40 | Hardcoded well-known tracker domains |
| `BLACKLISTED_TRACKER_DOMAINS` | ~537 | Auto-loaded from external blacklist files |
| `ALL_TRACKER_DOMAINS` | ~577 | Merged set used for matching |

---

## BigQuery Integration

The project was bootstrapped with BigQuery analysis of the HTTP Archive dataset to identify websites using IndexedDB:

### Query 1: Sites Using IndexedDB (`BQ_results_Q1.txt`)

```sql
SELECT
  page, url, NET.HOST(page) AS domain, date,
  REGEXP_CONTAINS(response_body,
    r'indexedDB\.open|indexedDB\.deleteDatabase|IDBTransaction|IDBObjectStore'
  ) AS uses_indexeddb
FROM `httparchive.crawl.requests`
WHERE date = '2024-06-01'
  AND REGEXP_CONTAINS(response_body, r'indexedDB\.open|...')
LIMIT 100
```

### Query 2: Script Domains Using IndexedDB (`BQ_trackersdomains_Q2.txt`)

Identifies which script domains use IndexedDB APIs on which websites, revealing third-party libraries and SDKs that interact with IndexedDB.

---

## Blacklisted Tracker Domains

Two external blacklist files are automatically loaded at startup:

- **`blacklisted-trackers_all_HTTP.txt`** — 888 HTTP tracker announce URLs
- **`blacklisted-trackers_all_HTTPS.txt`** — 128 HTTPS tracker announce URLs

Domains are extracted from these URLs and merged with the hardcoded `KNOWN_TRACKER_DOMAINS`. The combined set (`ALL_TRACKER_DOMAINS`, ~577 unique domains) is used for tracker matching during confidence scoring.

---

## Project Structure

```
scratch/
├── main.py                  # Entry point & CLI orchestrator
├── crawler.py               # Playwright-based web crawler
├── detector.py              # Taint analysis & flow detection engine
├── reporter.py              # Report generation (JSON, CSV, charts, tables)
├── config.py                # All configuration & constants
├── requirements.txt         # Python dependencies
├── sites.json               # Default target site list
├── README.md                # This file
├── GUIDELINES.md            # Research guidelines & objectives
│
├── domains2scan/            # Pre-chunked domain lists (500/chunk)
│   ├── chunk_000
│   ├── chunk_001
│   └── ... (up to chunk_999)
│
├── BQ_results_Q1.txt        # BigQuery results: sites using IndexedDB
├── BQ_trackersdomains_Q2.txt# BigQuery results: tracker script domains
├── Queries_used.txt         # BigQuery SQL queries used
│
├── blacklisted-trackers_all_HTTP.txt   # Tracker blacklist (HTTP)
├── blacklisted-trackers_all_HTTPS.txt  # Tracker blacklist (HTTPS)
│
└── results/                 # Output directory (generated)
    ├── raw/                 # Per-site crawled JSON data
    ├── charts/              # Matplotlib chart PNGs
    ├── summary.json         # Detailed per-site results
    ├── statistics.json      # Aggregate metrics
    ├── tracking_events.csv  # All flow events
    ├── per_site_analysis.csv# Per-site pandas summary
    └── pipeline.log         # Execution log
```

---

## Key Metrics Explained

| Metric | Formula | Meaning |
|---|---|---|
| **% sites with IndexedDB** | (sites with ≥1 IDB database) / total sites | IndexedDB adoption rate |
| **Outflow flows** | IDB identifiers found in network requests | Data leaving the browser |
| **Inflow flows** | External data (navigator, URLs) found in IDB records | Data entering IDB |
| **Internal (confined)** | Flows where request domain == page domain | Data stays on same origin |
| **External** | Flows where request domain ≠ page domain | Data crosses origins |
| **Cross-site** | External flows to a different registrable domain | Potential cross-site tracking |
| **% tracking** | Flows to known tracker domains / total external flows | Confirmed tracking activity |

---

## Limitations

- **Heuristic-based**: Uses pattern matching and string search rather than true dynamic taint tracking (no JS instrumentation)
- **Single page load**: Only analyzes the initial page load; interactive flows (clicks, form submissions) are not captured
- **No Service Worker analysis**: IDB usage by service workers during background sync is not directly captured
- **String matching**: Identifier exfiltration is detected by substring matching, which can produce false positives for short or common strings
- **Navigator-only inflow**: Inflow detection currently only catches navigator properties and URL parameters, not network response → IDB flows

---

## Function Reference — Detailed Documentation

This section documents **every function** in the codebase, explaining its parameters, return values, and the internal logic / algorithmic approach.

---

### `config.py` — Configuration & Constants

#### `_load_blacklisted_tracker_domains() → set[str]`

**Purpose:** Loads tracker domains from external blacklist files at module import time.

**Logic:**
1. Iterates over each file path in `BLACKLIST_FILES` (the HTTP and HTTPS blacklist text files).
2. Skips files that don't exist, empty lines, and comment lines (starting with `#`).
3. Parses each line as a URL using `urllib.parse.urlparse` and extracts the hostname.
4. Filters out pure IP addresses (e.g., `192.168.1.1`) by checking if the hostname consists only of digits and dots.
5. Lowercases all hostnames and collects them into a `set` for O(1) lookup.

**Returns:** A `set[str]` of unique tracker domain hostnames extracted from the blacklist files. This set is merged with the hardcoded `KNOWN_TRACKER_DOMAINS` to form `ALL_TRACKER_DOMAINS` (~577 domains).

---

### `main.py` — Pipeline Orchestrator

#### `setup_logging()`

**Purpose:** Configures Python's logging system for the entire pipeline.

**Logic:**
- Sets log level to `INFO` with timestamp format `HH:MM:SS`.
- Creates two handlers: one for `stdout` (console) and one for a `pipeline.log` file in the results directory.
- If the results directory doesn't exist yet, falls back to a second `StreamHandler` instead of the file handler.

---

#### `load_sites_from_file(filepath: str) → list[dict]`

**Purpose:** Loads a custom site list from a user-provided file.

| Parameter | Type | Description |
|---|---|---|
| `filepath` | `str` | Path to a `.txt` or `.json` file containing URLs/domains |

**Logic:**
1. Checks if the file exists; exits with error if not.
2. Determines format by file extension:
   - **JSON (`.json`)**: Supports two formats — a flat list of URL strings (`["url1", "url2"]`) or an object with a `"sites"` key containing a list of `{url, reason}` dicts.
   - **Plain text (any other extension)**: Reads one URL/domain per line. Lines starting with `#` are treated as comments and skipped.
3. For each entry, calls `_normalize_url()` to ensure proper formatting.
4. Exits with error if no valid URLs are found.

**Returns:** A `list[dict]` where each dict has keys `"url"` (normalized) and `"reason"` (set to `"custom input"` for user-provided entries).

---

#### `_normalize_url(url: str) → str`

**Purpose:** Ensures a URL has a proper scheme and trailing slash.

**Logic:**
- Strips whitespace from the input.
- If the URL doesn't start with `http://` or `https://`, prepends `https://`.
- Appends a trailing `/` if not already present.

**Returns:** The normalized URL string (e.g., `"example.com"` → `"https://example.com/"`).

---

#### `parse_args() → argparse.Namespace`

**Purpose:** Parses command-line arguments using `argparse`.

**Supported flags:**
- `--input-file FILE` — Custom domain list path
- `--crawl-only` — Run only Phase 1
- `--detect-only` — Run only Phases 2 & 3
- `--sites N` — Limit to first N sites
- `--no-headless` — Show browser window
- `--overwrite` / `--no-overwrite` — Control overwrite behavior

**Returns:** An `argparse.Namespace` with all parsed flag values.

---

#### `main()`

**Purpose:** Runs the full three-phase analysis pipeline.

**Logic (step by step):**
1. Parses CLI arguments via `parse_args()`.
2. Applies runtime config overrides (e.g., `--no-headless` sets `config.HEADLESS = False`).
3. **Overwrite protection**: Checks if `summary.json`, `statistics.json`, or `tracking_events.csv` already exist. If so:
   - `--no-overwrite`: silently skips.
   - No flag: prompts the user for confirmation.
   - `--overwrite`: proceeds without prompting.
4. Creates the results directory and sets up logging.
5. Loads custom sites if `--input-file` is provided.
6. **Phase 1 (Crawl)**: Imports `crawler.crawl_all_sites` and runs it with `asyncio.run()`. If `--crawl-only`, exits after saving raw data.
7. **Phase 2 (Detect)**: Imports `detector.analyze_all_sites`. In full-pipeline mode, passes only the filenames of just-crawled sites. In `--detect-only` mode, analyzes all existing crawled files.
8. **Phase 3 (Report)**: Imports `reporter.generate_reports` and generates all outputs.

---

### `crawler.py` — Web Crawler

#### `EXTRACT_INDEXEDDB_SCRIPT` (JavaScript constant)

**Purpose:** A JavaScript async function injected into the browser page via `page.evaluate()`.

**Logic:**
1. Calls `window.indexedDB.databases()` to enumerate all IDB databases.
2. For each database, opens it with `indexedDB.open(dbName)` using a Promise wrapper.
3. Handles `onupgradeneeded` (version conflict) by closing the DB and returning `null`.
4. Iterates over all object store names from `db.objectStoreNames`.
5. For each store, opens a `readonly` transaction and calls `store.getAll()` + `store.getAllKeys()` to retrieve all records.
6. **Unwrapping logic**: If a record value is an object with `{key/k, value}` shape, it extracts just the `value` portion. If the value has an inline `keyPath`, it removes that key to avoid redundancy.
7. Caps records at **200 per store** to prevent memory issues.
8. Returns `{ databases: [...] }` with all stores and their records.

---

#### `class SiteCrawler`

##### `__init__(self)`

Initializes an empty `network_requests` list to collect intercepted requests.

##### `crawl_site(self, browser, url: str) → dict`

**Purpose:** Visits a single URL, extracts IndexedDB data, and captures all network requests.

| Parameter | Type | Description |
|---|---|---|
| `browser` | Playwright `Browser` | An active Playwright browser instance |
| `url` | `str` | The target URL to crawl |

**Logic:**
1. Creates a new browser context with a custom user agent and HTTPS error ignoring.
2. Opens a new page and attaches `request` / `response` event listeners.
3. Navigates to the URL with `wait_until="domcontentloaded"` and the configured `NAVIGATION_TIMEOUT`.
4. Waits an additional `IDLE_WAIT` ms for async scripts to finish executing.
5. Evaluates `EXTRACT_INDEXEDDB_SCRIPT` in the page context to extract all IDB data.
6. Logs the database count and total record count.
7. Attaches the captured `network_requests` list to the result.
8. Closes the browser context and returns the result dict.

**Returns:** A dict with keys: `url`, `domain`, `timestamp`, `indexeddb`, `network_requests`, `errors`.

##### `_on_request(self, request)`

**Purpose:** Event handler that captures outgoing request details.

**Logic:** Creates a dict with `url`, `method`, `resource_type`, `headers`, and `post_data` (captured only for POST/PUT/PATCH methods). Appends to `self.network_requests`.

##### `_on_response(self, response)`

**Purpose:** Event handler that attaches the HTTP response status to the matching request entry.

**Logic:** Searches `self.network_requests` in **reverse order** (most recent first) for a request with the same URL and no response yet, then sets `response.status`.

---

#### `crawl_all_sites(site_limit=None, custom_sites=None) → list[dict]`

**Purpose:** Crawls all target sites with multiple iterations per site.

| Parameter | Type | Description |
|---|---|---|
| `site_limit` | `int \| None` | Maximum number of sites to crawl |
| `custom_sites` | `list[dict] \| None` | Custom site list overriding `sites.json` |

**Logic:**
1. Loads sites from `custom_sites` or from `config.SITES_FILE` (`sites.json`).
2. Applies `site_limit` to truncate the list.
3. For each site, performs `config.CRAWL_ITERATIONS` (default: 3) crawls, each with a **completely fresh browser instance** (new `async_playwright()` context). This ensures cookies/storage from prior iterations don't persist.
4. Combines all iterations under one result dict, using the first iteration as the primary data for backward compatibility.
5. Collects all errors across iterations, prefixed with the iteration number.
6. Saves each site's combined result (including all iterations) as a JSON file in `results/crawled/`, using a sanitized domain as the filename.
7. Adds a 2-second delay between iterations and between sites.

**Returns:** A `list[dict]` of per-site results, each containing an `iterations` list.

---

### `detector.py` — Tracking Detection Engine

#### `shannon_entropy(s: str) → float`

**Purpose:** Calculates the Shannon entropy of a string — a measure of randomness.

**Logic:**
- Counts the frequency of each character in the string.
- Applies the Shannon entropy formula: `H = -Σ (p_i × log₂(p_i))` where `p_i = count_i / length`.
- Higher entropy values (closer to `log₂(alphabet_size)`) indicate more random, uniformly distributed strings — characteristic of tracking identifiers like UUIDs or hex tokens.

**Returns:** A `float` representing entropy in bits. Returns `0.0` for empty strings.

---

#### `extract_potential_ids(value, path: str = "") → list[dict]`

**Purpose:** Recursively extracts potential tracking identifiers from an IndexedDB value.

| Parameter | Type | Description |
|---|---|---|
| `value` | `any` | The IndexedDB record value (string, dict, list, or primitive) |
| `path` | `str` | Dot-notation path tracking the current position in the nested structure |

**Logic:**
1. **String values**: If length ≥ `MIN_ID_LENGTH` (8), flagged as `"idb_value"` with its Shannon entropy.
2. **Dict values**: Iterates over all key-value pairs. Any key with a string value ≥ 8 chars is flagged as `"idb_key:{keyname}"`. Then recurses into the value for nested structures.
3. **List values**: Recurses into each element with an indexed path like `path[0]`, `path[1]`, etc.

**Returns:** A `list[dict]` where each dict contains: `value`, `path`, `reason`, and `entropy`.

---

#### `_check_string_value(value: str, path: str, results: list)`

**Purpose:** Checks a string value against specific tracking identifier patterns (used as a supplementary detector).

**Logic (pattern priority):**
1. **UUID v4**: Matches `[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`. If found, extracts all matches and returns early.
2. **Hex string**: Matches `^[0-9a-f]{16,}$` (pure hex, ≥16 chars). Returns early.
3. **Base64 blob**: Matches `^[A-Za-z0-9+/]{20,}={0,2}$` with minimum 20 chars. Returns early.
4. **High-entropy string**: If entropy ≥ `ENTROPY_THRESHOLD` (3.0 bits) and length is between 12–128 characters, flags as `"high_entropy"` unless filtered out by `_is_common_value()`.

---

#### `_is_common_value(value: str) → bool`

**Purpose:** Filters out false positives — strings that are high-entropy but clearly not tracking IDs.

**Logic:** Returns `True` (= skip this value) if the string:
- Starts with `http://`, `https://`, `/`, `data:`, or `blob:` (URLs/paths)
- Contains file extensions like `.js`, `.css`, `.html`, `.png`, `.jpg`, `.svg`
- Matches a date pattern `YYYY-MM-DD`

---

#### `find_exfiltrations(identifiers, network_requests, site_domain) → list[dict]`

**Purpose:** Searches all captured network requests for occurrences of extracted identifiers — detecting data exfiltration.

| Parameter | Type | Description |
|---|---|---|
| `identifiers` | `list[dict]` | Potential tracking identifiers from `extract_potential_ids()` |
| `network_requests` | `list[dict]` | Captured HTTP requests from the crawler |
| `site_domain` | `str` | The domain of the crawled site (for first/third-party classification) |

**Logic:**
1. For each identifier (skipping those shorter than `MIN_ID_LENGTH`), searches every network request using `_find_value_in_request()`.
2. For each match, classifies the request as first-party or third-party via `_is_same_party()`, checks against tracker lists via `_is_known_tracker()`, and assigns a confidence level via `_calculate_confidence()`.
3. **Deduplication**: Uses a `(value, url, location)` tuple as a key to eliminate duplicate events.
4. **False positive filter**: Removes events where the identifier value is just the site's own domain name (domain self-match).

**Returns:** A deduplicated `list[dict]` of exfiltration events.

---

#### `_find_value_in_request(value: str, request: dict) → str | None`

**Purpose:** Checks if a tracking identifier value appears anywhere in a network request.

**Logic (checked in order):**
1. Raw URL string → returns `"url"`
2. URL-decoded URL → returns `"url_decoded"`
3. POST body (raw) → returns `"post_body"`
4. POST body (URL-decoded) → returns `"post_body_decoded"`
5. Specific headers (`cookie`, `authorization`, `x-client-id`, `x-request-id`) → returns `"header:{name}"`

**Returns:** A string describing the match location, or `None` if not found.

---

#### `_is_same_party(site_domain: str, request_domain: str) → bool`

**Purpose:** Determines if two domains belong to the same party (same registrable domain).

**Logic:** Extracts the last two parts of each domain (e.g., `cdn.example.com` → `example.com`) and compares them. This is a simplified heuristic that doesn't use the Public Suffix List.

---

#### `_is_known_tracker(domain: str) → bool`

**Purpose:** Checks if a domain appears in the combined tracker list (`ALL_TRACKER_DOMAINS`).

**Logic:** Performs exact match and suffix match (e.g., `sub.tracker.com` matches `tracker.com`) against all ~577 tracker domains.

---

#### `_calculate_confidence(identifier, is_third_party, is_known_tracker) → str`

**Purpose:** Assigns a confidence level (`HIGH` / `MEDIUM` / `LOW`) to an exfiltration event using a point-based scoring system.

**Scoring logic:**

| Signal | Points |
|---|---|
| Third-party request | +3 |
| Known tracker domain | +2 |
| High-entropy identifier (≥ 3.0 bits) | +1 |
| UUID v4 or hex string pattern | +1 |
| Tracking key name pattern | +1 |

- **Score ≥ 5** → `HIGH` (e.g., third-party + known tracker + high-entropy)
- **Score ≥ 3** → `MEDIUM` (e.g., third-party + UUID pattern)
- **Score < 3** → `LOW` (e.g., first-party or ambiguous)

---

#### `classify_flow_direction(event: dict) → str`

**Purpose:** Classifies an exfiltration event as an outflow or inflow.

**Logic:** Since the detector captures IDB→network flows by design, all detected exfiltrations are classified as `"outflow"` flows. Inflow flows are detected separately by `detect_integrity_flows()`.

---

#### `classify_confinement(site_domain, request_domain) → str`

**Purpose:** Classifies whether a flow stays within the same origin or crosses origin boundaries.

**Logic:** Extracts the origin (domain without `www.` prefix, lowercased) for both the site and the request. If they match → `"internal"` (confined); otherwise → `"external"` (escaped).

---

#### `classify_cross_origin(site_domain, request_domain) → str`

**Purpose:** For external flows, further classifies as same-site or cross-site.

**Logic:** Uses `_is_same_party()` to check if the two domains share the same registrable domain. Same registrable domain but different origin → `"same_site"`; different registrable domain → `"cross_site"`.

---

#### `_get_origin(domain: str) → str`

**Purpose:** Normalizes a domain to its origin representation by stripping `www.` prefix and lowering case.

---

#### `detect_integrity_flows(site_data: dict) → list[dict]`

**Purpose:** Heuristically detects inflow flows — external data being written into IndexedDB.

**Logic:**
1. Extracts URL query parameter values from the site's URL (only those ≥ 8 chars).
2. Iterates over all IDB databases → stores → records.
3. For each record value, calls `_check_integrity_sources()` to check if the value contains data from external sources.

**Returns:** A `list[dict]` of inflow events, each containing `flow_direction`, `source_class`, `sink_class`, `value`, `path`, etc.

---

#### `_check_integrity_sources(value, path, db_name, store_name, record_key, domain, url_params, results)`

**Purpose:** Recursively checks if an IDB value contains data originating from known external sources.

**Logic:**
1. For string values ≥ 8 chars:
   - Checks if the value contains any URL parameter value → source = `"url_parameter"`
   - Checks if the value contains navigator/browser fingerprint patterns (e.g., `"mozilla"`, `"chrome"`, `"windows nt"`) and is > 20 chars → source = `"navigator_prop"`
2. Recurses into dicts and lists to check nested values.
3. Appends matching events to `results` with `confinement = "internal"` (data is being stored locally).

---

#### `compute_paper_metrics(all_results: list[dict]) → dict`

**Purpose:** Computes all quantitative metrics aligned with the *"What Storage"* paper's analytical framework.

**Logic:**
1. Aggregates all outflow and inflow flows across all analyzed sites.
2. **Table III (Confinement)**: Counts internal vs external flows for both outflow and inflow. Inflow flows are all internal by nature.
3. **Table IV (External Breakdown)**: Counts same-site vs cross-site for external outflow flows.
4. **Tracking Classification**: Counts flows to known tracker domains vs non-tracker domains.
5. **Sink/Source Distribution**: Counts cookie-based vs network-based sinks; URL parameter vs navigator property sources.
6. **Per-database distribution**: Counts flows per IDB database name.

**Returns:** A nested dict with keys: `overview`, `table_iii_confinement`, `table_iv_external_breakdown`, `tracking_classification`, `sink_distribution`, `source_distribution`, `top_databases`.

---

#### `_extract_idb_kv_map(idb_data: dict) → dict`

**Purpose:** Flattens IndexedDB data into a simple key-value map for cross-iteration comparison.

**Logic:** Iterates over all databases → stores → records, building a flat dict with keys like `"dbName/storeName/recordKey"` mapped to the stringified record value.

---

#### `diff_iterations(site_data: dict) → dict`

**Purpose:** Compares IDB records across multiple crawl iterations to identify values that change between visits (strong tracking signal).

**Logic:**
1. Extracts a KV map from each iteration using `_extract_idb_kv_map()`.
2. Takes the union of all keys across iterations.
3. For each key, compares values across iterations:
   - **Key present in only one iteration** → classified as `changed` (unique per session)
   - **Different values across iterations** → classified as `changed` (tracking candidate)
   - **Same value in all iterations** → classified as `static` (likely config/cache)

**Returns:** A dict with `changed_keys` (path → list of values per iteration), `static_keys`, `changed_count`, and `static_count`.

---

#### `analyze_site(site_data: dict) → dict`

**Purpose:** Runs the **full detection pipeline** on a single site's crawled data. This is the core analysis function.

**Logic (5 steps):**
1. **Step 0 — Diff Analysis**: Calls `diff_iterations()` to identify records that changed across crawl iterations.
2. **Step 1 — Identifier Extraction**: Iterates over all IDB records, calling `extract_potential_ids()` on each. Marks each identifier with whether its record changed across iterations. **Key optimization**: If diff data is available, only identifiers from *changed* records are kept — static records are filtered out as likely non-tracking.
3. **Step 2 — Exfiltration Detection**: Calls `find_exfiltrations()` to search all network requests for the extracted identifiers (outflow flows).
4. **Step 3 — Flow Classification**: For each exfiltration event, applies `classify_flow_direction()`, `classify_confinement()`, and `classify_cross_origin()`. Also assigns `sink_class` (cookie, POST body, or URL) and `source_class` (always `IDBObjectStore.get`).
5. **Step 4 — Inflow Detection**: Calls `detect_integrity_flows()` to find external data stored in IDB.

**Returns:** A comprehensive dict with: `domain`, `url`, `indexeddb_summary`, `indexeddb_records`, `network_summary`, `network_requests`, `identifiers_found`, `identifiers`, `exfiltration_events`, `exfiltration_summary`, `inflow_flows`, `flow_classification`, `iteration_diff`.

---

#### `analyze_all_sites(raw_data_dir=None, site_limit=None, only_files=None) → list[dict]`

**Purpose:** Analyzes all crawled site JSON files in the raw data directory.

| Parameter | Type | Description |
|---|---|---|
| `raw_data_dir` | `str \| None` | Directory with crawled JSON files (defaults to `config.RAW_DATA_DIR`) |
| `site_limit` | `int \| None` | Max number of sites to analyze |
| `only_files` | `list[str] \| None` | Specific filenames to analyze (used in full-pipeline mode) |

**Logic:** Lists all `.json` files in the directory (or uses `only_files`), loads each one, and calls `analyze_site()` on it.

**Returns:** A `list[dict]` of per-site analysis results.

---

### `reporter.py` — Report Generator

#### `_print_table(title, headers, rows, col_aligns=None)`

**Purpose:** Prints a formatted ASCII table to the console using numpy for uniform string processing.

**Logic:**
1. Converts all values to strings and creates a numpy array.
2. Calculates column widths as the max string length in each column, plus 2 for padding.
3. Formats each row with alignment: `'l'` (left), `'r'` (right), or `'c'` (center). Headers are always centered.
4. Draws `+---+---+` separators between header and data rows.

---

#### `generate_reports(analysis_results: list[dict])`

**Purpose:** Master function that generates all report formats from analysis results.

**Logic:** Calls five sub-functions in sequence:
1. `_write_summary_json()` — Full structured results
2. `_write_tracking_csv()` — Per-event CSV
3. `compute_paper_metrics()` — Paper-aligned metrics (from `detector.py`)
4. `_write_statistics_json()` — Aggregate statistics JSON
5. `_generate_charts()` — Matplotlib visualizations
6. `_print_console_summary()` — Console tables

---

#### `_write_summary_json(results: list[dict])`

**Purpose:** Writes the full structured analysis results to `summary.json`.

**Logic:** Strips the raw `identifiers` list (which can be very large) from each result to reduce file size, replacing it with just the `identifiers_found` count. Serializes to JSON with pretty-printing.

---

#### `_write_tracking_csv(results: list[dict])`

**Purpose:** Writes one row per flow event (both outflow and inflow) to `tracking_events.csv`.

**Logic:**
- For **outflow flows**: Extracts the IDB key name from the reason string (e.g., `"idb_key:userId"` → `"userId"`), hashes the identifier value with SHA-256 (truncated to 16 chars) for privacy, and populates all 23 CSV columns.
- For **inflow flows**: Uses `"inflow_source"` as the reason and leaves tracking-specific fields empty.

---

#### `_write_statistics_json(results, paper_metrics) → dict`

**Purpose:** Computes aggregate statistics and writes them along with paper metrics to `statistics.json`.

**Logic:** Aggregates across all sites: total databases, records, identifiers, exfiltration counts by confidence level, third-party and known-tracker counts, top tracker domains (Counter.most_common), identifier type distribution, and site-level classification (sites with any exfiltration, sites with HIGH confidence).

**Returns:** The `stats` dict (also used by `_generate_charts` and `_print_console_summary`).

---

#### `_generate_charts(results, stats, paper_metrics)`

**Purpose:** Generates 6 publication-quality matplotlib charts saved as PNG files.

| Chart | Type | Data Source |
|---|---|---|
| `confidence_distribution.png` | Pie chart | `stats["confidence_breakdown"]` |
| `top_trackers.png` | Horizontal bar | `stats["top_tracker_domains"]` (top 10) |
| `confinement_analysis.png` | Pie chart | `paper_metrics["table_iii_confinement"]` |
| `flow_direction.png` | Bar chart | `paper_metrics["overview"]` (outflow vs inflow) |
| `cross_site_breakdown.png` | Pie chart | `paper_metrics["table_iv_external_breakdown"]` |
| `identifier_types.png` | Bar chart | `stats["identifier_type_distribution"]` |

**Logic:** Uses `seaborn-v0_8-whitegrid` style with the `Agg` backend (non-interactive, suitable for headless/server environments). Each chart is only generated if there is data to display. All charts are saved at 150 DPI.

---

#### `_print_console_summary(results, stats, paper_metrics)`

**Purpose:** Prints a comprehensive tabular summary to the console using pandas DataFrames and numpy-backed ASCII tables.

**Logic (output sections):**
1. **Per-site DataFrame**: Builds a pandas DataFrame with columns for IDB DBs, Records, Network Requests, IDs Found, Exfiltrations (by confidence), Inflow flows, and Internal/External counts. Only shows sites with detected flows.
2. **Aggregate statistics**: Computes Total, Mean, Max, and Std for all numeric columns.
3. **IDB Key:Value records**: Displays a table of all extracted IDB records with text wrapping for long values (>60 chars). Also saves as `indexeddb_records.json`.
4. **Network requests**: Shows total captured requests, third-party percentage, and top 15 third-party domains. Saves as `network_requests.csv`.
5. **Confidence breakdown table**: HIGH / MEDIUM / LOW counts.
6. **Top tracker domains table**: Top 10 by event count.
7. **Identifier types table**: Distribution of detection reasons.
8. **Overall classification table**: Site-level statistics.
9. **Paper Table III**: Confinement analysis (Internal vs External × Outflow/Inflow).
10. **Paper Table IV**: External flow breakdown (Same-site vs Cross-site).
11. **Tracking classification table**: Tracking vs Non-tracking for both flow types.
12. **Sink/Source distribution tables**: Where outflow data goes and where inflow data comes from.
13. **Top databases table**: IDB databases ranked by flow count.
14. **Paper metrics summary**: All key percentages from the analytical framework.

---

## References

1. *"What Storage: An Empirical Analysis of Web Storage in the Wild"* — Framework for classifying information flows in web storage APIs
2. *"I Know What You Did Last Summer: New Persistent Tracking Mechanisms in the Wild"* — Analysis of persistent tracking via browser storage
3. **HTTP Archive** — BigQuery dataset used for initial IndexedDB usage analysis
4. **Playwright** — Browser automation library for crawling

---

## License

This project is part of a Final Year Project (FYP) research study. For academic use only.
