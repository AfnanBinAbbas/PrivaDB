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
- [Key Metrics Explained](#key-metrics-explained)
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
5. **Traces** exfiltration of those identifiers via network requests (confidentiality flows)
6. **Detects** external data flowing into IndexedDB (integrity flows)
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
           │ • Raw JSON out │ │ • Integrity  │ │ • Matplotlib     │
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
- **Integrity Flow Detection**: Identifies external data entering IDB
  - Navigator properties (userAgent, platform, etc.) → `IDBObjectStore.put`
  - URL parameter values → `IDBObjectStore.put`
- **Flow Classification** (paper-aligned):
  - Flow direction: confidentiality (IDB→network) vs integrity (external→IDB)
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
| `flow_direction.png` | Bar | Confidentiality vs Integrity flow counts |
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

## Analytical Framework

This project implements the methodology from the *"What Storage"* paper, adapted for IndexedDB:

### Information Flow Types

| Flow Type | Direction | Source | Sink | Description |
|---|---|---|---|---|
| **Confidentiality** | IDB → Network | `IDBObjectStore.get` | `fetch_url` / `xhr_body` / `header_cookie` | Data read from IDB and sent to network |
| **Integrity** | External → IDB | `url_parameter` / `navigator_prop` | `IDBObjectStore.put` | External data written into IDB |

### Paper-Aligned Tables

- **Table III — Confinement Analysis**: Internal vs External × Confidentiality/Integrity
- **Table IV — External Flow Breakdown**: Same-site vs Cross-site with tracking classification

### Confidence Scoring

Each confidentiality flow receives a confidence level:

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
| **Confidentiality flows** | IDB identifiers found in network requests | Data leaving the browser |
| **Integrity flows** | External data (navigator, URLs) found in IDB records | Data entering IDB |
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
- **Navigator-only integrity**: Integrity flow detection currently only catches navigator properties and URL parameters, not network response → IDB flows

---

## References

1. *"What Storage: An Empirical Analysis of Web Storage in the Wild"* — Framework for classifying information flows in web storage APIs
2. *"I Know What You Did Last Summer: New Persistent Tracking Mechanisms in the Wild"* — Analysis of persistent tracking via browser storage
3. **HTTP Archive** — BigQuery dataset used for initial IndexedDB usage analysis
4. **Playwright** — Browser automation library for crawling

---

## License

This project is part of a Final Year Project (FYP) research study. For academic use only.
