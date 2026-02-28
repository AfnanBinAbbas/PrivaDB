# PRIVADB: Empirical Analaysis of  IndexedDB with Dynamic Taint Analysis

**Detecting Persistent Web Tracking via IndexedDB — FYP Research Project**

A three-phase dynamic analysis pipeline that crawls websites, extracts IndexedDB storage data, and detects tracking identifier exfiltration using heuristic taint analysis. Implements the analytical framework from *"What Storage: An Empirical Analysis of Web Storage in the Wild"* adapted specifically for IndexedDB.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Input Formats](#input-formats)
- [Output & Results](#output--results)
- [Glossary & Terminal Output Guide](#glossary--terminal-output-guide)
- [Project Structure](#project-structure)
- [Limitations](#limitations)
- [References](#references)

> [!NOTE]
> Looking for the deep-dive technical details? See [**Documentation.md**](Documentation.md) for detailed information on pipeline phases, the analytical framework, script configurations, BigQuery integration, and a comprehensive function reference.

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
## Limitations

- **Heuristic-based**: Uses pattern matching and string search rather than true dynamic taint tracking (no JS instrumentation)
- **Single page load**: Only analyzes the initial page load; interactive flows (clicks, form submissions) are not captured
- **No Service Worker analysis**: IDB usage by service workers during background sync is not directly captured
- **String matching**: Identifier exfiltration is detected by substring matching, which can produce false positives for short or common strings
- **Navigator-only inflow**: Inflow detection currently only catches navigator properties and URL parameters, not network response → IDB flows

---

## References

1. *"What Storage: An Empirical Analysis of Web Storage in the Wild"* — Framework for classifying information flows in web storage APIs
2. *"I Know What You Did Last Summer: New Persistent Tracking Mechanisms in the Wild"* — Analysis of persistent tracking via browser storage
3. **HTTP Archive** — BigQuery dataset used for initial IndexedDB usage analysis
4. **Playwright** — Browser automation library for crawling

---

## License

This project is part of a Final Year Project (FYP) research study. For academic use only.
