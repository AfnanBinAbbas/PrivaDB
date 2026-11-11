<p align="center">
  <img src="Web/public/logo.png" width="200" alt="PrivaDB Logo">
</p>

# PrivaDB: Advanced Privacy Analysis Platform

**PrivaDB** is a high-fidelity, cyber-intelligence engine engineered to detect and analyze stealthy tracking mechanisms in the modern web. Specifically designed for **IndexedDB Taint Tracking**, it identifies how sensitive user identifiers are stored, retrieved, and exfiltrated to non-consensual third-party sinks.

[![Collaborate](https://img.shields.io/badge/Collaborate-GitHub-blue?style=for-the-badge&logo=github)](https://github.com/AfnanBinAbbas/PrivaDB/tree/main)
[![License](https://img.shields.io/badge/License-All%20Rights%20Reserved-red?style=for-the-badge)](LICENSE)

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## Key Intelligence Features

*   **Dual-Engine Pipeline**: Deploy either standard Chrome-based analysis or the custom **Foxhound** (Firefox-based) dynamic taint tracking engine.
*   **Holographic Telemetry**: Real-time visual reporting of global storage trends and exfiltration probabilities.
*   **Atomic Taint Tracking**: Directly monitors data flow at the browser's storage-to-network boundary.
*   **High-Density Dashboard**: Multi-layered analysis of IndexedDB records with responsible tracker identification.

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## Deployment & Execution Guide

### 1. Prerequisites (Prepare Your System)

- **Python 3.10+** (Required for the analysis engine and backend)
- **Node.js 18+ & NPM** (Required for the intelligence dashboard)
- **Git LFS** (Required – the Foxhound binary is stored with Git Large File Storage)
- **Playwright** (Manages browser dependencies)

### 2. Physical Installation

> **IMPORTANT: Complete pull using Git LFS**  
> The Foxhound binary (especially `libxul.so`) is too large for GitHub and is stored via LFS.  
> **If you skip `git lfs pull`, you will get the `invalid ELF header` error when launching a scan.**

```bash
# Clone the repository
git clone https://github.com/AfnanBinAbbas/PrivaDB.git
cd PrivaDB

# *** CRITICAL: Pull all Git LFS objects ***
git lfs pull

# Create and activate a virtual environment (strongly recommended)
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

# Install Python dependencies
pip3 install -r Web/requirements.txt

# Install Playwright browsers (Firefox is needed for Foxhound)
playwright install firefox
# Install Playwright browser binaries
playwright install chromium

# Install Frontend dependencies
cd Web/
npm install
```

### 3. Launch Sequence
PrivaDB operates in two stages. Run these in separate terminal sessions:

#### **Stage A: The Intelligence Backend**
Starts the FastAPI server which manages scan tasks and results.
```bash
cd Web/backend
source ../../venv/bin/activate   # Activate the repository-root virtual environment
python3 server.py
```

#### **Stage B: The Visual Dashboard**
Launches the cinematic UI for interacting with scans.
```bash
cd Web
npm run dev
```
Navigate to `http://localhost:8080` (or the port specified in your terminal).

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## The Investigation Workflow

### **Step 1: Configuration**
Define your target domains in the dashboard. Choose between **Headless** (fast) or **Headed** (visual check) modes. Select your engine: Chrome (Standard) or Foxhound (Detective).

### **Step 2: Execution**
Press **"Start Scan"**. The backend will spin up an isolated browser instance, inject the privacy-hooking scripts, and begin monitoring IndexedDB propagation.

### **Step 3: Intelligence Analysis**
Once complete, results populate the **"Scan Results"** section. 
- **Exfiltrated**: identifier observed inside a network request (substring match, transform-aware match, or a Foxhound taint/hook-verified flow — the `mechanism` field says which).
- **Not observed leaving the browser**: no matching network activity was captured for this identifier during the crawl (this is a measurement result, not a guarantee of safety).
- **Entropy & Category**: Deep analysis of the identifier's uniqueness and purpose.

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## Project Structure

```text
PrivaDB/
├── Documentation.md     # In-depth technical architecture and algorithms
├── README.md            # Execution guide and project overview
├── ATTRIBUTION.md       # Open-source acknowledgements and credits
├── LICENSE              # Proprietary license information
├── References/          # Academic papers and research material
├── third_party/         # Submodules (e.g., Comparative-Privacy-Analysis)
└── Web/                 # Core Monorepo
    ├── backend/         # FastAPI Engine Controller
    │   └── server.py    # Orchestrates scan tasks and results
    ├── foxhound/        # Custom Firefox build (stored with Git LFS)
    ├── public/          # Static assets (logos, 3D graphics)
    ├── requirements.txt # Python dependencies
    └── src/
        ├── components/  # React/Vite UI Dashboard
        └── engine/      # Python Analysis Core (Crawling & Heuristics)
            ├── app_config.py
            ├── crawler.py
            ├── detector.py
            ├── reporter.py
            └── schema.py   # Unified exfiltration-event schema
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## HTML Reports & GRC Compliance (Phase 12)

Every completed scan renders a **standalone, standards-compliant HTML
report** (semantic HTML5, WCAG-oriented tables/skip-link, print styles,
zero JavaScript; per-site reports list every **leaked value in clear**
(clipped to 140 chars + SHA-256:16) next to its **source and sink**
provenance — handle them as sensitive; the bulk report stays
aggregates-only) including
**GRC compliance screening** against GDPR, ePrivacy, CCPA and
ISO/IEC 27001:2022 — each check backed by measured evidence (consent
study, flow data, policy disclosures, response headers).

| Endpoint | Output |
|---|---|
| `GET /scan/{scan_id}/report` | Single-target report (+ auto-generated in background after each scan) |
| `GET /reports` | List of all generated reports (both engines) |
| `GET /reports/{engine}/{name}` | Serve a stored report |
| `GET /reports/bulk` | Executive report across every analysed site (`?live=1` adds per-site header checks) |

Bulk/scale runs write per-site reports plus `bulk_latest.html` into
`results/<Engine>/reports/`. The dashboard links to both
("HTML Report" on the scan view, "HTML Report (GRC)" on results).
Samples: `Web/src/engine/testbed/samples/`.

## Operational Flags

| Variable | Default | Purpose |
|---|---|---|
| `PRIVADB_HOST` | `127.0.0.1` | Backend bind address (`0.0.0.0` in Docker) |
| `PRIVADB_PORT` | `8000` | Backend port |
| `PRIVADB_CORS_ORIGINS` | localhost dashboard origins | Comma-separated allowed origins |
| `PRIVADB_ALLOW_PRIVATE_TARGETS` | unset (guarded) | Set `true` to allow scanning localhost/RFC1918 lab targets (SSRF guard off) |
| `FLOW_HOOKS_ENABLED` | `True` | In-page flow hooks (IDB reads/writes, network sends); `evaluate --no-hooks` turns off |
| `FLOW_WORKER_INJECTION_ENABLED` | `True` | Worker/SharedWorker/SW hook injection (route prelude + blob bootstrap); `evaluate --no-worker-injection` = before-condition |
| `FOXHOUND_BIN` | `foxhound/foxhound` | Custom Firefox build path |
| `DNS_CNAME_CHECKS` | `True` (app_config) | CNAME-cloaking lookups (one `dig` per host, cached) |
| `UID_RELOAD_CHECK` | `True` | Paper §4.1 condition 2: same-session reload pass (iteration 1) for client-identifier confirmation — needs `iterations ≥ 2` for conditions 4/5 |

Scale-campaign CLI flags (`scale.py`): `--max-cpu 50` (CPU governor —
above the cap no NEW simultaneous scan starts; in-flight scans drain,
floor of 1 keeps progress), `--prune-raw` (delete each site's raw crawl
JSON after its analysis is written — needed for 10k-scale disk budgets;
run_meta is embedded in the analysis first, and `detect_only` re-runs
become unavailable for pruned sites), `--list/--sample` (Tranco tiers),
`tranco.py --select-idb <results_dir>` (Stage-B input: sites with IDB
activity).

CI runs byte-compile + backend tests + TypeScript/build on every push
(`.github/workflows/ci.yml`). The measurement suites live in
`Web/src/engine/testbed/` (smoke / consent / storage / scale /
evaluate) and are run before a release — they need browsers and the
Git-LFS Foxhound binary.

## Legal & Intellectual Property
Copyright (c) 2026 Afnan Bin Abbas. **All Rights Reserved.**

This software is the proprietary intelligence of the owner. Unauthorized redistribution, modification, or plagiarism is strictly prohibited. For collaborative inquiries, please use the **Collaborate** gateway in the dashboard.

Full details available in [LICENSE](LICENSE) and [ATTRIBUTION.md](ATTRIBUTION.md).
