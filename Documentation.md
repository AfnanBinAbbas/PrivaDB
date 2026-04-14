# PrivaDB: Technical Documentation

This document provides a deep-dive into the technical architecture, detection algorithms, and analytical framework used by the PrivaDB Privacy Analysis Engine.

## 🏗️ Architecture Overview

PrivaDB consists of three main components:
1.  **Frontend Dashboard**: A modern React/Vite interface for monitoring scans and viewing results.
2.  **Backend API**: A FastAPI-based server that orchestrates the analysis pipeline and serves reports.
3.  **Analysis Engine**: A Python-based core (located in `Web/src/engine`) that manages crawling and tracking detection.

## 🔬 Detection Algorithms

### 1. IndexedDB Extraction
The engine injects an asynchronous JavaScript payload into each target page to:
- Enumerate all `indexedDB` databases.
- Read every object store and record using a `readonly` transaction.
- Filter out common system entries and cap records at 200 per store to prevent memory bloat.

### 2. Taint Tracking Heuristics
Since PrivaDB performs heuristic-based analysis, it uses several layers of detection:
- **Identifier Extraction**: Recursively walks IDB records to find strings ≥ 8 chars that match specific patterns (UUID, Hex, Base64).
- **Shannon Entropy**: Calculates randomness of strings. Values ≥ 3.0 bits are flagged as potential high-entropy identifiers.
- **Exfiltration Detection**: Searches for extracted identifiers within all captured network requests (URL parameters, POST bodies, and Cookie headers).

### 3. Flow Classification
Each detected event is classified based on the *"What Storage"* research paper:
- **Direction**: Outflow (IDB → Network) vs. Inflow (External → IDB).
- **Confinement**: Internal (same-site) vs. External (cross-site).
- **Confidence**: High, Medium, or Low based on tracker domain matching and entropy.

## ⚙️ Configuration

Tuneable parameters are located in `Web/src/engine/config.py`:
- `MIN_ID_LENGTH`: Minimum string length to flag as potential ID (Default: 8).
- `ENTROPY_THRESHOLD`: Shannon entropy threshold (Default: 3.0).
- `PAGE_TIMEOUT_MS`: Timeout for page loads (Default: 30000).

## 🛡️ Tracker Lists
The system automatically merges multiple tracker blacklists, providing a combined set of over **570+ unique tracker domains** for high-precision detection.

## 📜 Paper References
The analytical methodology is inspired by and aligned with:
- *"What Storage? An Empirical Analysis of Persistent Web Tracking Revisited"* (eleumasc et al.)
- *"Foxhound: Peer-to-peer Taint Tracking in the Browser"* (SAP SE)
