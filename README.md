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
Ensure you have the following installed before proceeding:
- **Python 3.10+** (Required for the analysis engine and backend)
- **Node.js 18+ & NPM** (Required for the intelligence dashboard)
- **Foxhound Submodule**: Ensure submodules are initialized for the Firefox engine.
- **Chrome Playwright**: For standard Chromium-based analysis.

### 2. Physical Installation
```bash
# Clone the repository
git clone https://github.com/AfnanBinAbbas/PrivaDB.git
cd PrivaDB

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browser binaries
playwright install chromium

# Install Frontend dependencies
cd Web
npm install
```

### 3. Launch Sequence
PrivaDB operates in two stages. Run these in separate terminal sessions:

#### **Stage A: The Intelligence Backend**
Starts the FastAPI server which manages scan tasks and results.
```bash
cd Web/backend
python server.py
```

#### **Stage B: The Visual Dashboard**
Launches the cinematic UI for interacting with scans.
```bash
cd Web
npm run dev
```
Navigate to `http://localhost:8081` (or the port specified in your terminal).

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## The Investigation Workflow

### **Step 1: Configuration**
Define your target domains in the dashboard. Choose between **Headless** (fast) or **Headed** (visual check) modes. Select your engine: Chrome (Standard) or Foxhound (Detective).

### **Step 2: Execution**
Press **"Start Scan"**. The backend will spin up an isolated browser instance, inject the privacy-hooking scripts, and begin monitoring IndexedDB propagation.

### **Step 3: Intelligence Analysis**
Once complete, results populate the **"Scan Results"** section. 
- **Exfiltrated**: Data that successfully reached a third-party server.
- **Safe**: Data accessed but restricted by browser or project policy.
- **Entropy & Category**: Deep analysis of the identifier's uniqueness and purpose.

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## Legal & Intellectual Property
Copyright (c) 2026 Afnan Bin Abbas. **All Rights Reserved.**

This software is the proprietary intelligence of the owner. Unauthorized redistribution, modification, or plagiarism is strictly prohibited. For collaborative inquiries, please use the **Collaborate** gateway in the dashboard.

Full details available in [LICENSE](LICENSE) and [ATTRIBUTION.md](ATTRIBUTION.md).
