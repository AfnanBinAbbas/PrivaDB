import sys
import os
import asyncio
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict
import json
import uuid
import datetime
from urllib.parse import urlparse
from fastapi.middleware.cors import CORSMiddleware
import logging
import re

# Add src/scratch_new to path to import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "scratch_new")))

try:
    from crawler import crawl_all_sites
    from detector import analyze_site
    from reporter import generate_reports
    import config
except ImportError as e:
    print(f"Error importing scratch_new modules: {e}")
    # Fallback/Mock for testing if modules not found
    config = None

app = FastAPI(title="Pixel Perfect Playbook Backend")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging to show logs from this file and imported modules
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    force=True # Override scratch_new basicConfig
)
logger = logging.getLogger("backend")

# In-memory storage for scan status and results
scans = {}
active_tasks: Dict[str, asyncio.Task] = {}

class ScanRequest(BaseModel):
    url: str
    max_pages: Optional[int] = 5
    headless: Optional[bool] = False # Default to False so user can see it on desktop if possible
    crawl_only: Optional[bool] = False
    detect_only: Optional[bool] = False
    engine: Optional[str] = "chrome"

async def run_scan(scan_id: str, url: str, headless: bool = False, crawl_only: bool = False, detect_only: bool = False, engine: str = "chrome"):
    try:
        if config:
            config.HEADLESS = headless
            config.ENGINE = engine
            config.CRAWL_ITERATIONS = 3  # Restoring default iterations for correct detection
            config.CRAWL_ITERATIONS = 3  # Restoring default iterations for correct detection
        
        # Normalize URL: if it doesn't have a protocol, add https://
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            
        crawled_results = None
        analysis_result = None
        domain = urlparse(url).netloc
        
        # 1. Crawl
        if not detect_only:
            scans[scan_id]["status"] = "crawling"
            scans[scan_id]["progress"] = 10
            custom_sites = [{"url": url, "reason": "User requested scan"}]
            crawled_results = await crawl_all_sites(custom_sites=custom_sites)
            scans[scan_id]["progress"] = 50
            if not crawled_results:
                raise Exception("Crawl failed to return results")
            site_data = crawled_results[0]
        else:
            # Load existing crawl data if detect_only
            crawl_file = os.path.join(config.CRAWLED_DIR, f"{domain.replace('.', '_')}.json")
            if not os.path.exists(crawl_file):
                raise Exception(f"Crawl data not found for {domain}. Please run a crawl first.")
            with open(crawl_file, 'r') as f:
                site_data = json.load(f)
            scans[scan_id]["progress"] = 40

        # If it's a crawl-only scan, we're essentially done with the first stage
        if crawl_only:
            scans[scan_id]["status"] = "completed"
            scans[scan_id]["progress"] = 100
            scans[scan_id]["completed_at"] = datetime.datetime.now()
            # Return partial results (DB discovery)
            idb_data = site_data.get("indexeddb", {"databases": []})
            scans[scan_id]["results"] = {
                "url": url,
                "domain": domain,
                "exfiltration_summary": {"total": 0, "high_confidence": 0, "medium_confidence": 0, "low_confidence": 0},
                "stage": "crawl_only"
            }
            return

        # 2. Detect
        scans[scan_id]["status"] = "detecting"
        scans[scan_id]["progress"] = 60
        analysis_result = analyze_site(site_data)
        scans[scan_id]["progress"] = 80
        
        # 3. Report
        scans[scan_id]["status"] = "reporting"
        generate_reports([analysis_result])
        
        # Read the summary from the analysis directory
        summary_path = os.path.join(config.ANALYSIS_DIR, "summary.json")
        with open(summary_path, 'r') as f:
            all_summaries = json.load(f)
            results = next((s for s in all_summaries if s.get("domain") == domain), all_summaries[0])
            
        scans[scan_id]["status"] = "completed"
        scans[scan_id]["progress"] = 100
        scans[scan_id]["completed_at"] = datetime.datetime.now()
        scans[scan_id]["results"] = results
        scans[scan_id]["results"]["stage"] = "full"
        
    except asyncio.CancelledError:
        scans[scan_id]["status"] = "stopped"
        scans[scan_id]["message"] = "Scan terminated by user"
        logger.info(f"Scan {scan_id} was cancelled")
    except Exception as e:
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(e)
        import traceback
        traceback.print_exc()
        logger.error(f"Scan {scan_id} failed: {e}")
    finally:
        active_tasks.pop(scan_id, None)

@app.post("/scan", response_model=Dict)
async def start_scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "scan_id": scan_id,
        "status": "starting",
        "progress": 0,
        "started_at": datetime.datetime.now(),
        "url": request.url,
        "config": {
            "headless": request.headless,
            "crawl_only": request.crawl_only,
            "detect_only": request.detect_only
        }
    }
    
    task = asyncio.create_task(run_scan(
        scan_id, 
        request.url, 
        request.headless, 
        request.crawl_only, 
        request.detect_only,
        request.engine
    ))
    active_tasks[scan_id] = task
    
    return {"scan_id": scan_id}

@app.post("/scan/{scan_id}/stop")
async def stop_scan(scan_id: str):
    if scan_id not in active_tasks:
        if scan_id in scans:
            scans[scan_id]["status"] = "stopped"
            return {"message": "Scan record marked as stopped"}
        raise HTTPException(status_code=404, detail="Active scan not found")
    
    task = active_tasks[scan_id]
    task.cancel()
    return {"message": "Scan stop signal sent"}

@app.post("/scan/all/stop")
async def stop_all_scans():
    count = len(active_tasks)
    for scan_id, task in list(active_tasks.items()):
        task.cancel()
        if scan_id in scans:
            scans[scan_id]["status"] = "stopped"
            scans[scan_id]["message"] = "Scan terminated by global stop command"
    return {"message": f"Stop signal sent to {count} active scans"}

@app.get("/scan/{scan_id}", response_model=Dict)
async def get_scan_status(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]

@app.get("/history", response_model=List[Dict])
async def get_scan_history():
    # Return last 10 scans
    return sorted(scans.values(), key=lambda x: x["started_at"], reverse=True)[:10]

# ── Foxhound Results Endpoints ──────────────────────────────────────
FOXHOUND_RESULTS_BASE = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..",
    "Dynamic_Analysis_scratch", "Comparative-Privacy-Analysis", "results"
))

def _find_latest_foxhound_run() -> Optional[str]:
    """Find the latest foxhound run directory (numeric timestamp)."""
    if not os.path.isdir(FOXHOUND_RESULTS_BASE):
        return None
    runs = [d for d in os.listdir(FOXHOUND_RESULTS_BASE)
            if os.path.isdir(os.path.join(FOXHOUND_RESULTS_BASE, d)) and d.isdigit()]
    if not runs:
        return None
    return os.path.join(FOXHOUND_RESULTS_BASE, sorted(runs, reverse=True)[0])

@app.get("/foxhound/results", response_model=Dict)
async def get_foxhound_results():
    """Return aggregated results from all site .json files in the latest Foxhound run."""
    run_dir = _find_latest_foxhound_run()
    if not run_dir:
        raise HTTPException(status_code=404, detail="No Foxhound results found")
    
    # Check if we should use the existing combined_results.json (if it's complete)
    # or aggregate from individual files (more robust for large datasets).
    # We'll aggregate manually to ensure we pick up all sites.
    combined = {}
    
    # List all files in run_dir
    files = [f for f in os.listdir(run_dir) if f.endswith(".json")]
    
    # Filter for individual site results: exclude known totals/raw files
    site_files = [
        f for f in files 
        if f not in ("combined_results.json", "global_report.json", "sites.json")
        and "+ff1" not in f # Skip raw Foxhound data
    ]
    
    logger.info(f"Aggregating Foxhound results from {len(site_files)} files in {run_dir}")
    
    for f_name in site_files:
        try:
            site_name = f_name.replace(".json", "")
            with open(os.path.join(run_dir, f_name), "r", encoding="utf-8") as f:
                data = json.load(f)
                
                # Filter out entries with irrelevant values
                filtered_data = []
                for entry in data:
                    val = str(entry.get("value", "")).lower()
                    key = str(entry.get("key", "")).lower()
                    
                    # 1. Domain-like pattern
                    if re.search(r'[a-z0-9-]+\.[a-z]{2,}', val):
                        continue
                        
                    # 2. Timezones (e.g. Asia/Karachi, UTC)
                    if re.search(r'^[a-z]+/[a-z_]+$', val) or val.upper() in ["UTC", "GMT", "PST", "EST", "CET", "IST", "JST"]:
                        continue
                    
                    # 3. Dates and Timestamps (Unix or ISO)
                    if len(val) >= 10 and (val.isdigit() or re.search(r'\d{4}-\d{2}-\d{2}', val) or re.search(r'\d{2}/\d{2}/\d{4}', val)):
                        continue
                        
                    # 4. Locations: Latitude and Longitude
                    if re.search(r'^[+-]?\d{1,3}\.\d{4,}$', val) or re.search(r'^-?\d+\.\d+,-?\d+\.\d+$', val.replace(" ", "")):
                        continue
                        
                    # 5. Metadata-based (Location keywords in key)
                    location_keywords = ["location", "latitude", "longitude", "timezone", "tz", "lat", "lng", "coord"]
                    if any(kw in key for kw in location_keywords):
                        continue
                    
                    filtered_data.append(entry)
                
                # Only add if it's not an empty list
                if filtered_data:
                    combined[site_name] = filtered_data
        except Exception as e:
            logger.warning(f"Failed to load Foxhound result for {f_name}: {e}")
            
    if not combined:
        # If no individual files found or they were all empty after filtering
        combined_path = os.path.join(run_dir, "combined_results.json")
        if os.path.isfile(combined_path):
            with open(combined_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                filtered_combined = {}
                for site, entries in data.items():
                    fe = []
                    for e in entries:
                        v = str(e.get("value", "")).lower()
                        k = str(e.get("key", "")).lower()
                        
                        is_domain = re.search(r'[a-z0-9-]+\.[a-z]{2,}', v)
                        is_tz = re.search(r'^[a-z]+/[a-z_]+$', v) or v.upper() in ["UTC", "GMT", "PST", "EST", "CET", "IST", "JST"]
                        is_date = len(v) >= 10 and (v.isdigit() or re.search(r'\d{4}-\d{2}-\d{2}', v) or re.search(r'\d{2}/\d{2}/\d{4}', v))
                        is_loc = re.search(r'^[+-]?\d{1,3}\.\d{4,}$', v) or re.search(r'^-?\d+\.\d+,-?\d+\.\d+$', v.replace(" ", ""))
                        is_meta_loc = any(kw in k for kw in ["location", "latitude", "longitude", "timezone", "tz", "lat", "lng", "coord"])
                        
                        if not (is_domain or is_tz or is_date or is_loc or is_meta_loc):
                            fe.append(e)
                    if fe:
                        filtered_combined[site] = fe
                return filtered_combined
        raise HTTPException(status_code=404, detail="No non-empty Foxhound results found after filtering")
        
    return combined

@app.get("/foxhound/report", response_model=Dict)
async def get_foxhound_report():
    """Return global_report.json from the latest Foxhound run."""
    run_dir = _find_latest_foxhound_run()
    if not run_dir:
        raise HTTPException(status_code=404, detail="No Foxhound results found")
    report_path = os.path.join(run_dir, "global_report.json")
    if not os.path.isfile(report_path):
        raise HTTPException(status_code=404, detail="global_report.json not found")
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)

@app.get("/foxhound/sites", response_model=List[str])
async def get_foxhound_sites():
    """Return list of sites with Foxhound results."""
    data = await get_foxhound_results()
    return sorted(list(data.keys()))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
