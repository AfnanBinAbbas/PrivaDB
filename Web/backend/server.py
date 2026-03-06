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
    headless: Optional[bool] = False # Default to False so user sees the browser
    crawl_only: Optional[bool] = False
    detect_only: Optional[bool] = False

async def run_scan(scan_id: str, url: str, headless: bool = False, crawl_only: bool = False, detect_only: bool = False):
    try:
        if config:
            config.HEADLESS = headless
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
                "indexeddb_summary": {
                    "database_count": len(idb_data.get("databases", [])),
                    "total_records": sum(s.get("recordCount", 0) for d in idb_data.get("databases", []) for s in d.get("stores", []))
                },
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
        request.detect_only
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

@app.get("/scan/{scan_id}", response_model=Dict)
async def get_scan_status(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]

@app.get("/history", response_model=List[Dict])
async def get_scan_history():
    # Return last 10 scans
    return sorted(scans.values(), key=lambda x: x["started_at"], reverse=True)[:10]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
