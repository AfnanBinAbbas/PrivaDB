import sys
import os
import asyncio
import warnings
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict
import json
import uuid
import datetime
from urllib.parse import urlparse
from fastapi.middleware.cors import CORSMiddleware
import logging
import re

# Suppress matplotlib 3D projection warning
warnings.filterwarnings("ignore", category=UserWarning, message=".*Axes3D.*")
warnings.filterwarnings("ignore", message=".*3D projection.*")

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

# ─── Health Check & Status Endpoints ──────────────────────────────
@app.get("/health")
async def health_check():
    """Health check endpoint - useful for debugging."""
    return {
        "status": "healthy",
        "service": "PrivaDB Backend",
        "timestamp": datetime.datetime.now().isoformat(),
        "api_version": "1.0"
    }

@app.get("/")
async def root():
    """Root endpoint with API info."""
    return {
        "name": "PrivaDB Backend API",
        "version": "1.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "scan": "/scan",
            "scan_status": "/scan/{scan_id}",
            "scan_history": "/history",
            "scan_results": "/scan/results",
            "foxhound_results": "/foxhound/results",
            "foxhound_report": "/foxhound/report"
        }
    }

# In-memory storage for scan status and results
scans = {}
active_tasks: Dict[str, asyncio.Task] = {}

# Error response models
class ErrorResponse(BaseModel):
    error: str
    detail: str
    status_code: int
    timestamp: str = ""

class ScanRequest(BaseModel):
    url: str
    max_pages: Optional[int] = 5
    headless: Optional[bool] = False # Default to False so user can see it on desktop if possible
    crawl_only: Optional[bool] = False
    detect_only: Optional[bool] = False
    engine: Optional[str] = "chrome"
    
    class Config:
        example = {
            "url": "https://example.com",
            "engine": "chrome",
            "headless": True
        }

# Custom Exceptions
class ScanException(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(message)

class ValidationException(ScanException):
    def __init__(self, message: str):
        super().__init__(message, 400)

class NotFoundError(ScanException):
    def __init__(self, message: str):
        super().__init__(message, 404)

class ProcessingError(ScanException):
    def __init__(self, message: str):
        super().__init__(message, 500)

# Exception handlers
@app.exception_handler(ValidationException)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=400,
        content={
            "error": "Validation Error",
            "detail": exc.message,
            "status_code": 400,
            "timestamp": datetime.datetime.now().isoformat()
        }
    )

@app.exception_handler(NotFoundError)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "detail": exc.message,
            "status_code": 404,
            "timestamp": datetime.datetime.now().isoformat()
        }
    )

@app.exception_handler(ProcessingError)
async def processing_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={
            "error": "Processing Error",
            "detail": exc.message,
            "status_code": 500,
            "timestamp": datetime.datetime.now().isoformat()
        }
    )

async def run_scan(scan_id: str, url: str, headless: bool = False, crawl_only: bool = False, detect_only: bool = False, engine: str = "chrome"):
    try:
        if config:
            logger.info(f"━━━━━━━━ SCAN CONFIG ━━━━━━━━")
            logger.info(f"Engine selected: {engine}")
            logger.info(f"Headless: {headless}")
            logger.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            config.HEADLESS = headless
            config.ENGINE = engine
            logger.info(f"✓ config.ENGINE set to: {config.ENGINE}")
            config.CRAWL_ITERATIONS = 3  # Restoring default iterations for correct detection
            logger.info(f"✓ config.CRAWL_ITERATIONS set to: {config.CRAWL_ITERATIONS}")
        
        # Normalize URL: if it doesn't have a protocol, add https://
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            
        crawled_results = None
        analysis_result = None
        domain = urlparse(url).netloc
        
        # 1. Crawl
        if not detect_only:
            scans[scan_id]["status"] = "crawling"
            engine_name = "Foxhound (Firefox-based)" if engine == "foxhound" else "Chrome"
            scans[scan_id]["message"] = f"Starting crawl with {engine_name}..."
            
            def on_crawl_progress(pct, msg):
                # Map 0-100 to 10-55
                scans[scan_id]["progress"] = int(10 + (pct / 100) * 45)
                scans[scan_id]["message"] = f"[{engine_name}] {msg}"
                
            custom_sites = [{"url": url, "reason": "User requested scan"}]
            crawled_results = await crawl_all_sites(custom_sites=custom_sites, on_progress=on_crawl_progress)
            scans[scan_id]["progress"] = 55
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
            scans[scan_id]["results"] = {
                "url": url,
                "domain": domain,
                "engine": engine,
                "exfiltration_summary": {"total": 0, "high_confidence": 0, "medium_confidence": 0, "low_confidence": 0},
                "stage": "crawl_only"
            }
            return

        # 2. Detect
        scans[scan_id]["status"] = "detecting"
        
        def on_detect_progress(pct, msg):
            # Map 0-100 to 60-85
            scans[scan_id]["progress"] = int(60 + (pct / 100) * 25)
            scans[scan_id]["message"] = msg
            
        analysis_result = analyze_site(site_data) # Note: analyze_site for single site doesn't take callback yet, but let's update analyze_all_sites usage if needed.
        # Actually analyze_site is called here. Let's update it to support callback if we want per-site granularity which is even better.
        # But analyze_site for ONE site is fast. The loops are inside.
        scans[scan_id]["progress"] = 85
        
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
        results["engine"] = engine
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
    try:
        # Validate URL
        if not request.url or len(request.url.strip()) == 0:
            raise ValidationException("URL cannot be empty")
        
        if not request.engine in ["chrome", "foxhound"]:
            raise ValidationException(f"Invalid engine '{request.engine}'. Must be 'chrome' or 'foxhound'")
        
        # Warn if detect_only without existing crawl
        if request.detect_only and not config:
            raise ValidationException("Detection requires crawler modules to be installed")
        
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
            },
            "error": None,
            "message": "Scan queued and starting..."
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
        
        logger.info(f"✓ Scan started: {scan_id} for {request.url}")
        return {"scan_id": scan_id, "message": "Scan started successfully"}
    except ValidationException:
        raise
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        raise ProcessingError(f"Failed to start scan: {str(e)}")

@app.post("/scan/{scan_id}/stop")
async def stop_scan(scan_id: str):
    try:
        if scan_id not in scans:
            raise NotFoundError(f"Scan with ID '{scan_id}' not found")
        
        if scan_id in active_tasks:
            task = active_tasks[scan_id]
            task.cancel()
            logger.info(f"✓ Scan {scan_id} stop signal sent")
        
        scans[scan_id]["status"] = "stopped"
        scans[scan_id]["message"] = "Scan stopped by user"
        return {"message": "Scan stopped successfully", "scan_id": scan_id}
    except NotFoundError:
        raise
    except Exception as e:
        logger.error(f"Error stopping scan {scan_id}: {str(e)}")
        raise ProcessingError(f"Error stopping scan: {str(e)}")

@app.post("/scan/all/stop")
async def stop_all_scans():
    count = len(active_tasks)
    for scan_id, task in list(active_tasks.items()):
        task.cancel()
        if scan_id in scans:
            scans[scan_id]["status"] = "stopped"
            scans[scan_id]["message"] = "Scan terminated by global stop command"
    return {"message": f"Stop signal sent to {count} active scans"}

@app.get("/scan/results", response_model=Dict)
async def get_scan_results():
    """Return aggregated results from all completed scans."""
    try:
        aggregated = {
            "chrome": {},
            "foxhound": {},
            "summary": {"total_scans": 0, "completed_scans": 0, "chrome_scans": 0, "foxhound_scans": 0},
            "last_updated": datetime.datetime.now().isoformat()
        }
        
        # Process Chrome and Foxhound scan results
        for scan_id, scan_data in scans.items():
            if scan_data.get("status") != "completed":
                continue
                
            results = scan_data.get("results", {})
            engine = results.get("engine", "chrome")
            domain = results.get("domain", "unknown")
            
            if domain not in aggregated[engine]:
                aggregated[engine][domain] = []
            
            exfiltrations = []
            # Extract exfiltrated values
            if "exfiltration_events" in results:
                for exfil in results["exfiltration_events"]:
                    value = str(exfil.get("identifier_value", ""))
                    key = str(exfil.get("record_key", "")).lower()
                    if _is_irrelevant_value(value, key):
                        continue
                    exfiltrations.append({
                        "status_code": exfil.get("request_status", 200),
                        "idb_value": value,
                        "tracker_category": "third_party" if exfil.get("is_third_party") else "first_party",
                        "is_exfiltrated": True,
                        "responsible_tracker": exfil.get("request_domain", "unknown"),
                        "database": exfil.get("database", "unknown"),
                        "key": exfil.get("record_key", "unknown"),
                        "entropy": exfil.get("identifier_entropy", 0.0)
                    })
            
            # Include IDB values not exfiltrated
            if "indexeddb_records" in results:
                for record in results["indexeddb_records"]:
                    value = str(record.get("value", ""))
                    key = str(record.get("key", "")).lower()
                    if _is_irrelevant_value(value, key):
                        continue
                    if not any(e["idb_value"] == value and e["key"] == record.get("key") for e in exfiltrations):
                        exfiltrations.append({
                            "status_code": 200,
                            "idb_value": value,
                            "tracker_category": "first_party",
                            "is_exfiltrated": False,
                            "responsible_tracker": "none",
                            "database": record.get("database", "unknown"),
                            "key": record.get("key", "unknown"),
                            "entropy": record.get("entropy", 0.0)
                        })
            
            # Deduplicate
            unique_results = []
            seen_keys = set()
            for item in exfiltrations:
                dedupe_key = (item.get("idb_value", ""), item.get("key", ""), item.get("status_code", 0), item.get("responsible_tracker", ""), item.get("database", ""))
                if dedupe_key not in seen_keys:
                    seen_keys.add(dedupe_key)
                    unique_results.append(item)
            
            aggregated[engine][domain].extend(unique_results)
            aggregated["summary"]["total_scans"] += 1
            aggregated["summary"]["completed_scans"] += 1
            if engine == "chrome":
                aggregated["summary"]["chrome_scans"] += 1
            elif engine == "foxhound":
                aggregated["summary"]["foxhound_scans"] += 1
        
        # Add Foxhound file results
        try:
            foxhound_data = await get_foxhound_results()
            for domain, events in foxhound_data.items():
                if domain not in aggregated["foxhound"]:
                    aggregated["foxhound"][domain] = []
                seen_foxhound = set()
                for event in events:
                    value = str(event.get("value", ""))
                    key = str(event.get("key", "")).lower()
                    if _is_irrelevant_value(value, key):
                        continue
                    foxhound_item = {
                        "status_code": event.get("statusCode", 200),
                        "idb_value": value,
                        "tracker_category": "third_party" if event.get("domain") != domain else "first_party",
                        "is_exfiltrated": True,
                        "responsible_tracker": event.get("domain", "unknown"),
                        "database": event.get("databaseName", "unknown"),
                        "key": event.get("key", "unknown"),
                        "entropy": 0.0
                    }
                    key_tuple = (foxhound_item["idb_value"], foxhound_item["key"], foxhound_item["status_code"], foxhound_item["responsible_tracker"], foxhound_item["database"])
                    if key_tuple not in seen_foxhound:
                        seen_foxhound.add(key_tuple)
                        aggregated["foxhound"][domain].append(foxhound_item)
        except Exception as e:
            logger.warning(f"Could not load Foxhound results: {str(e)}")
        
        if not aggregated["chrome"] and not aggregated["foxhound"]:
            return {**aggregated, "message": "No scan results available yet. Run a scan to generate results."}
        
        return aggregated
    except Exception as e:
        logger.error(f"Error aggregating scan results: {str(e)}")
        raise ProcessingError(f"Error retrieving results: {str(e)}")

@app.get("/scan/{scan_id}", response_model=Dict)
async def get_scan_status(scan_id: str):
    try:
        if scan_id not in scans:
            raise NotFoundError(f"Scan with ID '{scan_id}' not found")
        return scans[scan_id]
    except NotFoundError:
        raise
    except Exception as e:
        logger.error(f"Error fetching scan status for {scan_id}: {str(e)}")
        raise ProcessingError(f"Error retrieving scan status: {str(e)}")

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

def _is_irrelevant_value(value: str, key: str) -> bool:
    """Check if value should be filtered out (dates, locations, etc.)"""
    val_lower = value.lower()
    key_lower = key.lower()
    
    # Domain-like patterns
    if re.search(r'[a-z0-9-]+\.[a-z]{2,}', val_lower):
        return True
    
    # Timezones
    if re.search(r'^[a-z]+/[a-z_]+$', val_lower) or val_lower in ["utc", "gmt", "pst", "est", "cet", "ist", "jst"]:
        return True
    
    # Dates and timestamps
    if len(val_lower) >= 10 and (val_lower.isdigit() or 
                                re.search(r'\d{4}-\d{2}-\d{2}', val_lower) or 
                                re.search(r'\d{2}/\d{2}/\d{4}', val_lower)):
        return True
    
    # Locations: coordinates
    if re.search(r'^[+-]?\d{1,3}\.\d{4,}$', val_lower) or re.search(r'^-?\d+\.\d+,-?\d+\.\d+$', val_lower.replace(" ", "")):
        return True
    
    # Location keywords in key
    location_keywords = ["location", "latitude", "longitude", "timezone", "tz", "lat", "lng", "coord"]
    if any(kw in key_lower for kw in location_keywords):
        return True
    
    return False

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
