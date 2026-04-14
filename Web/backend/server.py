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

# Add src/engine to path to import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "engine")))

try:
    from crawler import crawl_all_sites
    from detector import analyze_site
    from reporter import generate_reports
    import config
except ImportError as e:
    logger.error(f"Failed to import engine modules: {e}")
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
            
            # Use the new dynamic engine setter to isolate results
            config.set_engine(engine)
            config.HEADLESS = headless
            logger.info(f"✓ config.ENGINE set to: {config.ENGINE}")
            logger.info(f"✓ Results will be saved to: {config.RESULTS_DIR}")
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
            
            # Setup command checks for granular skipping
            scans[scan_id]["commands"] = {"skip_iteration": False, "skip_domain": False}
            
            def check_command(cmd):
                # If globally stopped, crawler's task.cancelled() will catch it
                # Here we only check granular commands
                if scan_id in scans and "commands" in scans[scan_id]:
                    if scans[scan_id]["commands"].get(cmd, False):
                        scans[scan_id]["commands"][cmd] = False # Reset flag after consumption
                        return True
                return False
            
            def on_crawl_progress(pct, msg):
                # Map 0-100 to 10-55
                scans[scan_id]["progress"] = int(10 + (pct / 100) * 45)
                scans[scan_id]["message"] = f"[{engine_name}] {msg}"
                
            custom_sites = [{"url": url, "reason": "User requested scan"}]
            crawled_results = await crawl_all_sites(
                custom_sites=custom_sites, 
                on_progress=on_crawl_progress,
                check_command=check_command
            )
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
        # Set status immediately so polling returns the correct state
        if scan_id in scans:
            scans[scan_id]["status"] = "stopped"
            scans[scan_id]["message"] = "Scan terminated by user"
        logger.info(f"Scan {scan_id} was successfully cancelled")
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

@app.post("/scan/{scan_id}/skip_iteration")
async def skip_iteration(scan_id: str):
    if scan_id in scans and "commands" in scans[scan_id]:
        scans[scan_id]["commands"]["skip_iteration"] = True
        logger.info(f"⏭ Skip Iteration signal sent for {scan_id}")
        return {"message": "Skip iteration signal sent", "scan_id": scan_id}
    raise NotFoundError(f"Scan with ID '{scan_id}' not found")

@app.post("/scan/{scan_id}/skip_domain")
async def skip_domain(scan_id: str):
    if scan_id in scans and "commands" in scans[scan_id]:
        scans[scan_id]["commands"]["skip_domain"] = True
        logger.info(f"⏭ Skip Domain signal sent for {scan_id}")
        return {"message": "Skip domain signal sent", "scan_id": scan_id}
    raise NotFoundError(f"Scan with ID '{scan_id}' not found")

@app.post("/scan/all/stop")
async def stop_all_scans():
    count = 0
    for scan_id, task in list(active_tasks.items()):
        if not task.done():
            task.cancel()
            count += 1
        if scan_id in scans:
            scans[scan_id]["status"] = "stopped"
            scans[scan_id]["message"] = "Scan terminated by global stop command"
    
    logger.info(f"🛑 Global stop signal sent to {count} active tasks")
    return {"message": f"Stop signal sent to {count} active scans"}

@app.get("/scan/results", response_model=Dict)
async def get_scan_results():
    """Return aggregated results from all completed scans in both engine silos."""
    try:
        aggregated = {
            "chrome": {},
            "foxhound": {},
            "summary": {"total_scans": 0, "completed_scans": 0, "chrome_scans": 0, "foxhound_scans": 0},
            "last_updated": datetime.datetime.now().isoformat()
        }
        
        # 1. Add results from both engines by querying their dedicated directories
        for engine_type in ["chrome", "foxhound"]:
            try:
                engine_data = await get_engine_results(engine_type)
                for domain, events in engine_data.items():
                    if domain not in aggregated[engine_type]:
                        aggregated[engine_type][domain] = []
                    
                    for event in events:
                        value = str(event.get("value", "") or event.get("idb_value", ""))
                        key = str(event.get("key", "")).lower()
                        if _is_irrelevant_value(value, key):
                            continue
                            
                        # Standardize format for dashboard
                        standardized = {
                            "status_code": event.get("statusCode", event.get("status_code", 200)),
                            "idb_value": value,
                            "tracker_category": "third_party" if (event.get("domain") != domain and event.get("responsible_tracker", "none") != "none") else "first_party",
                            "is_exfiltrated": event.get("is_exfiltrated", True),
                            "responsible_tracker": event.get("domain", event.get("responsible_tracker", "unknown")),
                            "database": event.get("databaseName", event.get("database", "unknown")),
                            "key": event.get("key", "unknown"),
                            "entropy": event.get("entropy", 0.0)
                        }
                        aggregated[engine_type][domain].append(standardized)
                        
                    aggregated["summary"]["total_scans"] += 1
                    aggregated["summary"]["completed_scans"] += 1
                    aggregated["summary"][f"{engine_type}_scans"] += 1
            except Exception as e:
                logger.warning(f"Could not load {engine_type} results: {str(e)}")
        
        if not aggregated["chrome"] and not aggregated["foxhound"]:
            return {**aggregated, "message": "No scan results available yet. Run a scan to generate results."}
        
        return aggregated
    except Exception as e:
        logger.error(f"Error aggregating scan results: {str(e)}")
        raise ProcessingError(f"Error retrieving results: {str(e)}")

async def get_engine_results(engine_name: str) -> Dict:
    """Helper to aggregate results from a specific dynamic engine silo directory."""
    run_dir = _find_latest_run(get_engine_results_base(engine_name))
    if not run_dir:
        return {}
        
    combined = {}
    files = [f for f in os.listdir(run_dir) if f.endswith(".json")]
    site_files = [
        f for f in files 
        if f not in ("combined_results.json", "global_report.json", "sites.json", "summary.json", "statistics.json")
        and "+ff1" not in f
    ]
    
    for f_name in site_files:
        try:
            site_name = f_name.replace(".json", "").replace("_", ".")
            with open(os.path.join(run_dir, f_name), "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    combined[site_name] = data
                elif isinstance(data, dict):
                    # Handle different result structures dynamically
                    if "exfiltration_events" in data:
                        combined[site_name] = data["exfiltration_events"]
                    else:
                        combined[site_name] = [data]
        except Exception as e:
            logger.warning(f"Failed to load {engine_name} result for {f_name}: {e}")
            
    return combined

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
def get_engine_results_base(engine_name: str) -> str:
    """Dynamically resolve results base without hardcoding."""
    return os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "src", "engine", "results", 
        "Chrome" if engine_name.lower() == "chrome" else "Foxhound",
        "analysis"
    ))

def _find_latest_run(results_base: str) -> Optional[str]:
    """Find the latest run directory in a results base."""
    if not os.path.isdir(results_base):
        return None
    
    # Check for site JSONs directly (flat structure)
    if any(f.endswith(".json") for f in os.listdir(results_base)):
        return results_base
        
    return None

@app.get("/foxhound/results", response_model=Dict)
async def get_foxhound_results_endpoint():
    """Return aggregated results from the Foxhound engine silo."""
    results = await get_engine_results("foxhound")
    if not results:
        return {} # Return empty dict instead of 404 to avoid frontend errors
    
    # Apply filtering for the endpoint specific view if needed
    filtered_results = {}
    for domain, events in results.items():
        fe = []
        for event in events:
            value = str(event.get("value", "") or event.get("idb_value", ""))
            key = str(event.get("key", "")).lower()
            if not _is_irrelevant_value(value, key):
                fe.append(event)
        if fe:
            filtered_results[domain] = fe
            
    return filtered_results

@app.get("/foxhound/report", response_model=Dict)
async def get_foxhound_report():
    """Return global_report.json from the latest Foxhound run."""
    run_dir = _find_latest_run(get_engine_results_base("foxhound"))
    if not run_dir:
        raise HTTPException(status_code=404, detail="No Foxhound results found")
    report_path = os.path.join(run_dir, "global_report.json")
    if not os.path.isfile(report_path):
        raise HTTPException(status_code=404, detail="global_report.json not found")
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)

def _is_irrelevant_value(value: str, key: str) -> bool:
    """Check if value should be filtered out (dates, locations, undefined, versions, etc.)"""
    val_lower = value.lower().strip()
    key_lower = key.lower()
    
    # Filter out common placeholders and noise
    if val_lower in ["undefined", "null", "[object object]", "nan", "none"]:
        return True
        
    # Version numbers (e.g., 1.2.3, v5.0.1, 15.0)
    if re.search(r'^[vV]?\d+(\.\d+)+$', val_lower) or re.search(r'^\d+\.\d+$', val_lower):
        if len(val_lower) < 10: # Long digit strings might be IDs
            return True

    # Domain-like patterns in values (often just noisy URLs or scripts)
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
    import sys
    
    try:
        logger.info("Starting PrivaDB Backend on http://0.0.0.0:8000")
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
    except OSError as e:
        if e.errno == 98:
            logger.error("❌ Port 8000 is already in use. Please stop the other process or use a different port.")
            sys.exit(1)
        else:
            raise
    except Exception as e:
        logger.error(f"❌ Critical error during startup: {e}")
        sys.exit(1)
