import sys
import os
import asyncio
import warnings
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, ConfigDict
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
# Add the backend dir itself so `policy_scanner` resolves regardless of cwd
# (needed when launched as `uvicorn backend.server:app` from the repo root/Docker)
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from policy_scanner.api import router as policy_router
from security import is_public_url

# Configure logging early
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from crawler import crawl_all_sites
    from detector import analyze_site
    from reporter import generate_reports
    import app_config as config
except ImportError as e:
    logger.error(f"Failed to import engine modules: {e}")
    config = None

app = FastAPI(title="PrivaDB Backend")

# CORS: locked to the local dashboard origins by default. Override with
# PRIVADB_CORS_ORIGINS (comma-separated) when serving the UI elsewhere.
_cors_origins = [
    o.strip() for o in os.environ.get(
        "PRIVADB_CORS_ORIGINS",
        "http://localhost:8080,http://127.0.0.1:8080,http://localhost:5173,http://127.0.0.1:5173"
    ).split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Force log configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    force=True
)
logger = logging.getLogger("backend")

# ─── Health Check & Status Endpoints ──────────────────────────────
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "PrivaDB Backend", "timestamp": datetime.datetime.now().isoformat(), "api_version": "1.0"}

@app.get("/")
async def root():
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
            "foxhound_report": "/foxhound/report",
            "scan_html_report": "/scan/{scan_id}/report",
            "reports_list": "/reports",
            "bulk_report": "/reports/bulk?live=1"
        }
    }

# In-memory storage for scan status and results
scans = {}
active_tasks: Dict[str, asyncio.Task] = {}

class ErrorResponse(BaseModel):
    error: str
    detail: str
    status_code: int
    timestamp: str = ""

class ScanRequest(BaseModel):
    url: str
    # Number of fresh-browser crawl iterations per site (was previously
    # silently ignored). None → engine default (3).
    max_pages: Optional[int] = None
    headless: Optional[bool] = False
    crawl_only: Optional[bool] = False
    detect_only: Optional[bool] = False
    engine: Optional[str] = "chrome"
    # Phase 4: run no-interaction/accept/reject conditions instead of
    # plain iterations; results include consent_analysis.
    consent_study: Optional[bool] = False
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "url": "https://example.com",
                "engine": "chrome",
                "headless": True,
                "max_pages": 3,
                "consent_study": False
            }
        }
    )

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
        content={"error": "Validation Error", "detail": exc.message, "status_code": 400, "timestamp": datetime.datetime.now().isoformat()}
    )

@app.exception_handler(NotFoundError)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"error": "Not Found", "detail": exc.message, "status_code": 404, "timestamp": datetime.datetime.now().isoformat()}
    )

@app.exception_handler(ProcessingError)
async def processing_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"error": "Processing Error", "detail": exc.message, "status_code": 500, "timestamp": datetime.datetime.now().isoformat()}
    )


def _finalize_partial(scan_id: str, url: str, engine: str,
                      partial_sink: dict) -> Optional[dict]:
    """Sync: build + persist a partial crawl from the sink (usable
    from cancellation handlers — no awaits allowed here).

    Returns the saved site_data (partial=True) or None when nothing
    usable was collected. Also reaps stray browser processes."""
    iterations = partial_sink.get("iterations") or []
    if not iterations:
        return None
    domain = urlparse(url).netloc
    combined = {
        "url": url,
        "domain": domain,
        "timestamp": partial_sink.get("timestamp")
                     or datetime.datetime.now().isoformat() + "Z",
        "iterations": iterations,
        "partial": True,
        "indexeddb": iterations[0].get("indexeddb",
                                       {"databases": []}),
        "network_requests": iterations[0].get("network_requests", []),
        "run_meta": {
            "engine": engine,
            "headless": bool(scans.get(scan_id, {}).get(
                "config", {}).get("headless")),
            "iterations_completed": len(iterations),
            "captured_at": datetime.datetime.now().isoformat() + "Z",
            "partial": True,
        },
        "errors": ["cancelled by user after "
                   f"{len(iterations)} iteration(s)"],
    }
    for i, it in enumerate(iterations, 1):
        for err in it.get("errors", []):
            combined["errors"].append(f"iter{i}: {err}")

    # reap any browser stragglers synchronously
    try:
        from crawler import _kill_browser_processes
        _kill_browser_processes()
    except Exception:
        pass

    raw_dir = config.RAW_DATA_DIR
    os.makedirs(raw_dir, exist_ok=True)
    safe_domain = domain.replace(".", "_").replace("/", "_")
    path = os.path.join(raw_dir, f"{safe_domain}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2, ensure_ascii=False, default=str)
    if scan_id in scans:
        scans[scan_id]["partial_crawl_path"] = path
    logger.info(
        f"Partial crawl saved -> {path} ({len(iterations)} iteration(s))")
    return combined


async def run_scan(scan_id: str, url: str, headless: bool = False,
                   crawl_only: bool = False, detect_only: bool = False,
                   engine: str = "chrome", iterations: Optional[int] = None,
                   consent_study: bool = False):
    try:
        if config is None:
            raise ProcessingError("Engine modules not properly imported. Check that src/engine is accessible.")
        
        if not hasattr(config, 'set_engine'):
            raise ProcessingError(
                "Config module is missing 'set_engine' function. "
                "Please update your config.py to include the set_engine() method."
            )
        
        logger.info(f"━━━━━━━━ SCAN CONFIG ━━━━━━━━")
        logger.info(f"Engine selected: {engine}")
        logger.info(f"Headless: {headless}")
        logger.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        
        config.set_engine(engine)
        config.HEADLESS = headless
        logger.info(f"✓ config.ENGINE set to: {config.ENGINE}")
        logger.info(f"✓ Results will be saved to: {config.RESULTS_DIR}")
        # Clamp user-supplied iteration count to a sane range
        if iterations is not None:
            config.CRAWL_ITERATIONS = max(1, min(int(iterations), 20))
        else:
            config.CRAWL_ITERATIONS = 3
        logger.info(f"✓ config.CRAWL_ITERATIONS set to: {config.CRAWL_ITERATIONS}")
        
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            
        crawled_results = None
        domain = urlparse(url).netloc
        # Cooperative stop bookkeeping: the crawler mirrors completed
        # iterations here after every iteration, so a cancel can still
        # persist "the current state".
        partial_sink: Dict = {}

        def _stopped() -> bool:
            return bool(scans.get(scan_id, {}).get("stop_requested"))

        if not detect_only:
            if not _stopped():
                scans[scan_id]["status"] = "crawling"
            engine_name = "Foxhound (Firefox-based)" if engine == "foxhound" else "Chrome"
            scans[scan_id]["message"] = f"Starting crawl with {engine_name}..."
            scans[scan_id]["commands"] = {"skip_iteration": False, "skip_domain": False}
            
            def check_command(cmd):
                if scan_id in scans and "commands" in scans[scan_id]:
                    if scans[scan_id]["commands"].get(cmd, False):
                        scans[scan_id]["commands"][cmd] = False
                        return True
                return False
            
            def on_crawl_progress(pct, msg):
                scans[scan_id]["progress"] = int(10 + (pct / 100) * 45)
                scans[scan_id]["message"] = f"[{engine_name}] {msg}"
                
            custom_sites = [{"url": url, "reason": "User requested scan"}]
            crawled_results = await crawl_all_sites(
                custom_sites=custom_sites, 
                on_progress=on_crawl_progress,
                check_command=check_command,
                consent_study=consent_study,
                partial_sink=partial_sink,
            )
            scans[scan_id]["progress"] = 55
            if not crawled_results:
                if _stopped() or partial_sink.get("iterations"):
                    # stopped before any site finished — persist what we have
                    site_data = _finalize_partial(
                        scan_id, url, engine, partial_sink)
                    if site_data is None:
                        if scan_id in scans:
                            scans[scan_id]["status"] = "stopped"
                            scans[scan_id]["message"] = (
                                "Stopped before any data was collected")
                        return
                else:
                    raise Exception("Crawl failed to return results")
            else:
                site_data = crawled_results[0]
        else:
            crawl_file = os.path.join(config.RAW_DATA_DIR, f"{domain.replace('.', '_')}.json")
            if not os.path.exists(crawl_file):
                raise Exception(f"Crawl data not found for {domain}. Please run a crawl first.")
            with open(crawl_file, 'r') as f:
                site_data = json.load(f)
            scans[scan_id]["progress"] = 40

        if crawl_only:
            if _stopped():
                scans[scan_id]["status"] = "stopped"
                scans[scan_id]["message"] = (
                    "Stopped — crawl data saved (crawl-only mode)")
            else:
                scans[scan_id]["status"] = "completed"
            scans[scan_id]["progress"] = 100
            scans[scan_id]["completed_at"] = datetime.datetime.now()
            scans[scan_id]["results"] = {
                "url": url,
                "domain": domain,
                "engine": engine,
                "exfiltration_summary": {"total": 0, "high_confidence": 0, "medium_confidence": 0, "low_confidence": 0},
                "stage": "crawl_only"
            }
            return

        if not _stopped():
            scans[scan_id]["status"] = "detecting"
        analysis_result = analyze_site(site_data)
        scans[scan_id]["progress"] = 85

        if not _stopped():
            scans[scan_id]["status"] = "reporting"
        generate_reports([analysis_result])

        summary_path = os.path.join(config.ANALYSIS_DIR, "summary.json")
        with open(summary_path, 'r') as f:
            all_summaries = json.load(f)
            results = next((s for s in all_summaries if s.get("domain") == domain), all_summaries[0])

        if _stopped() or site_data.get("partial"):
            # Stopped by user: keep the stopped state but attach the
            # analysis of everything collected so far.
            n_iter = len(site_data.get("iterations") or [])
            scans[scan_id]["status"] = "stopped"
            scans[scan_id]["message"] = (
                f"Stopped by user — partial state saved "
                f"({n_iter} crawl iteration(s) analyzed)")
        else:
            scans[scan_id]["status"] = "completed"
            scans[scan_id]["message"] = "Scan completed successfully"
        scans[scan_id]["progress"] = 100
        scans[scan_id]["completed_at"] = datetime.datetime.now()
        results["engine"] = engine
        results["partial"] = bool(site_data.get("partial"))
        scans[scan_id]["results"] = results
        scans[scan_id]["results"]["stage"] = (
            "partial" if site_data.get("partial") else "full")

        # Phase 12: HTML report (standalone + GRC) in the background —
        # pollers already see "completed"; report appears moments later.
        try:
            asyncio.create_task(_bg_generate_report(scan_id))
        except RuntimeError:
            pass
        
    except asyncio.CancelledError:
        # Cancel landed inside the crawl — persist + analyze whatever
        # the partial sink holds, so stopping never loses collected data.
        try:
            site_data = _finalize_partial(scan_id, url, engine,
                                          partial_sink)
            if site_data is not None:
                analysis_result = analyze_site(site_data)
                analysis_result["partial"] = True
                generate_reports([analysis_result])
                summary_path = os.path.join(config.ANALYSIS_DIR,
                                            "summary.json")
                with open(summary_path, 'r') as f:
                    all_summaries = json.load(f)
                results = next(
                    (s for s in all_summaries
                     if s.get("domain") == urlparse(url).netloc),
                    all_summaries[0])
                results["engine"] = engine
                results["partial"] = True
                scans[scan_id]["results"] = results
                scans[scan_id]["results"]["stage"] = "partial"
                scans[scan_id]["progress"] = 100
                n_iter = len(site_data.get("iterations") or [])
                scans[scan_id]["message"] = (
                    f"Stopped by user — partial state saved "
                    f"({n_iter} crawl iteration(s) analyzed)")
                logger.info(
                    f"Scan {scan_id} cancelled — partial results saved "
                    f"({n_iter} iterations)")
            else:
                scans[scan_id]["message"] = (
                    "Stopped by user — no data had been collected yet")
                logger.info(f"Scan {scan_id} cancelled before any data")
        except Exception as save_err:
            logger.error(
                f"Failed to save partial state for {scan_id}: {save_err}")
            if scan_id in scans:
                scans[scan_id]["message"] = (
                    f"Stopped by user (partial save failed: {save_err})")
        finally:
            if scan_id in scans:
                scans[scan_id]["status"] = "stopped"
                scans[scan_id]["completed_at"] = datetime.datetime.now()
            # HTML report for the partial state as well
            try:
                if scan_id in scans and scans[scan_id].get("results"):
                    asyncio.create_task(_bg_generate_report(scan_id))
            except RuntimeError:
                pass
    except Exception as e:
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(e)
        import traceback
        traceback.print_exc()
        logger.error(f"Scan {scan_id} failed: {e}")
    finally:
        active_tasks.pop(scan_id, None)

@app.post("/scan")
async def start_scan(request: ScanRequest):
    try:
        if not request.url or len(request.url.strip()) == 0:
            raise ValidationException("URL cannot be empty")
        # SSRF guard: the crawler and policy fetcher make outbound
        # requests on behalf of API callers — reject private/metadata
        # targets (PRIVADB_ALLOW_PRIVATE_TARGETS=true for lab use).
        probe = request.url if request.url.startswith(
            ("http://", "https://")) else "https://" + request.url
        if not is_public_url(probe):
            raise ValidationException(
                "Target rejected by SSRF guard (private, loopback, "
                "link-local or metadata address). Set "
                "PRIVADB_ALLOW_PRIVATE_TARGETS=true to scan lab targets.")
        if request.engine not in ["chrome", "foxhound"]:
            raise ValidationException(f"Invalid engine '{request.engine}'. Must be 'chrome' or 'foxhound'")
        if request.detect_only and config is None:
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
            scan_id, request.url, request.headless, request.crawl_only, request.detect_only, request.engine,
            iterations=request.max_pages, consent_study=bool(request.consent_study)
        ))
        active_tasks[scan_id] = task
        
        logger.info(f"✓ Scan started: {scan_id} for {request.url}")
        return {"scan_id": scan_id, "message": "Scan started successfully"}
    except ValidationException:
        raise
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        raise ProcessingError(f"Failed to start scan: {str(e)}")

# ========== ADD MISSING ENDPOINTS ==========

@app.post("/scan/{scan_id}/stop")
async def stop_scan(scan_id: str):
    try:
        if scan_id not in scans:
            raise NotFoundError(f"Scan with ID '{scan_id}' not found")
        # Cooperative flag FIRST (run_scan polls it during sync phases
        # where task.cancel() alone cannot take effect), then cancel.
        scans[scan_id]["stop_requested"] = True
        if scan_id in active_tasks:
            task = active_tasks[scan_id]
            task.cancel()
            logger.info(f"✓ Scan {scan_id} stop signal sent")
        scans[scan_id]["status"] = "stopped"
        scans[scan_id]["message"] = "Stopping — saving collected state…"
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
        if scan_id in scans:
            scans[scan_id]["stop_requested"] = True
        if not task.done():
            task.cancel()
            count += 1
        if scan_id in scans:
            scans[scan_id]["status"] = "stopped"
            scans[scan_id]["message"] = (
                "Stopping — saving collected state…")
    logger.info(f"🛑 Global stop signal sent to {count} active tasks")
    return {"message": f"Stop signal sent to {count} active scans"}

@app.get("/scan/results")
async def get_scan_results():
    try:
        aggregated = {
            "chrome": {},
            "foxhound": {},
            "summary": {"total_scans": 0, "completed_scans": 0, "chrome_scans": 0, "foxhound_scans": 0},
            "last_updated": datetime.datetime.now().isoformat()
        }
        
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
    run_dir = _find_latest_run(get_engine_results_base(engine_name))
    if not run_dir:
        return {}
    combined = {}
    files = [f for f in os.listdir(run_dir) if f.endswith(".json")]
    site_files = [f for f in files if f not in ("combined_results.json", "global_report.json", "sites.json", "summary.json", "statistics.json") and "+ff1" not in f]
    for f_name in site_files:
        try:
            site_name = f_name.replace(".json", "").replace("_", ".")
            with open(os.path.join(run_dir, f_name), "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    combined[site_name] = data
                elif isinstance(data, dict):
                    if "exfiltration_events" in data:
                        combined[site_name] = data["exfiltration_events"]
                    else:
                        combined[site_name] = [data]
        except Exception as e:
            logger.warning(f"Failed to load {engine_name} result for {f_name}: {e}")
    return combined

@app.get("/scan/{scan_id}")
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

@app.get("/history")
async def get_scan_history():
    return sorted(scans.values(), key=lambda x: x["started_at"], reverse=True)[:10]

def get_engine_results_base(engine_name: str) -> str:
    return os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "src", "engine", "results", 
        "Chrome" if engine_name.lower() == "chrome" else "Foxhound",
        "analysis"
    ))

def _find_latest_run(results_base: str) -> Optional[str]:
    if not os.path.isdir(results_base):
        return None
    if any(f.endswith(".json") for f in os.listdir(results_base)):
        return results_base
    return None

@app.get("/foxhound/results")
async def get_foxhound_results_endpoint():
    results = await get_engine_results("foxhound")
    if not results:
        return {}
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

@app.get("/foxhound/report")
async def get_foxhound_report():
    run_dir = _find_latest_run(get_engine_results_base("foxhound"))
    if not run_dir:
        raise HTTPException(status_code=404, detail="No Foxhound results found")
    report_path = os.path.join(run_dir, "global_report.json")
    if not os.path.isfile(report_path):
        raise HTTPException(status_code=404, detail="global_report.json not found")
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)

def _is_irrelevant_value(value: str, key: str) -> bool:
    val_lower = value.lower().strip()
    key_lower = key.lower()
    if val_lower in ["undefined", "null", "[object object]", "nan", "none"]:
        return True
    if re.search(r'^[vV]?\d+(\.\d+)+$', val_lower) or re.search(r'^\d+\.\d+$', val_lower):
        if len(val_lower) < 10:
            return True
    if re.search(r'[a-z0-9-]+\.[a-z]{2,}', val_lower):
        return True
    if re.search(r'^[a-z]+/[a-z_]+$', val_lower) or val_lower in ["utc", "gmt", "pst", "est", "cet", "ist", "jst"]:
        return True
    if len(val_lower) >= 10 and (val_lower.isdigit() or re.search(r'\d{4}-\d{2}-\d{2}', val_lower) or re.search(r'\d{2}/\d{2}/\d{4}', val_lower)):
        return True
    if re.search(r'^[+-]?\d{1,3}\.\d{4,}$', val_lower) or re.search(r'^-?\d+\.\d+,-?\d+\.\d+$', val_lower.replace(" ", "")):
        return True
    location_keywords = ["location", "latitude", "longitude", "timezone", "tz", "lat", "lng", "coord"]
    if any(kw in key_lower for kw in location_keywords):
        return True
    return False


# ─── Phase 12: HTML reports + GRC ───────────────────────────────────
def _reports_dir(engine: str) -> str:
    d = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "src", "engine", "results",
        "Chrome" if str(engine).lower() == "chrome" else "Foxhound",
        "reports"))
    os.makedirs(d, exist_ok=True)
    return d


def _crawl_meta(engine: str, domain: str) -> dict:
    """run_meta from the raw crawl file for this domain, if present."""
    raw_dir = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "src", "engine", "results",
        "Chrome" if str(engine).lower() == "chrome" else "Foxhound",
        "crawled"))
    path = os.path.join(raw_dir, f"{domain.replace('.', '_')}.json")
    try:
        with open(path, encoding="utf-8") as f:
            return (json.load(f).get("run_meta") or {})
    except Exception:
        return {}


def _build_scan_report(scan_id: str) -> str:
    """Blocking: render + write the standalone HTML for one scan.
    Returns the file path."""
    import grc as grc_mod
    import report_html

    rec = scans[scan_id]
    if rec.get("report_path") and os.path.exists(rec["report_path"]):
        return rec["report_path"]
    url = rec.get("url") or ""
    analysis = rec.get("results") or {}
    engine = analysis.get("engine") or (
        rec.get("config", {}) or {}).get("engine") or "chrome"
    domain = urlparse(url).netloc or url

    header_info = grc_mod.fetch_headers(url)
    policy_info = grc_mod.load_policy_info(url)
    grc_report = grc_mod.run_grc_checks(
        analysis, url, policy_info=policy_info,
        header_info=header_info)

    sources = []
    raw_path = os.path.join(
        os.path.dirname(_reports_dir(engine)), "crawled",
        f"{domain.replace('.', '_')}.json")
    if os.path.exists(raw_path):
        sources.append(os.path.relpath(raw_path, os.path.dirname(
            os.path.dirname(_reports_dir(engine)))))
    sources.append(f"in-memory scan record {scan_id}")

    html_doc = report_html.render_scan_report(
        analysis, url, grc_report,
        run_meta=_crawl_meta(engine, domain),
        scan_meta={"started_at": str(rec.get("started_at", "")),
                   "status": rec.get("status", "")},
        sources=sources)

    safe = re.sub(r"[^A-Za-z0-9._-]", "_", domain)[:60] or "target"
    out = os.path.join(_reports_dir(engine),
                       f"{safe}_{scan_id[:8]}.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html_doc)
    rec["report_path"] = out
    rec["grc_summary"] = grc_report.get("summary")
    rec["grc_risk_score"] = (grc_report.get("summary") or {}).get(
        "risk_score")
    logger.info(f"  HTML report → {out}")
    return out


async def _bg_generate_report(scan_id: str):
    try:
        await asyncio.to_thread(_build_scan_report, scan_id)
    except Exception as e:
        logger.warning(f"HTML report generation failed for "
                       f"{scan_id}: {e}")


@app.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    """Standalone HTML report (Phase 12) for one scan."""
    if scan_id not in scans:
        raise NotFoundError(f"Scan with ID '{scan_id}' not found")
    rec = scans[scan_id]
    path = rec.get("report_path")
    if not path or not os.path.exists(path):
        if rec.get("status") != "completed":
            raise ProcessingError(
                "Report not ready — scan has not completed yet.")
        try:
            path = await asyncio.to_thread(_build_scan_report, scan_id)
        except Exception as e:
            raise ProcessingError(f"Report generation failed: {e}")
    return FileResponse(path, media_type="text/html; charset=utf-8",
                        filename=os.path.basename(path))


@app.get("/reports")
async def list_reports():
    """All generated HTML reports (both engines)."""
    out = []
    for engine in ("chrome", "foxhound"):
        d = _reports_dir(engine)
        for name in sorted(os.listdir(d)):
            if not name.endswith(".html"):
                continue
            full = os.path.join(d, name)
            out.append({
                "engine": engine, "name": name,
                "bytes": os.path.getsize(full),
                "generated_at": datetime.datetime.fromtimestamp(
                    os.path.getmtime(full)).isoformat(),
                "url": f"/reports/{engine}/{name}",
            })
    return {"reports": out}


@app.get("/reports/{engine}/{name}")
async def serve_report(engine: str, name: str):
    if engine not in ("chrome", "foxhound"):
        raise NotFoundError("Unknown engine for reports")
    safe = os.path.basename(name)  # no traversal
    path = os.path.join(_reports_dir(engine), safe)
    if not os.path.exists(path):
        raise NotFoundError(f"Report '{safe}' not found")
    return FileResponse(path, media_type="text/html; charset=utf-8")


@app.get("/reports/bulk")
async def bulk_report(live: int = 0):
    """Executive HTML over every analysed site (both engines).

    live=1 adds per-site response-header checks (slow: one fetch per
    site, capped at 40). Policy fetch stays off for bulk runs.
    """
    import grc as grc_mod
    import report_html

    sites = []
    for engine in ("chrome", "foxhound"):
        summary = os.path.join(get_engine_results_base(engine),
                               "summary.json")
        if not os.path.exists(summary):
            continue
        try:
            with open(summary, encoding="utf-8") as f:
                entries = json.load(f)
        except Exception:
            continue
        for entry in entries if isinstance(entries, list) else []:
            domain = entry.get("domain") or entry.get("url") or "?"
            url = entry.get("url") or f"https://{domain}"
            headers = None
            if live and len(sites) < 40:
                headers = grc_mod.fetch_headers(url, timeout=5.0)
            grc_report = grc_mod.run_grc_checks(
                entry, url, policy_info=None, header_info=headers)
            sites.append({"domain": domain, "url": url,
                          "engine": engine, "analysis": entry,
                          "grc": grc_report,
                          "run_meta": _crawl_meta(engine, domain)})
    if not sites:
        raise ProcessingError(
            "No analysed sites available for a bulk report yet.")

    html_doc = report_html.render_bulk_report(sites)
    out = os.path.join(_reports_dir("chrome"),
                       "bulk_latest_live.html" if live
                       else "bulk_latest.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return FileResponse(out, media_type="text/html; charset=utf-8",
                        filename=os.path.basename(out))


app.include_router(policy_router, prefix="/api/v1")

if __name__ == "__main__":
    import uvicorn
    # Bind to loopback only — this server can launch browsers and fetch
    # arbitrary URLs, so it must not be reachable from the network.
    # Docker sets PRIVADB_HOST=0.0.0.0 inside the container.
    host = os.environ.get("PRIVADB_HOST", "127.0.0.1")
    port = int(os.environ.get("PRIVADB_PORT", "8000"))
    try:
        logger.info(f"Starting PrivaDB Backend on http://{host}:{port}")
        uvicorn.run(app, host=host, port=port, log_level="info")
    except OSError as e:
        if e.errno == 98:
            logger.error("❌ Port 8000 is already in use. Please stop the other process or use a different port.")
            sys.exit(1)
        else:
            raise
    except Exception as e:
        logger.error(f"❌ Critical error during startup: {e}")
        sys.exit(1)
