"""
Playwright-based automated website crawler for IndexedDB analysis.

Visits target websites, extracts all IndexedDB data, and captures
network requests for downstream tracking detection.
"""

import asyncio
import json
import os
import logging
from urllib.parse import urlparse
from datetime import datetime

from playwright.async_api import async_playwright

import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ─── IndexedDB Extraction Script ────────────────────────────────────
# Injected into the page context via page.evaluate()
EXTRACT_INDEXEDDB_SCRIPT = """
async () => {
    const result = { databases: [] };

    try {
        // Get list of all databases
        const dbList = await window.indexedDB.databases();

        for (const dbInfo of dbList) {
            const dbName = dbInfo.name;
            const dbVersion = dbInfo.version;
            const dbData = {
                name: dbName,
                version: dbVersion,
                stores: []
            };

            try {
                const db = await new Promise((resolve, reject) => {
                    const req = window.indexedDB.open(dbName);
                    req.onsuccess = (e) => resolve(e.target.result);
                    req.onerror = (e) => reject(e.target.error);
                    req.onupgradeneeded = (e) => {
                        e.target.result.close();
                        resolve(null);
                    };
                });

                if (!db) continue;

                const storeNames = Array.from(db.objectStoreNames);

                for (const storeName of storeNames) {
                    try {
                        const records = await new Promise((resolve, reject) => {
                            const tx = db.transaction([storeName], 'readonly');
                            const store = tx.objectStore(storeName);
                            const req = store.getAll();
                            const keyReq = store.getAllKeys();
                            let values = [];
                            let keys = [];

                            req.onsuccess = () => { values = req.result; };
                            keyReq.onsuccess = () => { keys = keyReq.result; };

                            tx.oncomplete = () => {
                                const keyPath = store.keyPath;
                                const entries = keys.map((k, i) => {
                                    let val = values[i];
                                    // Unwrap: if value is {key/k: X, value: Y},
                                    // extract Y as the actual value
                                    if (val && typeof val === 'object' && !Array.isArray(val)) {
                                        if ('value' in val && ('k' in val || 'key' in val)) {
                                            val = val.value;
                                        } else if (keyPath && keyPath in val) {
                                            // Remove inline keyPath to avoid redundancy
                                            val = Object.assign({}, val);
                                            delete val[keyPath];
                                        }
                                    }
                                    return { key: k, value: val };
                                });
                                resolve(entries);
                            };
                            tx.onerror = () => reject(tx.error);
                        });

                        dbData.stores.push({
                            name: storeName,
                            recordCount: records.length,
                            records: records.slice(0, 200)  // Cap per store
                        });
                    } catch (storeErr) {
                        dbData.stores.push({
                            name: storeName,
                            error: String(storeErr)
                        });
                    }
                }

                db.close();
            } catch (dbErr) {
                dbData.error = String(dbErr);
            }

            result.databases.push(dbData);
        }
    } catch (topErr) {
        result.error = String(topErr);
    }

    return result;
}
"""


class SiteCrawler:
    """Crawls a single website — extracts IndexedDB data and network requests."""

    def __init__(self):
        self.network_requests = []

    async def crawl_site(self, browser, url: str) -> dict:
        """
        Visit a URL, extract IndexedDB data and captured network requests.

        Returns a dict with keys: url, domain, timestamp, indexeddb, network_requests
        """
        domain = urlparse(url).netloc
        logger.info(f"▶ Crawling: {url}")

        context = await browser.new_context(
            user_agent=config.USER_AGENT,
            ignore_https_errors=True,
        )
        page = await context.new_page()
        self.network_requests = []

        # ── Attach network listeners ────────────────────────────────
        page.on("request", self._on_request)
        page.on("response", self._on_response)

        result = {
            "url": url,
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "indexeddb": {"databases": []},
            "network_requests": [],
            "errors": [],
        }

        try:
            # Navigate
            await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=config.NAVIGATION_TIMEOUT,
            )
            logger.info(f"  Page loaded, scrolling and waiting {config.IDLE_WAIT}ms...")
            
            # Simple scroll-to-bottom to trigger lazy-loaded scripts/trackers
            try:
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await asyncio.sleep(1)
                await page.evaluate("window.scrollTo(0, 0)")
            except:
                pass

            await page.wait_for_timeout(config.IDLE_WAIT)

            # Extract IndexedDB from ALL frames (main + iframes)
            try:
                all_idb_data = {"databases": []}
                frames = page.frames
                logger.info(f"  Extracting IndexedDB from {len(frames)} frames…")
                
                for i, frame in enumerate(frames):
                    try:
                        # Skip iframes that we can't access (cross-origin without permission)
                        # but evaluate handles it if we use try/except
                        frame_idb = await frame.evaluate(EXTRACT_INDEXEDDB_SCRIPT)
                        if frame_idb and frame_idb.get("databases"):
                            for db in frame_idb["databases"]:
                                # Add frame info to the database record
                                db["frame_url"] = frame.url
                                db["is_main_frame"] = (frame == page.main_frame)
                                all_idb_data["databases"].append(db)
                    except Exception as fe:
                        # Some frames might be cross-origin and block evaluation
                        continue

                result["indexeddb"] = all_idb_data
                db_count = len(all_idb_data.get("databases", []))
                total_records = sum(
                    s.get("recordCount", 0)
                    for d in all_idb_data.get("databases", [])
                    for s in d.get("stores", [])
                )
                logger.info(
                    f"  Extraction complete: {db_count} databases, "
                    f"{total_records} total records across all frames"
                )
            except Exception as e:
                error_msg = f"IndexedDB extraction failed: {str(e)}"
                logger.error(f"  {error_msg}")
                result["indexeddb"] = {"databases": [], "error": error_msg}
                result["errors"].append(error_msg)

        except Exception as e:
            err_msg = f"Navigation error: {e}"
            logger.warning(f"  {err_msg}")
            result["errors"].append(err_msg)

        # Attach captured network data
        result["network_requests"] = self.network_requests
        logger.info(f"  Network: {len(self.network_requests)} requests captured")

        await context.close()
        return result

    def _on_request(self, request):
        """Capture outgoing request details."""
        try:
            entry = {
                "url": request.url,
                "method": request.method,
                "resource_type": request.resource_type,
                "headers": dict(request.headers) if request.headers else {},
                "post_data": None,
                "response": None,
            }
            # Capture POST body
            if request.method in ("POST", "PUT", "PATCH"):
                try:
                    entry["post_data"] = request.post_data
                except Exception:
                    pass
            self.network_requests.append(entry)
        except Exception:
            pass

    def _on_response(self, response):
        """Attach response status to the matching request entry."""
        try:
            url = response.url
            status = response.status
            for req in reversed(self.network_requests):
                if req["url"] == url and req["response"] is None:
                    req["response"] = {"status": status}
                    break
        except Exception:
            pass


from typing import List, Dict, Optional, Callable

async def crawl_all_sites(site_limit: int = None,
                          custom_sites: List[dict] = None,
                          on_progress: Optional[Callable[[float, str], None]] = None) -> List[dict]:
    """
    Crawl all sites and save per-site JSON output.

    Each site is crawled config.CRAWL_ITERATIONS times with a completely
    fresh browser instance each time. All iterations are stored so the
    detector can diff values across visits.

    Args:
        site_limit: Max number of sites to crawl (None = all)
        custom_sites: Optional list of site dicts [{"url": ..., "reason": ...}].
                      If provided, overrides sites.json.

    Returns:
        List of per-site result dicts (each containing an `iterations` list)
    """
    # Load site list — custom input or default
    if custom_sites:
        sites = custom_sites
        logger.info("Using custom site list")
    else:
        with open(config.SITES_FILE, "r") as f:
            sites_data = json.load(f)
        sites = sites_data["sites"]

    if site_limit:
        sites = sites[:site_limit]

    iterations = config.CRAWL_ITERATIONS
    logger.info(f"Starting crawl of {len(sites)} sites × {iterations} iterations each")

    # Ensure output dirs
    os.makedirs(config.RAW_DATA_DIR, exist_ok=True)

    total_steps = len(sites) * iterations
    current_step = 0

    for i, site in enumerate(sites, 1):
        url = site["url"]
        logger.info(f"\n{'='*60}")
        logger.info(f"Site {i}/{len(sites)}: {url}")
        logger.info(f"Reason: {site.get('reason', 'N/A')}")

        site_iterations = []

        for iteration in range(1, iterations + 1):
            current_step += 1
            if on_progress:
                progress_pct = (current_step / total_steps) * 100
                msg = f"Crawling {url} (Iteration {iteration}/{iterations})"
                if len(sites) > 1:
                    msg = f"[{i}/{len(sites)}] " + msg
                on_progress(progress_pct, msg)

            logger.info(f"  ── Iteration {iteration}/{iterations} (fresh browser) ──")

            # Fresh browser for each iteration
            async with async_playwright() as pw:
                launch_args = [
                    '--disable-gpu',
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage'
                ]
                
                # Note: Playwright Firefox ignores some chromium-specific flags, 
                # but passing them is generally harmless/ignored.
                
                # Enhanced display detection and auto-mode selection
                requires_display = not config.HEADLESS
                has_display = False
                working_display = None
                
                if os.name != 'nt' and requires_display:
                    # 1. Normalize and test current DISPLAY
                    display_env = os.environ.get('DISPLAY')
                    candidates = []
                    if display_env:
                        candidates.append(display_env)
                        if display_env.isdigit():
                            candidates.append(f":{display_env}")
                    
                    # 2. Add common fallback candidates
                    for d in [":0", ":1", ":2"]:
                        if d not in candidates:
                            candidates.append(d)
                            
                    # 3. Probe for the first working display
                    import subprocess
                    for d in candidates:
                        try:
                            # Use a separate env for the test to avoid side effects
                            test_env = os.environ.copy()
                            test_env['DISPLAY'] = d
                            subprocess.run(['xdpyinfo'], env=test_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=True)
                            working_display = d
                            has_display = True
                            # Force update the environment so Playwright uses the found display
                            os.environ['DISPLAY'] = working_display
                            logger.info(f"Found and using working X11 display: {working_display}")
                            break
                        except:
                            continue
                            
                    if not has_display:
                        # Fallback for Wayland if no X11
                        if os.environ.get('WAYLAND_DISPLAY'):
                            has_display = True
                            logger.info(f"Using Wayland display: {os.environ.get('WAYLAND_DISPLAY')}")
                elif os.name == 'nt':
                    has_display = True # Windows always has a display
                
                # If headed requested on headless system (e.g., started by script), 
                # try Xvfb first if available, otherwise switch to True headless.
                disp = None
                launch_headless = config.HEADLESS # Start with config value
                
                if requires_display and not has_display:
                    try:
                        from pyvirtualdisplay import Display
                        logger.info("No usable X11 display detected, but headed mode was requested. Starting Xvfb virtual monitor...")
                        disp = Display(visible=0, size=(1920, 1080))
                        disp.start()
                        # Now that Xvfb is running, we can stay in NO-HEADLESS (headed) mode!
                        launch_headless = False # Explicitly stay headed
                    except (ImportError, Exception) as e:
                        logger.warning(f"Failed to start pyvirtualdisplay: {e}. Falling back to true headless mode.")
                        launch_headless = True # Force headless since no display/Xvfb

                browser = None
                try:
                    try:
                        if config.ENGINE == "foxhound":
                            foxhound_path = "/home/afnan/Downloads/Static-Analysis/mursaleen/Dynamic_Analysis_scratch/foxhound/foxhound"
                            browser = await pw.firefox.launch(headless=launch_headless, executable_path=foxhound_path, args=launch_args)
                        else:
                            browser = await pw.chromium.launch(headless=launch_headless, args=launch_args)
                    except Exception as launch_err:
                        if not launch_headless:
                            logger.error(f"Headed browser launch failed: {launch_err}. Retrying in true HEADLESS mode...")
                            if config.ENGINE == "foxhound":
                                foxhound_path = "/home/afnan/Downloads/Static-Analysis/mursaleen/Dynamic_Analysis_scratch/foxhound/foxhound"
                                browser = await pw.firefox.launch(headless=True, executable_path=foxhound_path, args=launch_args)
                            else:
                                browser = await pw.chromium.launch(headless=True, args=launch_args)
                        else:
                            raise launch_err
                        
                    crawler = SiteCrawler()
                    iter_result = await crawler.crawl_site(browser, url)
                    iter_result["iteration"] = iteration
                    site_iterations.append(iter_result)
                finally:
                    if browser:
                        await browser.close()
                    if disp:
                        disp.stop()

            # Small delay between iterations
            if iteration < iterations:
                await asyncio.sleep(2)

        # Build combined result with all iterations
        combined = {
            "url": url,
            "domain": site_iterations[0]["domain"],
            "timestamp": site_iterations[0]["timestamp"],
            "iterations": site_iterations,
            # Use the first iteration as the primary data for backward compat
            "indexeddb": site_iterations[0].get("indexeddb", {"databases": []}),
            "network_requests": site_iterations[0].get("network_requests", []),
            "errors": [],
        }

        # Collect all errors across iterations
        for it in site_iterations:
            for err in it.get("errors", []):
                combined["errors"].append(f"iter{it['iteration']}: {err}")

        results.append(combined)

        # Save per-site raw data (includes all iterations)
        safe_domain = combined["domain"].replace(".", "_").replace("/", "_")
        out_path = os.path.join(config.RAW_DATA_DIR, f"{safe_domain}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"  Saved {iterations} iterations → {out_path}")

        # Delay between sites
        if i < len(sites):
            await asyncio.sleep(2)

    logger.info(f"\n{'='*60}")
    logger.info(f"Crawl complete: {len(results)} sites × {iterations} iterations")
    return results


if __name__ == "__main__":
    import sys
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    asyncio.run(crawl_all_sites(limit))
