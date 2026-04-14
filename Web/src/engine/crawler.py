"""
Playwright-based automated website crawler for IndexedDB analysis.

Visits target websites, extracts all IndexedDB data, and captures
network requests for downstream tracking detection.
"""

import asyncio
import json
import os
import logging
import signal
import psutil
from urllib.parse import urlparse
from datetime import datetime

from playwright.async_api import async_playwright

import config

# Disable D-Bus for Firefox to prevent headless mode crashes on systems without proper D-Bus
# This is set before Playwright is imported to ensure all Firefox processes inherit these settings
os.environ.setdefault('DBUS_SYSTEM_BUS_ADDRESS', 'unix:path=/dev/null')
os.environ.setdefault('DBUS_SESSION_BUS_ADDRESS', 'unix:path=/dev/null')
# Set MOZ_NO_REMOTE to prevent Firefox from trying to contact an existing instance
os.environ.setdefault('MOZ_NO_REMOTE', '1')

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


def _get_firefox_env():
    """Create environment dict for Firefox with D-Bus disabled and display configured."""
    env = os.environ.copy()
    # Disable D-Bus to prevent headless mode crashes
    env['DBUS_SYSTEM_BUS_ADDRESS'] = 'unix:path=/dev/null'
    env['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=/dev/null'
    # Prevent Firefox from trying to contact existing instances
    env['MOZ_NO_REMOTE'] = '1'
    # Ensure DISPLAY and WAYLAND_DISPLAY are set in environment
    # (they may have been set for Xvfb virtual display)
    if 'DISPLAY' not in env and 'WAYLAND_DISPLAY' not in env:
        env['DISPLAY'] = ':99'  # Fallback - shouldn't be needed if Xvfb started
    return env


def _kill_browser_processes():
    """Forcefully kill any orphaned browser processes started by this task."""
    try:
        current_process = psutil.Process()
        children = current_process.children(recursive=True)
        for child in children:
            if child.name().lower() in ["chrome", "firefox", "chromium", "firefox-bin"]:
                try:
                    child.terminate()
                    # Wait a bit then kill if still alive
                    try:
                        child.wait(timeout=1)
                    except psutil.TimeoutExpired:
                        child.kill()
                    logger.info(f"Forcefully reaped browser process: {child.pid} ({child.name()})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
    except Exception as e:
        logger.error(f"Error during browser process reaping: {e}")


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
            # Navigation
            if asyncio.current_task().cancelled(): raise asyncio.CancelledError()
            await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=config.NAVIGATION_TIMEOUT,
            )
            logger.info(f"  Page loaded, scrolling and waiting {config.IDLE_WAIT}ms...")
            
            # Simple scroll-to-bottom to trigger lazy-loaded scripts/trackers
            try:
                if asyncio.current_task().cancelled(): raise asyncio.CancelledError()
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await asyncio.sleep(1)
                await page.evaluate("window.scrollTo(0, 0)")
            except asyncio.CancelledError:
                raise
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
                    except asyncio.CancelledError:
                        raise
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
            except asyncio.CancelledError:
                raise
            except Exception as e:
                error_msg = f"IndexedDB extraction failed: {str(e)}"
                logger.error(f"  {error_msg}")
                result["indexeddb"] = {"databases": [], "error": error_msg}
                result["errors"].append(error_msg)

        except asyncio.CancelledError:
            raise
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
                          on_progress: Optional[Callable[[float, str], None]] = None,
                          check_command: Optional[Callable[[str], bool]] = None) -> List[dict]:
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
    results = []

    for i, site in enumerate(sites, 1):
        if asyncio.current_task().cancelled():
            logger.info("Crawl task cancelled by user (site loop)")
            raise asyncio.CancelledError()
            
        if check_command and check_command("skip_domain"):
            logger.info("Skipping domain via UI command")
            continue
            
        url = site["url"]
        logger.info(f"\n{'='*60}")
        logger.info(f"Site {i}/{len(sites)}: {url}")
        logger.info(f"Reason: {site.get('reason', 'N/A')}")

        site_iterations = []

        for iteration in range(1, iterations + 1):
            if asyncio.current_task().cancelled():
                logger.info("Crawl task cancelled by user (iteration loop)")
                raise asyncio.CancelledError()
                
            if check_command and check_command("skip_iteration"):
                logger.info("Skipping iteration via UI command")
                continue
            
            if check_command and check_command("skip_domain"):
                logger.info("Skipping domain via UI command")
                break
                
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
                # Base arguments for both Chrome and Firefox
                launch_args = [
                    '--disable-gpu',
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage'
                ]
                
                # Additional Firefox-specific arguments for headless stability
                firefox_args = launch_args + [
                    '-new-instance',  # Prevent attempts to contact existing Firefox instance
                    '-width', '1920',  # Set explicit window size
                    '-height', '1080',
                ]
                
                # Note: Playwright Firefox ignores some chromium-specific flags, 
                # but passing them is generally harmless/ignored.
                
                # ================= DISPLAY SETUP =================
                disp = None
                launch_headless = config.HEADLESS
                
                logger.info(f"")
                logger.info(f"━━━ BROWSER SELECTION ━━━")
                logger.info(f"Browser engine: {config.ENGINE}")
                logger.info(f"Headless config: {config.HEADLESS}")
                logger.info(f"━━━━━━━━━━━━━━━━━━━━━━━━")
                logger.info(f"")
                
                # Firefox: Try to use existing X11 display first, fallback to Xvfb
                if config.ENGINE == "foxhound":
                    import subprocess
                    xvfb_created = False
                    
                    # First: Try to find an existing X11 display
                    logger.info("Firefox: Checking for existing X11 displays...")
                    candidates = [':0', ':1', ':2', ':3', ':4']
                    if os.environ.get('DISPLAY'):
                        candidates.insert(0, os.environ.get('DISPLAY'))
                    
                    for d in candidates:
                        try:
                            test_env = os.environ.copy()
                            test_env['DISPLAY'] = d
                            result = subprocess.run(['xdpyinfo'], env=test_env,
                                                  stdout=subprocess.DEVNULL, 
                                                  stderr=subprocess.DEVNULL, 
                                                  timeout=2, check=True)
                            os.environ['DISPLAY'] = d
                            logger.info(f"✓ Using existing X11 display: {d}")
                            break
                        except Exception:
                            logger.debug(f"Display {d} not available")
                            continue
                    else:
                        # No existing X11 display - create Xvfb
                        logger.info("No X11 display found, creating Xvfb virtual display...")
                        try:
                            from pyvirtualdisplay import Display
                            import time
                            disp = Display(visible=0, size=(1920, 1080))
                            disp.start()
                            time.sleep(1)
                            display_num = f":{disp.display}"
                            os.environ['DISPLAY'] = display_num
                            xvfb_created = True
                            logger.info(f"✓ Created Xvfb virtual display: {display_num}")
                        except (ImportError, Exception) as e:
                            logger.error(f"✗ Cannot create Xvfb: {e}")
                            logger.warning("Will attempt Firefox in headless mode...")
                    
                    # Firefox with real X11 display: use headed mode (headless causes hangs)
                    # Firefox with Xvfb virtual display: use headless=True (headed causes crashes)
                    if xvfb_created:
                        launch_headless = True
                        logger.info("Using Xvfb: launch_headless=True (required for virtual display)")
                    else:
                        # Real X11 display exists - use headed mode even if config.HEADLESS=True
                        # (headed mode is more stable for Firefox than headless)
                        launch_headless = False
                        logger.info("Real X11 display found: using headed mode (more stable for Firefox)")
                
                # Chrome: In no-headless mode, try to use X11 display or Xvfb
                elif config.ENGINE == "chrome" and not config.HEADLESS:
                    import subprocess
                    has_display = False
                    candidates = [':0', ':1', ':2', ':3', ':4']
                    if os.environ.get('DISPLAY'):
                        candidates.insert(0, os.environ.get('DISPLAY'))
                    
                    logger.info("Chrome: Checking for X11 display...")
                    for d in candidates:
                        try:
                            test_env = os.environ.copy()
                            test_env['DISPLAY'] = d
                            subprocess.run(['xdpyinfo'], env=test_env,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, 
                                         timeout=2, check=True)
                            os.environ['DISPLAY'] = d
                            has_display = True
                            logger.info(f"✓ Using existing X11 display: {d}")
                            break
                        except Exception:
                            continue
                    
                    # No system display - create virtual one
                    if not has_display:
                        try:
                            from pyvirtualdisplay import Display
                            import time
                            logger.info("Chrome: No X11 display, starting Xvfb...")
                            disp = Display(visible=0, size=(1920, 1080))
                            disp.start()
                            time.sleep(1)
                            display_num = f":{disp.display}"
                            os.environ['DISPLAY'] = display_num
                            logger.info(f"✓ Created Xvfb for Chrome: {display_num}")
                            launch_headless = False
                        except (ImportError, Exception) as e:
                            logger.warning(f"Cannot create Xvfb: {e}. Using headless.")
                            launch_headless = True
                
                logger.info(f"Launch mode: headless={launch_headless}, DISPLAY={os.environ.get('DISPLAY', 'unset')}")

                browser = None
                try:
                    if config.ENGINE == "foxhound":
                        logger.info(f"")
                        logger.info(f"🦊 ━━━━━ LAUNCHING FOXHOUND ━━━━━ 🦊")
                        logger.info(f"Executable: {config.FOXHOUND_BIN}")
                        logger.info(f"Headless mode: {launch_headless}")
                        logger.info(f"Foxhound binary exists: {os.path.exists(config.FOXHOUND_BIN)}")
                        logger.info(f"Firefox args: {firefox_args}")
                        logger.info(f"🦊 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 🦊")
                        # Use custom Foxhound executable (not Playwright's managed Firefox)
                        browser = await pw.firefox.launch(
                            headless=launch_headless,
                            executable_path=config.FOXHOUND_BIN,
                            args=firefox_args,
                            env=_get_firefox_env(),
                            timeout=60000  # 60 seconds (Xvfb startup overhead)
                        )
                        logger.info(f"✓ Foxhound launched successfully")
                    else:
                        logger.info(f"")
                        logger.info(f"🌐 ━━━━━ LAUNCHING CHROME ━━━━━ 🌐")
                        logger.info(f"Headless mode: {launch_headless}")
                        logger.info(f"Chrome args: {launch_args}")
                        logger.info(f"🌐 ━━━━━━━━━━━━━━━━━━━━━━━━━━ 🌐")
                        browser = await pw.chromium.launch(headless=launch_headless, args=launch_args)
                        logger.info(f"✓ Chrome launched successfully")
                        logger.info("✓ Chrome launched successfully")
                        
                    crawler = SiteCrawler()
                    skip_type = None
                    
                    if check_command:
                        crawl_task = asyncio.create_task(crawler.crawl_site(browser, url))
                        while not crawl_task.done():
                            if check_command("skip_iteration"):
                                skip_type = "iteration"
                                crawl_task.cancel()
                                break
                            if check_command("skip_domain"):
                                skip_type = "domain"
                                crawl_task.cancel()
                                break
                            await asyncio.sleep(0.5)
                            
                        try:
                            iter_result = await crawl_task
                            iter_result["iteration"] = iteration
                            site_iterations.append(iter_result)
                        except asyncio.CancelledError:
                            logger.info(f"Task cancelled via {skip_type} signal.")
                    else:
                        iter_result = await crawler.crawl_site(browser, url)
                        iter_result["iteration"] = iteration
                        site_iterations.append(iter_result)

                finally:
                    # Robust cleanup: try to close browser, then stop display
                    if browser:
                        try:
                            # Use a small timeout for closing to prevent hanging the cleanup
                            await asyncio.wait_for(browser.close(), timeout=5.0)
                        except asyncio.TimeoutError:
                            logger.warning("Browser close timed out - attempting force kill")
                            # If Playwright close hangs, we need to be more aggressive
                            try:
                                _kill_browser_processes()
                            except:
                                pass
                        except Exception:
                            logger.warning("Browser close failed during cleanup")
                    
                    if disp:
                        try:
                            disp.stop()
                        except:
                            pass
                            
            if skip_type == "domain":
                logger.info("Domain skipped during active crawl.")
                break

            # Small delay between iterations
            if iteration < iterations:
                await asyncio.sleep(2)

        if not site_iterations:
            continue

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
