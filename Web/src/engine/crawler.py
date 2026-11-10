"""
Playwright-based automated website crawler for IndexedDB analysis.

Visits target websites, extracts all IndexedDB data, and captures
network requests for downstream tracking detection.
"""

import asyncio
import functools
import json
import os
import logging
import signal
import threading
import psutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from datetime import datetime
from playwright.async_api import async_playwright
import app_config as config

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

                            tx.oncomplete = async () => {
                                const keyPath = store.keyPath;
                                const entries = [];
                                const hex = (ab) => {
                                    const b = new Uint8Array(ab);
                                    let s = "";
                                    for (let i = 0; i < b.length && i < 64; i++)
                                        s += b[i].toString(16).padStart(2, "0");
                                    return "hex:" + s;
                                };
                                for (let i = 0; i < keys.length; i++) {
                                    const k = keys[i];
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
                                    // Phase 3: serialize non-string IDB types
                                    // (numbers/Dates/Blobs/typed arrays) so they
                                    // enter the identifier candidate pool.
                                    if (val instanceof Date) {
                                        val = val.toISOString();
                                    } else if (val instanceof ArrayBuffer) {
                                        val = hex(val);
                                    } else if (ArrayBuffer.isView(val)) {
                                        val = hex(val.buffer.slice(
                                            val.byteOffset,
                                            val.byteOffset + val.byteLength));
                                    } else if (typeof Blob !== "undefined"
                                               && val instanceof Blob) {
                                        try {
                                            if (val.size <= 4096) {
                                                val = await val.text();
                                            } else {
                                                val = {__blob_size: val.size,
                                                       __blob_type: val.type || ""};
                                            }
                                        } catch (e) {
                                            val = {__blob_size: val.size};
                                        }
                                    }
                                    entries.push({ key: k, value: val });
                                }
                                resolve(entries);
                            };
                            tx.onerror = () => reject(tx.error);
                        });

                        dbData.stores.push({
                            name: storeName,
                            recordCount: records.length,
                            records: records.slice(0, 200),  // Cap per store
                            truncated: records.length > 200,
                            truncatedCount: Math.max(0, records.length - 200)
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

# ─── Foxhound Taint Collection ──────────────────────────────────────
# Foxhound's SpiderMonkey engine tags strings that originate from taint
# sources (document.cookie, location.*, localStorage.getItem, XHR.response,
# MessageEvent, ...). When a tainted value reaches a sink (fetch.url,
# XMLHttpRequest.open, navigator.sendBeacon, img.src, form.action, ...) the
# built-in "taint-exporter@sap.com" extension POSTs {detail, taint} JSON to
# the pref `tainting.export.url`. We run a tiny local server to collect it.
# NOTE (verified empirically): IndexedDB reads are NOT taint sources and
# taint does NOT survive an IDB put/get round-trip, so IDB-origin flows are
# additionally covered by FLOW_HOOKS_INIT_SCRIPT below.


class TaintCaptureServer:
    """Local HTTP capture endpoint for Foxhound taint export events."""

    def __init__(self):
        self._server = None
        self._thread = None
        self.events = []
        self._lock = threading.Lock()
        self.port = None

    def start(self):
        handler = functools.partial(_TaintHandler, self)
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def add_event(self, data):
        with self._lock:
            self.events.append(data)

    def drain(self):
        with self._lock:
            out, self.events = self.events, []
            return out


class _TaintHandler(BaseHTTPRequestHandler):
    """CORS-enabled handler: accepts OPTIONS preflight + JSON POST bodies."""

    def __init__(self, server, *args, **kwargs):
        self.capture = server
        super().__init__(*args, **kwargs)

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        try:
            data = json.loads(body.decode("utf-8", "ignore")) if body else {}
        except Exception:
            data = {"raw": body.decode("utf-8", "ignore")}
        self.capture.add_event(data)
        self.send_response(200)
        self._cors_headers()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, fmt, *args):
        pass


# ─── Flow Hooks (IDB read + network send instrumentation) ───────────
# IndexedDB is a taint blackout for Foxhound (reads are not sources and
# taint is lost on put/get). To keep the DB->network path visible we wrap
# IDB reads and network senders in-page and record the value + the JS
# function that performed the read/send (source/sink function attribution).
FLOW_HOOKS_INIT_SCRIPT = r"""
(() => {
  if (window.__prividb_hooks) return;
  const H = (window.__prividb_hooks = { reads: [], sends: [], writes: [], responses: [] });
  function push(arr, rec) {
    try {
      let v = typeof rec.value === "string" ? rec.value : JSON.stringify(rec.value);
      if (v !== undefined && v !== null && arr === H.reads && (!v || v === "null")) return;
      if (v !== undefined) {
        if (v.length > 2000) v = v.slice(0, 2000);
        rec.value = v;
      }
      if (arr.length >= 1000) arr.shift();
      arr.push(rec);
    } catch (e) {}
  }
  function caller() {
    // Works for both stack formats:
    //   Chrome/Firefox-new: "at fn (https://host/a.js:1:2)" / "at https://..."
    //   Firefox-classic:    "fn@https://host/a.js:1:2"
    try {
      const raw = (new Error().stack || "").split("\n");
      // Drop the header line(s) pointing at caller() itself
      const lines = raw.filter((l) => {
        const t = l.trim();
        return t.startsWith("at ") || t.includes("@");
      });
      for (let i = 0; i < lines.length; i++) {
        const t = lines[i].trim();
        // Skip frames belonging to this injected instrument script —
        // Playwright evaluates init scripts in a "debugger eval code"
        // context, so the wrapper frames (caller, proto[op], fetch, …)
        // all live there and must be skipped to reach the real caller.
        if (t.includes("__prividb_hooks") || t.includes("FLOW_HOOKS")) continue;
        let fn = "", loc = "";
        if (t.startsWith("at ")) {
          const body = t.slice(3);
          const m = body.match(/^(.*?)\s*\((.*)\)$/);
          if (m) { fn = m[1].trim(); loc = m[2].trim(); }
          else { loc = body.trim(); fn = ""; }
        } else if (t.includes("@")) {
          const at = t.lastIndexOf("@");
          fn = t.slice(0, at).trim();
          loc = t.slice(at + 1).trim();
          // Firefox may append :line:col — keep as-is (script origin
          // extraction strips it); drop "native" pseudo-frames
          if (loc === "native" || loc === "") continue;
        }
        if (loc && (loc.indexOf("debugger eval code") !== -1
                    || loc.indexOf("<anonymous>") !== -1)) continue;
        if (fn === "caller" || fn === "proto[op]"
            || fn.indexOf("proto[") === 0
            || fn.indexOf("proto.<") === 0
            || fn.indexOf("[as ") !== -1) continue;
        return { fn, loc };
      }
    } catch (e) {}
    return { fn: "", loc: "" };
  }
  // --- IndexedDB reads ---
  try {
    for (const proto of [IDBObjectStore.prototype, IDBIndex.prototype]) {
      const ops = ["get", "getAll", "getAllKeys", "getKey", "openCursor", "openKeyCursor"];
      for (const op of ops) {
        const orig = proto[op];
        if (typeof orig !== "function") continue;
        proto[op] = function (...args) {
          const c = caller();
          const store = (this && this.name) || "";
          const req = orig.apply(this, args);
          try {
            req.addEventListener("success", () => {
              try {
                const res = req.result;
                // Cursors (openCursor): record the current value
                const v0 = (res && typeof res === "object" && "value" in res && "primaryKey" in res && !Array.isArray(res))
                  ? res.value : res;
                // Include primitives: IDB get() often returns plain strings,
                // which the old object-only filter silently dropped.
                const vals = Array.isArray(v0) ? v0 : (v0 !== undefined && v0 !== null) ? [v0] : [];
                for (const v of vals) {
                  push(H.reads, { op, store, value: v, fn: c.fn, loc: c.loc, ts: Date.now() });
                }
              } catch (e) {}
            });
          } catch (e) {}
          return req;
        };
      }
    }
  } catch (e) {}
  // --- Network senders ---
  try {
    const origFetch = window.fetch;
    window.fetch = function (...args) {
      const c = caller();
      const url = (args[0] && args[0].url) || String(args[0] || "");
      const body = args[1] ? String(args[1].body || "") : "";
      push(H.sends, { op: "fetch", url, body, fn: c.fn, loc: c.loc, ts: Date.now() });
      const p = origFetch.apply(this, args);
      // Capture the response body (truncated) for inflow detection:
      // network value → later written to IDB.
      try {
        p.then((resp) => {
          try {
            const rurl = resp.url || url;
            const status = resp.status;
            resp.clone().text().then((t) => {
              try {
                if (t && t.length > 8000) t = t.slice(0, 8000);
                if (H.responses.length >= 300) H.responses.shift();
                H.responses.push({ url: rurl, status, body: t || "", ts: Date.now(),
                                   t_rel: Math.round(performance.now()) });
              } catch (e) {}
            }).catch(() => {});
          } catch (e) {}
        }).catch(() => {});
      } catch (e) {}
      return p;
    };
  } catch (e) {}
  try {
    const open = XMLHttpRequest.prototype.open;
    const send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url, ...rest) {
      const c = caller();
      this.__prividb_xurl = url;
      push(H.sends, { op: "XMLHttpRequest.open", url: String(url || ""), fn: c.fn, loc: c.loc, ts: Date.now() });
      return open.apply(this, [method, url, ...rest]);
    };
    XMLHttpRequest.prototype.send = function (body) {
      const c = caller();
      push(H.sends, { op: "XMLHttpRequest.send", url: this.__prividb_xurl || "", body: String(body || ""), fn: c.fn, loc: c.loc, ts: Date.now() });
      // Response capture for inflow detection
      try {
        this.addEventListener("loadend", () => {
          try {
            let t = "";
            try { t = this.responseText || ""; } catch (e) { t = ""; }
            if (!t) return;
            if (t.length > 8000) t = t.slice(0, 8000);
            if (H.responses.length >= 300) H.responses.shift();
            H.responses.push({ url: this.__prividb_xurl || "", status: this.status,
                               body: t, ts: Date.now(),
                               t_rel: Math.round(performance.now()) });
          } catch (e) {}
        });
      } catch (e) {}
      return send.apply(this, [body]);
    };
  } catch (e) {}
  try {
    const sb = navigator.sendBeacon;
    navigator.sendBeacon = function (url, data) {
      const c = caller();
      push(H.sends, { op: "sendBeacon", url: String(url || ""), body: String(data || ""), fn: c.fn, loc: c.loc, ts: Date.now() });
      return sb.apply(this, arguments);
    };
  } catch (e) {}
  try {
    Object.defineProperty(Image.prototype, "src", {
      configurable: true,
      get() { return this.__prividb_src; },
      set(v) {
        const c = caller();
        this.__prividb_src = v;
        push(H.sends, { op: "img.src", url: String(v || ""), fn: c.fn, loc: c.loc, ts: Date.now() });
      }
    });
  } catch (e) {}
  // --- IDB writes (put/add/cursor.update): WHO creates identifiers ---
  // Records value, store, database (via transaction), the calling script,
  // and time-relative-to-load so writes can be ordered against consent.
  try {
    function dbOf(store) {
      try { return (store.transaction && store.transaction.db && store.transaction.db.name) || ""; }
      catch (e) { return ""; }
    }
    for (const [proto, ops] of [
      [IDBObjectStore.prototype, ["put", "add"]],
      [IDBCursor.prototype, ["update"]],
    ]) {
      for (const op of ops) {
        const orig = proto[op];
        if (typeof orig !== "function") continue;
        proto[op] = function (value, ...rest) {
          const c = caller();
          const store = (proto === IDBObjectStore.prototype)
            ? ((this && this.name) || "")
            : ((this && this.source && this.source.name) || "");
          try {
            let v = typeof value === "string" ? value : JSON.stringify(value);
            if (v !== undefined && v !== null) {
              if (v.length > 2000) v = v.slice(0, 2000);
            }
            if (H.writes.length >= 1000) H.writes.shift();
            H.writes.push({
              op: (proto === IDBObjectStore.prototype) ? op : "cursor.update",
              db: (proto === IDBObjectStore.prototype) ? dbOf(this) : "",
              store, value: v,
              key: (rest[0] !== undefined && rest[0] !== null)
                    ? String(rest[0]).slice(0, 200) : "",
              fn: c.fn, loc: c.loc,
              ts: Date.now(),
              t_rel: Math.round(performance.now()),
            });
          } catch (e) {}
          return orig.apply(this, [value, ...rest]);
        };
      }
    }
  } catch (e) {}
})();
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

    def __init__(self, taint_capture: TaintCaptureServer = None, hooks: bool = False):
        self.network_requests = []
        self.taint_capture = taint_capture
        self.hooks = hooks

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
            no_viewport=True,
        )
        # Install IDB-read/sender instrumentation before any page exists so
        # every frame (main + iframes) records source/sink JS functions.
        if self.hooks:
            try:
                await context.add_init_script(script=FLOW_HOOKS_INIT_SCRIPT)
            except Exception as e:
                logger.warning(f"  Flow hooks init failed: {e}")
        page = await context.new_page()
        self.network_requests = []

        # ── Attach network listeners ────────────────────────────────
        page.on("request", self._on_request)
        page.on("response", self._on_response)

        # ── WebSocket frame capture (values can travel over WS too) ─
        page.on("websocket", self._on_websocket)

        result = {
            "url": url,
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "indexeddb": {"databases": []},
            "network_requests": [],
            "taint_events": [],
            "flow_hooks": {"reads": [], "sends": [], "writes": [], "responses": []},
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

        # Collect per-frame flow hooks (IDB reads, network sends, writes,
        # responses) — the same JS runs on both engines for comparability
        if self.hooks:
            try:
                hooks = {"reads": [], "sends": [], "writes": [], "responses": []}
                for frame in page.frames:
                    try:
                        frame_hooks = await frame.evaluate("window.__prividb_hooks")
                        if frame_hooks:
                            for k in ("reads", "sends", "writes", "responses"):
                                hooks[k].extend(frame_hooks.get(k, []))
                    except Exception:
                        continue
                result["flow_hooks"] = hooks
                logger.info(
                    f"  Flow hooks: {len(hooks['reads'])} IDB reads, "
                    f"{len(hooks['sends'])} network sends, "
                    f"{len(hooks['writes'])} IDB writes, "
                    f"{len(hooks['responses'])} responses captured"
                )
            except Exception as e:
                logger.warning(f"  Flow hook collection failed: {e}")

        # Drain this iteration's Foxhound taint reports (give in-flight
        # exporter POSTs a moment to arrive)
        if self.taint_capture is not None:
            await asyncio.sleep(0.6)
            taint_events = self.taint_capture.drain()
            result["taint_events"] = taint_events
            logger.info(f"  Foxhound taint flows captured: {len(taint_events)}")

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

    def _on_websocket(self, ws):
        """Capture WebSocket frames (send/receive) for transform matching.

        Frames are attached to the network entry created for the WS
        handshake request, so the matcher sees them alongside headers.
        """
        try:
            # Find/create the handshake request entry
            entry = None
            for req in reversed(self.network_requests):
                if req["url"] == ws.url:
                    entry = req
                    break
            if entry is None:
                entry = {"url": ws.url, "method": "GET",
                         "resource_type": "websocket",
                         "headers": {}, "post_data": None,
                         "response": None, "ws_frames": []}
                self.network_requests.append(entry)
            entry.setdefault("ws_frames", [])

            def _cap(payload, direction):
                try:
                    if isinstance(payload, (bytes, bytearray)):
                        payload = payload.decode("utf-8", "ignore")
                    payload = str(payload)
                    if len(payload) > 4000:
                        payload = payload[:4000]
                    frames = entry["ws_frames"]
                    if len(frames) >= 100:
                        frames.pop(0)
                    frames.append({"direction": direction,
                                   "payload": payload,
                                   "ts": datetime.utcnow().isoformat() + "Z"})
                except Exception:
                    pass

            ws.on("framesent", lambda pl: _cap(pl, "send"))
            ws.on("framereceived", lambda pl: _cap(pl, "receive"))
            ws.on("close", lambda: None)
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
                taint_capture = None
                try:
                    if config.ENGINE == "foxhound":
                        logger.info(f"")
                        logger.info(f"🦊 ━━━━━ LAUNCHING FOXHOUND ━━━━━ 🦊")
                        logger.info(f"Executable: {config.FOXHOUND_BIN}")
                        logger.info(f"Headless mode: {launch_headless}")
                        logger.info(f"Foxhound binary exists: {os.path.exists(config.FOXHOUND_BIN)}")
                        logger.info(f"Foxhound taint tracking: {'ENABLED' if config.TAINT_TRACKING_ENABLED else 'DISABLED'}")
                        logger.info(f"Firefox args: {firefox_args}")
                        logger.info(f"🦊 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 🦊")

                        taint_prefs = {}
                        if config.TAINT_TRACKING_ENABLED:
                            # Local capture endpoint for Foxhound taint exports.
                            # Must exist before launch so the exporter knows where to POST.
                            taint_capture = TaintCaptureServer().start()
                            logger.info(f"✓ Taint capture server on 127.0.0.1:{taint_capture.port}")
                            taint_prefs = {
                                "tainting.active": True,
                                "tainting.export.url": f"http://127.0.0.1:{taint_capture.port}/",
                                # Disable CSP so the exporter's POST to the local
                                # capture server can't be blocked by page connect-src.
                                "security.csp.enable": False,
                            }

                        # Use custom Foxhound executable (not Playwright's managed Firefox)
                        browser = await pw.firefox.launch(
                            headless=launch_headless,
                            executable_path=config.FOXHOUND_BIN,
                            args=firefox_args,
                            env=_get_firefox_env(),
                            firefox_user_prefs=taint_prefs or None,
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
                        
                    crawler = SiteCrawler(
                        taint_capture=taint_capture,
                        hooks=bool(config.TAINT_TRACKING_ENABLED),
                    )
                    skip_type = None
                    browser_version = ""
                    try:
                        browser_version = browser.version or ""
                    except Exception:
                        pass
                    
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
                            iter_result["browser_version"] = browser_version
                            site_iterations.append(iter_result)
                        except asyncio.CancelledError:
                            logger.info(f"Task cancelled via {skip_type} signal.")
                    else:
                        iter_result = await crawler.crawl_site(browser, url)
                        iter_result["iteration"] = iteration
                        iter_result["browser_version"] = browser_version
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

                    # Drain any final Foxhound taint reports and stop the server
                    if taint_capture is not None:
                        leftover = taint_capture.drain()
                        if leftover:
                            for it in site_iterations:
                                it.setdefault("taint_events", [])
                            target = site_iterations[-1] if site_iterations else None
                            if target:
                                target["taint_events"].extend(leftover)
                            logger.info(f"  Taint drain: +{len(leftover)} late events")
                        taint_capture.stop()
                        taint_capture = None

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
        import platform
        import sys as _sys
        try:
            from importlib.metadata import version as _pkg_version
            _pw_version = _pkg_version("playwright")
        except Exception:
            _pw_version = "unknown"
        run_meta = {
            "engine": config.ENGINE,
            "headless": bool(config.HEADLESS),
            "iterations": iterations,
            "user_agent": config.USER_AGENT,
            "browser_version": site_iterations[-1].get("browser_version", ""),
            "playwright_version": _pw_version,
            "python_version": _sys.version.split()[0],
            "platform": platform.platform(),
            "taint_tracking_enabled": bool(getattr(config, "TAINT_TRACKING_ENABLED", False)),
            "captured_at": datetime.utcnow().isoformat() + "Z",
        }
        combined = {
            "url": url,
            "domain": site_iterations[0]["domain"],
            "timestamp": site_iterations[0]["timestamp"],
            "iterations": site_iterations,
            "run_meta": run_meta,
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
