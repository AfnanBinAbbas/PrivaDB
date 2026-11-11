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
# Window + Web-Worker + SharedWorker coverage for the DB->network path
# (IndexedDB is a taint blackout for Foxhound: reads are not sources and
# taint does not survive an IDB put/get round-trip — PAPER_REPORT.md §
# "IDB is a taint blackout"; SAP's taint/ has zero MarkTaintSource in
# any IndexedDB path). The wrap core below runs in these contexts:
#
#   window            — installed by add_init_script; records into local
#                       arrays drained by the crawler.
#   dedicated Worker  — blob-URL bootstrap (core + importScripts with
#                       absolute-URL rebasing of direct children), same
#                       mechanism as SharedWorker. Probe-validated on
#                       Foxhound (probe3 Q14) and proven end-to-end on
#                       Chromium (shared-worker blob path delivered
#                       /v/shraw,/v/shb64 to the sink — logs/28).
#                       If the blob is CSP-blocked the wrap falls back
#                       to the untouched original constructor (site
#                       keeps working; injection gap recorded).
#   SharedWorker      — blob bootstrap (probe3 Q15/Q16 validated).
#   ServiceWorker     — NOT injectable on either engine: Playwright-
#                       Firefox never routes the registration fetch
#                       (probe1 Q2) and blob:-URL registration is
#                       rejected by spec (probe2 Q11), while on
#                       Chromium route-fulfilling the SW script poisons
#                       that SW's subsequent CROSS-ORIGIN fetches
#                       (net::ERR_FAILED — logs/32..35; same-origin
#                       still works, so the breakage is silent for
#                       same-origin sinks). register() is therefore
#                       left UNMARKED: the SW runs clean, its exfil
#                       reaches the sink (browser-side proof), and the
#                       no-hello gap is recorded per crawl. Never
#                       reported as hook coverage.
#
# WHY NOT route-injection for dedicated workers (removed): the earlier
# __privadb_tok route.fulfill path worked on Foxhound but produced
# PHANTOM requests on Chromium — the worker script's REQ event fires
# (so matchers TP) yet the request dies with net::ERR_FAILED before
# reaching the network (Chrome evaluate sink log had zero /v/w*
# arrivals while scoring claimed 1.000 recall — logs/28 + 35).
# Blob injection sidesteps interception entirely.
#
# Worker events reach the window over BroadcastChannel
# "__privadb_hook_bus__" filtered by per-frame token, so they land in
# the SAME reads/sends/writes/responses arrays the detector consumes.
# Worker-initiated fetches are invisible to Playwright's request events
# for SharedWorker (probe3 Q17; Chromium too — synth=2 [shared] in
# logs/28) — detector.py synthesizes network entries from these hook
# sends (tagged synthetic=true).

# Single source of truth for the wrap core. Runs identically in window
# and worker globals (only `self`, guarded typeof checks). env.kind
# selects the transport: "window" pushes locally, anything else emits
# over the BroadcastChannel + posts a hello for coverage accounting.
HOOK_CORE_EXPR = r"""function (env) {
  env = env || { kind: "window" };
  if (self.__privadb_hooks_live) return self.__privadb_hooks_live;
  self.__privadb_hooks_installed = true;
  const kind = String(env.kind || "window");
  const token = String(env.token || "");
  const isWin = kind === "window";
  const H = {
    reads: [], sends: [], writes: [], responses: [],
    meta: { kind: kind, token: token, spawned: {}, seen: {},
            gaps: [], tampered: null }
  };
  let bus = null;
  if (!isWin) {
    try { bus = new BroadcastChannel("__privadb_hook_bus__"); } catch (e) {}
  }
  const CAP = { reads: 1000, sends: 1000, writes: 1000, responses: 300 };
  function emit(arr, rec) {
    try {
      if (rec) {
        if (rec.ctx === undefined) rec.ctx = kind;
        if (rec.ts === undefined) rec.ts = Date.now();
        // old push() semantics: stringify + clip `value` (detector
        // json.loads string leaves); `body` passes through untouched.
        if (rec.value !== undefined && rec.value !== null) {
          if (typeof rec.value !== "string") {
            try { rec.value = JSON.stringify(rec.value); }
            catch (e) { rec.value = String(rec.value); }
          }
          if (rec.value.length > 2000) rec.value = rec.value.slice(0, 2000);
        }
      }
      if (isWin) {
        const a = H[arr];
        if (!a) return;
        if (arr === "reads") {
          const v = String((rec && rec.value !== undefined) ? rec.value : "");
          if (!v || v === "null") return;
        }
        if (a.length >= (CAP[arr] || 1000)) a.shift();
        a.push(rec);
      } else if (bus) {
        bus.postMessage({ __privadb: 1, token: token, arr: arr, rec: rec });
      }
    } catch (e) {}
  }
  if (!isWin) {
    try {
      bus.postMessage({ __privadb: 1, token: token, hello: kind,
                        loc: (self.location && self.location.href) || "" });
    } catch (e) {}
  }
  // Stack parser: works for Chrome/Firefox-new ("at fn (url:line)")
  // and Firefox-classic ("fn@url") formats; skips this instrument's
  // own frames (Playwright evaluates init scripts in a "debugger eval
  // code" context, so wrapper frames live there).
  function caller() {
    try {
      const raw = (new Error().stack || "").split("\n");
      const lines = raw.filter((l) => {
        const t = l.trim();
        return t.startsWith("at ") || t.includes("@");
      });
      for (let i = 0; i < lines.length; i++) {
        const t = lines[i].trim();
        if (t.includes("__prividb_hooks") || t.includes("FLOW_HOOKS")
            || t.includes("__privadb")) continue;
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
  const refs = {};
  // ── IndexedDB reads (same classes in window and all worker kinds) ──
  try {
    if (typeof IDBObjectStore !== "undefined") {
      for (const proto of [IDBObjectStore.prototype, IDBIndex.prototype]) {
        const ops = ["get", "getAll", "getAllKeys", "getKey",
                     "openCursor", "openKeyCursor"];
        for (const op of ops) {
          const orig = proto[op];
          if (typeof orig !== "function") continue;
          const wrapped = function (...args) {
            const c = caller();
            const store = (this && this.name) || "";
            const req = orig.apply(this, args);
            try {
              req.addEventListener("success", () => {
                try {
                  const res = req.result;
                  const v0 = (res && typeof res === "object"
                              && "value" in res && "primaryKey" in res
                              && !Array.isArray(res))
                    ? res.value : res;
                  const vals = Array.isArray(v0) ? v0
                    : (v0 !== undefined && v0 !== null) ? [v0] : [];
                  for (const v of vals) {
                    emit("reads", { op, store, value: v,
                                    fn: c.fn, loc: c.loc });
                  }
                } catch (e) {}
              });
            } catch (e) {}
            return req;
          };
          proto[op] = wrapped;
          if (proto === IDBObjectStore.prototype) refs["idb_" + op] = wrapped;
        }
      }
    }
  } catch (e) {}
  // ── fetch ──
  try {
    if (typeof self.fetch === "function") {
      const origFetch = self.fetch;
      const wrapped = function (...args) {
        const c = caller();
        const url = (args[0] && args[0].url) || String(args[0] || "");
        const body = args[1] ? String(args[1].body || "") : "";
        emit("sends", { op: "fetch", url, body, fn: c.fn, loc: c.loc });
        const p = origFetch.apply(this, args);
        try {
          p.then((resp) => {
            try {
              const rurl = resp.url || url;
              const status = resp.status;
              resp.clone().text().then((t) => {
                try {
                  if (t && t.length > 8000) t = t.slice(0, 8000);
                  emit("responses", { url: rurl, status, body: t || "",
                                      t_rel: Math.round(
                                        (self.performance
                                         && self.performance.now()) || 0) });
                } catch (e) {}
              }).catch(() => {});
            } catch (e) {}
          }).catch(() => {});
        } catch (e) {}
        return p;
      };
      self.fetch = wrapped;
      refs.fetch = wrapped;
    }
  } catch (e) {}
  // ── XMLHttpRequest ──
  try {
    if (typeof XMLHttpRequest !== "undefined") {
      const open = XMLHttpRequest.prototype.open;
      const send = XMLHttpRequest.prototype.send;
      const openW = function (method, url, ...rest) {
        const c = caller();
        this.__prividb_xurl = url;
        emit("sends", { op: "XMLHttpRequest.open", url: String(url || ""),
                        fn: c.fn, loc: c.loc });
        return open.apply(this, [method, url, ...rest]);
      };
      const sendW = function (body) {
        const c = caller();
        emit("sends", { op: "XMLHttpRequest.send",
                        url: this.__prividb_xurl || "",
                        body: String(body || ""), fn: c.fn, loc: c.loc });
        try {
          this.addEventListener("loadend", () => {
            try {
              let t = "";
              try { t = this.responseText || ""; } catch (e) { t = ""; }
              if (!t) return;
              if (t.length > 8000) t = t.slice(0, 8000);
              emit("responses", { url: this.__prividb_xurl || "",
                                  status: this.status, body: t,
                                  t_rel: Math.round(
                                    (self.performance
                                     && self.performance.now()) || 0) });
            } catch (e) {}
          });
        } catch (e) {}
        return send.apply(this, [body]);
      };
      XMLHttpRequest.prototype.open = openW;
      XMLHttpRequest.prototype.send = sendW;
      refs.xhr_open = openW;
      refs.xhr_send = sendW;
    }
  } catch (e) {}
  // ── sendBeacon (window + dedicated/shared workers; absent in SW) ──
  try {
    if (typeof navigator !== "undefined"
        && typeof navigator.sendBeacon === "function") {
      const sb = navigator.sendBeacon;
      const wrapped = function (url, data) {
        const c = caller();
        emit("sends", { op: "sendBeacon", url: String(url || ""),
                        body: String(data || ""), fn: c.fn, loc: c.loc });
        return sb.apply(this, arguments);
      };
      navigator.sendBeacon = wrapped;
      refs.sendBeacon = wrapped;
    }
  } catch (e) {}
  // ── img.src (window only; Image is undefined in workers) ──
  try {
    if (typeof Image !== "undefined") {
      const proto = Image.prototype;
      const desc = Object.getOwnPropertyDescriptor(proto, "src")
                || (typeof HTMLImageElement !== "undefined"
                    ? Object.getOwnPropertyDescriptor(
                          HTMLImageElement.prototype, "src")
                    : null);
      if (desc && desc.set) {
        const d2 = Object.defineProperty(proto, "src", {
          configurable: true,
          get() { return desc.get.call(this); },
          set(v) {
            const c = caller();
            emit("sends", { op: "img.src", url: String(v || ""),
                            fn: c.fn, loc: c.loc });
            desc.set.call(this, v);
          }
        });
        refs.img_src = d2;
      }
    }
  } catch (e) {}
  // ── IDB writes (put/add/cursor.update): WHO creates identifiers ──
  try {
    if (typeof IDBObjectStore !== "undefined") {
      function dbOf(store) {
        try {
          return (store.transaction && store.transaction.db
                  && store.transaction.db.name) || "";
        } catch (e) { return ""; }
      }
      for (const [proto, ops] of [
        [IDBObjectStore.prototype, ["put", "add"]],
        [typeof IDBCursor !== "undefined" ? IDBCursor.prototype : null,
         ["update"]],
      ]) {
        if (!proto) continue;
        for (const op of ops) {
          const orig = proto[op];
          if (typeof orig !== "function") continue;
          const wrapped = function (value, ...rest) {
            const c = caller();
            const store = (proto === IDBObjectStore.prototype)
              ? ((this && this.name) || "")
              : ((this && this.source && this.source.name) || "");
            try {
              let v = typeof value === "string" ? value
                : JSON.stringify(value);
              if (v !== undefined && v !== null && v.length > 2000) {
                v = v.slice(0, 2000);
              }
              emit("writes", {
                op: (proto === IDBObjectStore.prototype) ? op
                    : "cursor.update",
                db: (proto === IDBObjectStore.prototype) ? dbOf(this) : "",
                store, value: v,
                key: (rest[0] !== undefined && rest[0] !== null)
                      ? String(rest[0]).slice(0, 200) : "",
                fn: c.fn, loc: c.loc,
                t_rel: Math.round((self.performance
                                   && self.performance.now()) || 0),
              });
            } catch (e) {}
            return orig.apply(this, [value, ...rest]);
          };
          proto[op] = wrapped;
          refs["w_" + op + "_" + (proto === IDBObjectStore.prototype
                                  ? "store" : "cursor")] = wrapped;
        }
      }
    }
  } catch (e) {}
  // ── tamper detection: did page code unwrap our closures? ──
  H.__tamper_check = function () {
    const bad = [];
    try { if (refs.fetch && self.fetch !== refs.fetch) bad.push("fetch"); }
    catch (e) {}
    try {
      if (refs.xhr_open
          && XMLHttpRequest.prototype.open !== refs.xhr_open) {
        bad.push("xhr_open");
      }
    } catch (e) {}
    try {
      if (refs.xhr_send
          && XMLHttpRequest.prototype.send !== refs.xhr_send) {
        bad.push("xhr_send");
      }
    } catch (e) {}
    try {
      if (refs.sendBeacon && navigator.sendBeacon !== refs.sendBeacon) {
        bad.push("sendBeacon");
      }
    } catch (e) {}
    try {
      if (refs.idb_get
          && IDBObjectStore.prototype.get !== refs.idb_get) {
        bad.push("idb_get");
      }
    } catch (e) {}
    try {
      if (refs.w_put_store
          && IDBObjectStore.prototype.put !== refs.w_put_store) {
        bad.push("idb_put");
      }
    } catch (e) {}
    return bad;
  };
  self.__privadb_hooks_live = H;
  return H;
}"""

# Page glue: runs in every frame before any site script. The frame
# token is generated IN the page (per-frame unique, so BroadcastChannel
# events from another frame's workers can never land in this frame's
# arrays) — crypto.randomUUID on modern Firefox, entropy fallback.
_PAGE_GLUE = r"""(function () {
  const TOKEN = (self.crypto && crypto.randomUUID)
    ? crypto.randomUUID().replace(/-/g, "")
    : String(Math.random()).slice(2) + Date.now().toString(36);
  const INJECT = __PRIVADB_INJECT__;
  let core = null;
  try { core = (HOOK_CORE_PLACEHOLDER); } catch (e) { return; }
  // Blob bootstrap shared by the dedicated + shared worker wraps:
  // runs the core first, rebase-wraps importScripts so direct-child
  // relative imports resolve against the REAL script URL (probe16's
  // blob failure mode), then loads the original script.
  function makeBlob(abs, kind) {
    const src = "var __privadb_core = (" + core.toString() + ");\n"
      + "__privadb_core({kind:" + JSON.stringify(kind)
      + ", token:" + JSON.stringify(TOKEN) + "});\n"
      + "(function(){var __real=" + JSON.stringify(abs)
      + ";var __is=self.importScripts;if(__is){"
      + "self.importScripts=function(){"
      + "var a=Array.prototype.map.call(arguments,function(x){"
      + "try{return new URL(x,__real).href;}catch(e){return x;}});"
      + "return __is.apply(self,a);};}})();\n"
      + "importScripts(" + JSON.stringify(abs) + ");\n";
    return URL.createObjectURL(new Blob([src], {type: "text/javascript"}));
  }
  let H = null;
  try { H = core({ kind: "window", token: TOKEN }); } catch (e) { return; }
  // Only handlebar the drain depends on: non-enumerable, frozen —
  // readable by our evaluate (property access), invisible to
  // Object.keys/enumeration by site code.
  try {
    Object.defineProperty(self, "__prividb_hooks",
      { value: H, enumerable: false, writable: false,
        configurable: false });
  } catch (e) {
    try { self.__prividb_hooks = H; } catch (e2) {}
  }
  // ── relay: worker -> window events (token-filtered) ──
  try {
    const bus = new BroadcastChannel("__privadb_hook_bus__");
    bus.onmessage = function (e) {
      const d = e.data;
      if (!d || d.__privadb !== 1 || d.token !== TOKEN) return;
      if (d.hello) {
        const seen = H.meta.seen;
        const key = d.hello + "\u0000" + (d.loc || "");
        seen[key] = (seen[key] || 0) + 1;
        return;
      }
      if (d.arr && d.rec) {
        const a = H[d.arr];
        if (a) {
          const cap = d.arr === "responses" ? 300 : 1000;
          if (a.length >= cap) a.shift();
          a.push(d.rec);
        }
      }
    };
  } catch (e) {}
  // ── Worker: blob bootstrap (route-based injection removed — see
  // header: route.fulfill poisons worker cross-origin fetches on
  // Chromium). CSP-blocked blobs fall back to the original URL. ──
  if (INJECT) {
  try {
    const OW = self.Worker;
    if (typeof OW === "function") {
      const blobCache = Object.create(null);
      const W = function (u, o) {
        let abs;
        try { abs = new URL(u, self.location.href).href; }
        catch (e) { abs = String(u); }
        if (!/^https?:/i.test(abs)) {
          H.meta.gaps.push("non_http:" + abs.slice(0, 120));
          return new OW(u, o);
        }
        if (o && o.type === "module") {
          H.meta.gaps.push("dedicated_module:" + abs);
          return new OW(u, o);
        }
        try {
          if (!blobCache[abs]) blobCache[abs] = makeBlob(abs, "dedicated");
          const w = new OW(blobCache[abs], o);
          H.meta.spawned[blobCache[abs]] = "dedicated";
          return w;
        } catch (e) {
          H.meta.gaps.push("blob_blocked:" + abs.slice(0, 120));
          return new OW(u, o);
        }
      };
      self.Worker = W;
    }
  } catch (e) {}
  }
  // ── SharedWorker: blob bootstrap (route never sees these) ──
  if (INJECT) {
  try {
    const OS = self.SharedWorker;
    if (typeof OS === "function") {
      const blobCache = Object.create(null);
      const S = function (u, o) {
        let abs;
        try { abs = new URL(u, self.location.href).href; }
        catch (e) { abs = String(u); }
        if (!/^https?:/i.test(abs)) {
          H.meta.gaps.push("non_http:" + abs.slice(0, 120));
          return new OS(u, o);
        }
        if (o && o.type === "module") {
          H.meta.gaps.push("shared_module:" + abs);
          return new OS(u, o);
        }
        try {
          if (!blobCache[abs]) blobCache[abs] = makeBlob(abs, "shared");
          const w = new OS(blobCache[abs], o);
          H.meta.spawned[blobCache[abs]] = "shared";
          return w;
        } catch (e) {
          H.meta.gaps.push("blob_blocked:" + abs.slice(0, 120));
          return new OS(u, o);
        }
      };
      self.SharedWorker = S;
    }
  } catch (e) {}
  }
  // ── ServiceWorker: spawn accounting ONLY — never mark the URL.
  // Injection is unsafe/impossible on both engines (see header: FF
  // route bypass; Chromium route-fulfillment breaks the SW's own
  // cross-origin fetches). The SW runs clean so its exfil reaches the
  // sink for browser-side proof; the no-hello gap is recorded at drain.
  if (INJECT) {
  try {
    const swc = self.navigator && self.navigator.serviceWorker;
    if (swc && typeof swc.register === "function") {
      const OR = swc.register.bind(swc);
      swc.register = function (u, o) {
        let abs;
        try { abs = new URL(u, self.location.href).href; }
        catch (e) { abs = String(u); }
        if (!/^https?:/i.test(abs)) {
          H.meta.gaps.push("non_http:" + abs.slice(0, 120));
          return OR(u, o);
        }
        H.meta.spawned[abs] = "service";
        return OR(u, o);
      };
    }
  } catch (e) {}
  }
})();
"""

# Init script = glue with the core function expression spliced in and
# the worker-injection switch stamped in (evaluate --no-worker-injection
# produces the true BEFORE condition: window hooks on, no worker
# injection). One source of truth: HOOK_CORE_EXPR is embedded here AND
# (as source text via core.toString()) inside the worker blob
# bootstraps built by the glue below.
def hooks_init_script(worker_injection: bool = None) -> str:
    if worker_injection is None:
        worker_injection = getattr(
            config, "FLOW_WORKER_INJECTION_ENABLED", True)
    return (_PAGE_GLUE
            .replace("__PRIVADB_INJECT__",
                     "true" if worker_injection else "false")
            .replace("HOOK_CORE_PLACEHOLDER",
                     "(" + HOOK_CORE_EXPR + ")"))


# Back-compat alias (worker injection on).
FLOW_HOOKS_INIT_SCRIPT = hooks_init_script(True)

# ─── Other persistence mechanisms (Phase 6) ─────────────────────────
# localStorage / sessionStorage / cookies / Cache Storage / service
# workers, captured so IDB can be compared against every other store
# on one axis (the comparison the project title promises).
EXTRACT_OTHER_STORAGE_SCRIPT = r"""
async () => {
  const out = {localStorage: {}, sessionStorage: {}, cookies: [],
               caches: {}, service_workers: [], errors: []};
  const clip = (s, n) => (s && s.length > n) ? s.slice(0, n) : s;

  // Web Storage (capped: 200 entries each, values ≤2000 chars)
  for (const [name, store] of [["localStorage", window.localStorage],
                               ["sessionStorage", window.sessionStorage]]) {
    try {
      const n = store.length;
      for (let i = 0; i < n && i < 200; i++) {
        const k = store.key(i);
        out[name][k] = clip(String(store.getItem(k) ?? ""), 2000);
      }
    } catch (e) { out.errors.push(name + ": " + e); }
  }

  // Cookies (document.cookie; HttpOnly cookies are invisible here —
  // noted in the report as a measurement limitation)
  try {
    const raw = document.cookie || "";
    for (const pair of raw.split(";")) {
      const eq = pair.indexOf("=");
      if (eq === -1) continue;
      const k = pair.slice(0, eq).trim();
      const v = clip(pair.slice(eq + 1).trim(), 1000);
      if (k) out.cookies.push({name: k, value: v});
      if (out.cookies.length >= 100) break;
    }
  } catch (e) { out.errors.push("cookies: " + e); }

  // Cache Storage — names + request URLs (bodies stay out of the dump)
  try {
    if (window.caches && caches.keys) {
      const names = await caches.keys();
      for (const name of names.slice(0, 20)) {
        const cache = await caches.open(name);
        const reqs = await cache.keys();
        out.caches[name] = reqs.slice(0, 50).map((r) => r.url);
      }
    }
  } catch (e) { out.errors.push("caches: " + e); }

  // Service worker registrations
  try {
    if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {
      const regs = await navigator.serviceWorker.getRegistrations();
      out.service_workers = regs.slice(0, 20).map(
        (r) => (r.active || r.installing || r.waiting
                ? (r.active || r.installing || r.waiting).scriptURL
                : ""));
    }
  } catch (e) { out.errors.push("sw: " + e); }

  return out;
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

    def __init__(self, taint_capture: TaintCaptureServer = None, hooks: bool = False):
        self.network_requests = []
        self.taint_capture = taint_capture
        self.hooks = hooks

    async def _consent_phase(self, page, result: dict, action: str):
        """Phase 4: detect banner → snapshot IDB → act → snapshot again.

        Records result["consent"] = {action, banner, outcome, snapshots}.
        Snapshots are cheap IDB record listings at fixed milestones:
        post_load (before any interaction) and post_consent (after act).
        """
        import consent as consent_mod
        from schema import CONSENT_UNKNOWN

        rec = {"action": action, "banner": None, "outcome": None,
               "snapshots": {}, "click_ts": None, "t_rel_click": None}
        try:
            # let CMP scripts render
            await page.wait_for_timeout(1500)
            banner = await consent_mod.detect_banner(page)
            rec["banner"] = banner
            logger.info(
                f"  CMP: detected={banner['detected']} cmp={banner['cmp']} "
                f"action={action}"
            )

            # Snapshot A: post-load, before any consent interaction
            rec["snapshots"]["post_load"] = await self._idb_snapshot(page)

            # Act (or deliberately don't for action=none)
            t_click = None
            try:
                t_click = await page.evaluate(
                    "() => Math.round(performance.now())")
            except Exception:
                pass
            outcome = await consent_mod.act(page, banner, action)
            rec["outcome"] = outcome
            rec["click_ts"] = datetime.utcnow().isoformat() + "Z" if outcome.get("clicked") else None
            rec["t_rel_click"] = t_click
            if outcome.get("clicked"):
                logger.info(f"  Consent {action} clicked (state={outcome['state']})")
            elif outcome.get("error"):
                logger.warning(f"  Consent outcome: {outcome['error']}")

            # settle: consented scripts fire after the click
            await page.wait_for_timeout(3000)

            # Snapshot B: post-consent interaction
            rec["snapshots"]["post_consent"] = await self._idb_snapshot(page)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            rec["outcome"] = {"state": CONSENT_UNKNOWN, "clicked": False,
                              "method": None, "error": f"consent phase failed: {e}"}
            logger.warning(f"  Consent phase failed: {e}")
        result["consent"] = rec

    async def _idb_snapshot(self, page) -> dict:
        """Cheap IDB listing (db/store/key inventory, values clipped)."""
        try:
            data = await page.evaluate(EXTRACT_INDEXEDDB_SCRIPT)
            dbs = []
            total = 0
            for db in (data or {}).get("databases") or []:
                stores = []
                for st in db.get("stores") or []:
                    keys = [str(r.get("key", "")) for r in st.get("records") or []]
                    stores.append({"name": st.get("name", ""),
                                   "recordCount": st.get("recordCount", 0),
                                   "keys": keys[:50]})
                    total += st.get("recordCount", 0)
                dbs.append({"name": db.get("name", ""), "stores": stores})
            return {"db_count": len(dbs), "record_count": total,
                    "databases": dbs,
                    "ts": datetime.utcnow().isoformat() + "Z"}
        except Exception as e:
            return {"error": str(e), "db_count": 0, "record_count": 0}

    async def crawl_site(self, browser, url: str,
                         consent_action: str = None,
                         reload_check: bool = False) -> dict:
        """
        Visit a URL, extract IndexedDB data and captured network requests.

        consent_action: None (normal scan) or one of
        "none"/"accept"/"reject" — Phase 4 consent study. When set, the
        banner is detected after load, IDB is snapshotted pre- and
        post-act, and the outcome (state/click/error) is recorded in
        result["consent"].
        reload_check: paper §4.1 condition 2 — after extraction, reload
        the page in the SAME session and capture IDB again into
        result["reload_check"] so uid.py can verify value persistence.

        Returns a dict with keys: url, domain, timestamp, indexeddb,
        network_requests, consent.
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
        # Worker injection happens INSIDE the init script via blob
        # bootstraps (no network interception — see HOOK_CORE_EXPR header).
        if self.hooks:
            try:
                await context.add_init_script(
                    script=hooks_init_script())
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
            "other_storage": {"localStorage": {}, "sessionStorage": {},
                              "cookies": [], "caches": {},
                              "service_workers": [], "frames": [],
                              "errors": []},
            "network_requests": [],
            "taint_events": [],
            "flow_hooks": {"reads": [], "sends": [], "writes": [],
                           "responses": [], "meta": []},
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

            # ── Phase 4: consent handling + IDB snapshots ────────────
            if consent_action is not None:
                await self._consent_phase(page, result, consent_action)

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

                # Phase 6: other persistence mechanisms — same frames as
                # IDB so the comparison is on identical page state.
                other = {"localStorage": {}, "sessionStorage": {},
                         "cookies": [], "caches": {},
                         "service_workers": [], "frames": [],
                         "errors": []}
                for frame in frames:
                    try:
                        fo = await frame.evaluate(EXTRACT_OTHER_STORAGE_SCRIPT)
                        if not fo:
                            continue
                        other["frames"].append(
                            {"frame_url": frame.url,
                             "is_main_frame": frame == page.main_frame,
                             "localStorage": fo.get("localStorage", {}),
                             "sessionStorage": fo.get("sessionStorage", {}),
                             "cookies": fo.get("cookies", []),
                             "caches": fo.get("caches", {}),
                             "service_workers": fo.get("service_workers", [])})
                        # main-frame copy at top level for convenience
                        if frame == page.main_frame:
                            other["localStorage"] = fo.get("localStorage", {})
                            other["sessionStorage"] = fo.get("sessionStorage", {})
                            other["cookies"] = fo.get("cookies", [])
                            other["caches"] = fo.get("caches", {})
                            other["service_workers"] = fo.get(
                                "service_workers", [])
                        other["errors"].extend(fo.get("errors", []))
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        continue
                result["other_storage"] = other
                logger.info(
                    f"  Other storage: ls={len(other['localStorage'])} "
                    f"ss={len(other['sessionStorage'])} "
                    f"cookies={len(other['cookies'])} "
                    f"caches={len(other['caches'])} "
                    f"sw={len(other['service_workers'])}"
                )

                # ── Paper §4.1 C2: same-session reload persistence ──
                if reload_check:
                    try:
                        logger.info(
                            "  UID reload pass (paper condition 2) …")
                        await page.reload(
                            wait_until="domcontentloaded",
                            timeout=config.NAVIGATION_TIMEOUT)
                        await page.wait_for_timeout(
                            min(config.IDLE_WAIT, 4000))
                        after = {"databases": []}
                        for rframe in page.frames:
                            try:
                                fdata = await rframe.evaluate(
                                    EXTRACT_INDEXEDDB_SCRIPT)
                                for rdb in (fdata or {}).get(
                                        "databases") or []:
                                    rdb["frame_url"] = rframe.url
                                    after["databases"].append(rdb)
                            except asyncio.CancelledError:
                                raise
                            except Exception:
                                continue
                        result["reload_check"] = {
                            "after_indexeddb": after,
                            "ts": datetime.utcnow().isoformat() + "Z",
                        }
                        rn = sum(
                            len(s.get("records", []))
                            for d in after["databases"]
                            for s in d.get("stores", []))
                        logger.info(
                            f"  Reload check: {rn} records after reload")
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        result.setdefault("errors", []).append(
                            f"uid reload check failed: {e}")
                        logger.warning(
                            f"  UID reload check failed: {e}")
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
        # responses) — the same JS runs on both engines for comparability.
        # Worker/SharedWorker records were relayed into these arrays over
        # the token-filtered BroadcastChannel at emit time; meta carries
        # per-frame coverage accounting (spawned vs hello'd locations,
        # injection gaps, tamper check).
        if self.hooks:
            try:
                # Give in-flight BroadcastChannel relays a beat to land.
                await asyncio.sleep(0.4)
                hooks = {"reads": [], "sends": [], "writes": [],
                         "responses": [], "meta": []}
                drain_expr = (
                    "(() => { const H = window.__prividb_hooks;"
                    " if (!H) return null;"
                    " let tamper = null;"
                    " try { tamper = H.__tamper_check"
                    "          ? H.__tamper_check() : null; } catch (e) {}"
                    " return { reads: H.reads, sends: H.sends,"
                    "          writes: H.writes, responses: H.responses,"
                    "          meta: Object.assign({}, H.meta || {},"
                    "                             { tampered: tamper }) };"
                    " })()"
                )
                for frame in page.frames:
                    try:
                        frame_hooks = await frame.evaluate(drain_expr)
                        if frame_hooks:
                            for k in ("reads", "sends", "writes",
                                      "responses"):
                                hooks[k].extend(frame_hooks.get(k, []))
                            fmeta = frame_hooks.get("meta") or {}
                            # Coverage gap: spawned script locations with
                            # no corresponding worker hello (injection
                            # never ran in that context).
                            try:
                                spawned = set((fmeta.get("spawned") or {}).keys())
                                seen_locs = set()
                                for key in (fmeta.get("seen") or {}):
                                    seen_locs.add(
                                        key.split("\u0000", 1)[1])
                                missed = sorted(
                                    u for u in spawned
                                    if u not in seen_locs)
                                if missed:
                                    fmeta.setdefault("gaps", []).extend(
                                        ["no_hello:" + u
                                         for u in missed[:5]])
                            except Exception:
                                pass
                            fmeta["frame_url"] = frame.url
                            hooks["meta"].append(fmeta)
                    except Exception:
                        continue
                result["flow_hooks"] = hooks
                n_spawn = sum(
                    len(m.get("spawned") or {})
                    for m in hooks["meta"])
                n_gap = sum(
                    len(m.get("gaps") or []) for m in hooks["meta"])
                n_tamp = sum(
                    1 for m in hooks["meta"]
                    if m.get("tampered"))
                logger.info(
                    f"  Flow hooks: {len(hooks['reads'])} IDB reads, "
                    f"{len(hooks['sends'])} network sends, "
                    f"{len(hooks['writes'])} IDB writes, "
                    f"{len(hooks['responses'])} responses captured "
                    f"(worker spawns={n_spawn}, gaps={n_gap}, "
                    f"tampered_frames={n_tamp})"
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

        # Context teardown must never destroy an already-collected
        # crawl: the Foxhound driver occasionally dies during close
        # ("Connection closed while reading from the driver") after all
        # data was captured — tolerate it, record it, keep the result.
        try:
            await context.close()
        except Exception as close_err:
            logger.warning(
                f"  context.close failed (data kept): {close_err}")
            result.setdefault("errors", []).append(
                f"context close: {close_err}")
            try:
                _kill_browser_processes()
            except Exception:
                pass
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
                          check_command: Optional[Callable[[str], bool]] = None,
                          consent_study: bool = False,
                          partial_sink: Optional[dict] = None) -> List[dict]:
    """
    Crawl all sites and save per-site JSON output.

    Each site is crawled config.CRAWL_ITERATIONS times with a completely
    fresh browser instance each time. All iterations are stored so the
    detector can diff values across visits.

    Args:
        site_limit: Max number of sites to crawl (None = all)
        custom_sites: Optional list of site dicts [{"url": ..., "reason": ...}].
                      If provided, overrides sites.json.
        consent_study: Phase 4 — instead of plain iterations, run each
            site once per consent condition (no-interaction / accept-all /
            reject-all), each in a fresh context, recording banner
            detection + IDB snapshots before/after the click.
        partial_sink: optional dict the crawler mirrors the current
            site's completed iterations into after EVERY iteration —
            lets a cancellation handler persist "the current state"
            even when the crawl task is torn down mid-run.

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
    # Phase 4: consent study plan — one run per condition, fresh context
    consent_plan = ["none", "accept", "reject"]
    run_plan: List[tuple] = ([(idx, action)
                              for idx, action in enumerate(consent_plan, 1)]
                             if consent_study else
                             [(idx, None) for idx in range(1, iterations + 1)])
    logger.info(
        f"Starting crawl of {len(sites)} sites × {len(run_plan)} runs each"
        + (" (consent study)" if consent_study else "")
    )

    # Ensure output dirs
    os.makedirs(config.RAW_DATA_DIR, exist_ok=True)

    total_steps = len(sites) * len(run_plan)
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

        for iteration, consent_action in run_plan:
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
                run_label = (f"consent={consent_action}" if consent_action
                             else f"Iteration {iteration}/{len(run_plan)}")
                msg = f"Crawling {url} ({run_label})"
                if len(sites) > 1:
                    msg = f"[{i}/{len(sites)}] " + msg
                on_progress(progress_pct, msg)

            logger.info(
                f"  ── Run {iteration}/{len(run_plan)} (fresh browser)"
                + (f", consent={consent_action}" if consent_action else "")
                + " ──"
            )

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
                    if config.HEADLESS:
                        # Operator wants headless: NEVER touch the
                        # real X display (no windows on their screen)
                        # and no Xvfb — Firefox runs fully headless.
                        launch_headless = True
                        logger.info(
                            "🦊 Headless mode — no browser windows "
                            "(operator request: do not disturb)")
                    else:
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
                        hooks=bool(
                            config.TAINT_TRACKING_ENABLED
                            and getattr(config, "FLOW_HOOKS_ENABLED", True)),
                    )
                    skip_type = None
                    browser_version = ""
                    try:
                        browser_version = browser.version or ""
                    except Exception:
                        pass
                    
                    reload_ok = (consent_action is None
                                 and iteration == 1
                                 and bool(getattr(
                                     config, "UID_RELOAD_CHECK", False)))
                    if check_command:
                        crawl_task = asyncio.create_task(
                            crawler.crawl_site(browser, url,
                                               consent_action=consent_action,
                                               reload_check=reload_ok))
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
                        iter_result = await crawler.crawl_site(
                            browser, url, consent_action=consent_action,
                            reload_check=reload_ok)
                        iter_result["iteration"] = iteration
                        iter_result["browser_version"] = browser_version
                        site_iterations.append(iter_result)

                    # Phase stop-fix: mirror completed iterations so a
                    # mid-crawl cancellation can still save this state.
                    if partial_sink is not None:
                        partial_sink["url"] = url
                        partial_sink["timestamp"] = (
                            site_iterations[0].get("timestamp")
                            if site_iterations else None)
                        partial_sink["iterations"] = list(site_iterations)

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

            # Small delay between runs
            if (iteration, consent_action) != run_plan[-1]:
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
            "iterations": len(run_plan),
            "consent_study": bool(consent_study),
            "user_agent": config.USER_AGENT,
            "browser_version": site_iterations[-1].get("browser_version", ""),
            "playwright_version": _pw_version,
            "python_version": _sys.version.split()[0],
            "platform": platform.platform(),
            "taint_tracking_enabled": bool(getattr(config, "TAINT_TRACKING_ENABLED", False)),
            "captured_at": datetime.utcnow().isoformat() + "Z",
        }
        # Foxhound build pin (Phase 10): application.ini BuildID + binary
        # size — identifies the exact custom Firefox under test.
        try:
            ini = os.path.join(os.path.dirname(config.FOXHOUND_BIN),
                               "application.ini")
            with open(ini) as f:
                for line in f:
                    if line.startswith("BuildID="):
                        run_meta["foxhound_build_id"] = line.strip().split(
                            "=", 1)[1]
                        break
            run_meta["foxhound_bin_size"] = os.path.getsize(
                config.FOXHOUND_BIN)
        except Exception:
            pass
        combined = {
            "url": url,
            "domain": site_iterations[0]["domain"],
            "timestamp": site_iterations[0]["timestamp"],
            "iterations": site_iterations,
            "run_meta": run_meta,
            # Use the first iteration as the primary data for backward compat
            "indexeddb": site_iterations[0].get("indexeddb", {"databases": []}),
            "other_storage": site_iterations[0].get("other_storage", {
                "localStorage": {}, "sessionStorage": {}, "cookies": [],
                "caches": {}, "service_workers": [], "frames": [],
                "errors": [],
            }),
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

        logger.info(f"  Saved {len(run_plan)} runs → {out_path}")

        # Delay between sites
        if i < len(sites):
            await asyncio.sleep(2)

    logger.info(f"\n{'='*60}")
    logger.info(f"Crawl complete: {len(results)} sites × {len(run_plan)} runs")
    return results


if __name__ == "__main__":
    import sys
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    asyncio.run(crawl_all_sites(limit))
