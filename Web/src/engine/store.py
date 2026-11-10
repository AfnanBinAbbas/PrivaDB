"""
Job/result store for scale crawls (Phase 8).

SQLite when the interpreter has _sqlite3 (typical system Pythons);
JSONL checkpoint fallback otherwise (some minimal builds lack the
extension — e.g. this project's default venv). Both backends expose
the same interface:

    store.ensure(url)              upsert a pending job (idempotent)
    store.pending() -> [urls]      jobs not yet done/failed-permanent
    store.mark(url, status, ...)   done | failed | running(+error)
    store.completed() -> set[str]
    store.counts() -> dict         {status: n}
    store.summary(url) -> dict|None small per-site summary

Resume = call ensure() for every wanted url; anything already done is
left untouched.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Optional

try:  # sqlite availability varies by interpreter build (some minimal
      # Pythons ship without _sqlite3 — fall back to JSONL there)
    import sqlite3 as _sq
    _sq.connect(":memory:").close()
    _HAS_SQLITE = True
except Exception:
    _sq = None
    _HAS_SQLITE = False


class SiteStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.mode = "sqlite" if _HAS_SQLITE and not db_path.endswith(
            ".jsonl") else "jsonl"
        self._lock = threading.Lock()
        self._jobs: dict[str, dict] = {}   # url → record (jsonl mode)
        if self.mode == "sqlite":
            # venv pythons may lack _sqlite3 — fall back at open time
            try:
                self._conn = _sq.connect(db_path, check_same_thread=False)
                self._init_sqlite()
            except Exception:
                self.mode = "jsonl"
                self._conn = None
        if self.mode == "jsonl":
            self._jsonl_path = db_path if db_path.endswith(".jsonl") \
                else os.path.splitext(db_path)[0] + ".jsonl"
            self._load_jsonl()
        os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".",
                    exist_ok=True)

    # ── sqlite backend ──
    def _init_sqlite(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS sites (
                url TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                summary TEXT,
                updated_at REAL
            )""")
        self._conn.commit()

    def _load_jsonl(self):
        if not os.path.exists(getattr(self, "_jsonl_path", "")):
            return
        with open(self._jsonl_path) as f:
            for line in f:
                try:
                    r = json.loads(line)
                    if r.get("url"):
                        self._jobs[r["url"]] = r
                except Exception:
                    continue

    def _dump_jsonl_locked(self):
        tmp = self._jsonl_path + ".tmp"
        with open(tmp, "w") as f:
            for r in self._jobs.values():
                f.write(json.dumps(r) + "\n")
        os.replace(tmp, self._jsonl_path)

    # ── interface ──
    def ensure(self, url: str):
        with self._lock:
            if self.mode == "sqlite":
                cur = self._conn.execute(
                    "INSERT OR IGNORE INTO sites (url) VALUES (?)", (url,))
                if cur.rowcount:
                    self._conn.commit()
            else:
                if url not in self._jobs:
                    self._jobs[url] = {
                        "url": url, "status": "pending", "attempts": 0,
                        "error": None, "summary": None,
                        "updated_at": time.time()}
                    self._dump_jsonl_locked()

    def ensure_many(self, urls: list[str]):
        """Idempotent batch upsert — one dump instead of N rewrites
        (the per-call ensure is O(n²) on the jsonl backend at 10k)."""
        with self._lock:
            added = False
            if self.mode == "sqlite":
                for u in urls:
                    cur = self._conn.execute(
                        "INSERT OR IGNORE INTO sites (url) VALUES (?)",
                        (u,))
                    added = added or bool(cur.rowcount)
                if added:
                    self._conn.commit()
            else:
                for u in urls:
                    if u not in self._jobs:
                        self._jobs[u] = {
                            "url": u, "status": "pending",
                            "attempts": 0, "error": None,
                            "summary": None, "updated_at": time.time()}
                        added = True
                if added:
                    self._dump_jsonl_locked()

    def mark(self, url: str, status: str, error: Optional[str] = None,
             summary: Optional[dict] = None, bump_attempt: bool = False):
        with self._lock:
            if self.mode == "sqlite":
                self._conn.execute(
                    """UPDATE sites SET status=?, error=?,
                       summary=COALESCE(?, summary),
                       attempts=attempts+?,
                       updated_at=? WHERE url=?""",
                    (status, error, json.dumps(summary) if summary else None,
                     1 if bump_attempt else 0, time.time(), url))
                self._conn.commit()
            else:
                r = self._jobs.setdefault(url, {
                    "url": url, "status": "pending", "attempts": 0})
                r["status"] = status
                if error is not None:
                    r["error"] = error
                if summary is not None:
                    r["summary"] = summary
                if bump_attempt:
                    r["attempts"] = int(r.get("attempts", 0)) + 1
                r["updated_at"] = time.time()
                self._dump_jsonl_locked()

    def _rows(self) -> list[dict]:
        if self.mode == "sqlite":
            cur = self._conn.execute(
                "SELECT url, status, attempts, error, summary FROM sites")
            return [{"url": u, "status": s, "attempts": a, "error": e,
                     "summary": json.loads(s2) if s2 else None}
                    for u, s, a, e, s2 in cur.fetchall()]
        return list(self._jobs.values())

    def pending(self) -> list[str]:
        return [r["url"] for r in self._rows()
                if r["status"] in ("pending", "running", "failed")]

    def completed(self) -> set[str]:
        return {r["url"] for r in self._rows() if r["status"] == "done"}

    def counts(self) -> dict:
        out: dict[str, int] = {}
        for r in self._rows():
            out[r["status"]] = out.get(r["status"], 0) + 1
        return out

    def summary(self, url: str) -> Optional[dict]:
        for r in self._rows():
            if r["url"] == url:
                return r.get("summary")
        return None

    def all_done(self) -> bool:
        return all(r["status"] in ("done", "permanent_failed")
                   for r in self._rows())
