"""HistoryStore: SQLite-backed scan history and differential analysis.

Every completed scan is persisted so the agent team can answer "what changed?"
— new CVEs since last scan, resolved findings, and posture trend over time.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

from macsec.models import utcnow
from macsec.utils import cache_dir

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    hostname TEXT, model TEXT, chip TEXT, macos TEXT,
    macsec_score REAL, grade TEXT, stats_json TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    cve_id TEXT NOT NULL, target TEXT NOT NULL,
    tier TEXT, score REAL, exploited INTEGER,
    PRIMARY KEY (scan_id, cve_id, target)
);
"""


class HistoryStore:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or cache_dir() / "history.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------- write

    def record_scan(self, ctx) -> int:
        """Persist the current orchestration context; returns the scan id."""
        inv = ctx.inventory
        a = ctx.analysis
        score_info = a.stats.get("macsec_score", {})
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO scans (ts, hostname, model, chip, macos, macsec_score, grade, stats_json)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (utcnow(),
                 inv.hostname if inv else "", inv.model if inv else "",
                 inv.chip if inv else "", inv.macos_product_version if inv else "",
                 score_info.get("score"), score_info.get("grade", ""),
                 json.dumps(a.stats)))
            scan_id = cur.lastrowid
            conn.executemany(
                "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?)",
                [(scan_id, r.match.cve.cve_id, r.match.target, r.tier, r.score,
                  1 if r.match.cve.exploited else 0) for r in a.risks])
        return scan_id

    # ------------------------------------------------------------- read

    def list_scans(self, limit: int = 20) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: int) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            findings = conn.execute(
                "SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
        if row is None:
            return None
        return {**dict(row), "findings": [dict(f) for f in findings]}

    def diff(self, old_id: int, new_id: int) -> Optional[dict]:
        """Compare two scans: new findings, resolved findings, score movement."""
        old, new = self.get_scan(old_id), self.get_scan(new_id)
        if old is None or new is None:
            return None

        def key(f):
            return (f["cve_id"], f["target"])

        old_map, new_map = {key(f): f for f in old["findings"]}, {key(f): f for f in new["findings"]}
        added = [new_map[k] for k in new_map.keys() - old_map.keys()]
        resolved = [old_map[k] for k in old_map.keys() - new_map.keys()]
        persistent = [new_map[k] for k in new_map.keys() & old_map.keys()]
        escalated = [f for f in persistent
                     if f["exploited"] and not old_map[key(f)]["exploited"]]
        return {
            "old_scan": {"id": old_id, "ts": old["ts"], "macos": old["macos"]},
            "new_scan": {"id": new_id, "ts": new["ts"], "macos": new["macos"]},
            "new_findings": sorted(added, key=lambda f: -(f["score"] or 0)),
            "resolved_findings": sorted(resolved, key=lambda f: -(f["score"] or 0)),
            "persistent_findings": sorted(persistent, key=lambda f: -(f["score"] or 0)),
            "newly_exploited": escalated,
            "score_delta": ((new.get("macsec_score") or 0) - (old.get("macsec_score") or 0)),
            "grade_old": old.get("grade", ""), "grade_new": new.get("grade", ""),
        }
