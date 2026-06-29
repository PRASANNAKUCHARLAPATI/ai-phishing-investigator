from __future__ import annotations

import json
import logging
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DB_LOCK = threading.Lock()


@dataclass
class CaseRecord:
    case_id: str
    email_path: str
    case_dir: str
    verdict: str
    score: int
    confidence: str
    created_at: str
    updated_at: str


@dataclass
class IOCRecord:
    ioc_id: int
    case_id: str
    ioc_type: str
    value: str
    source: str
    first_seen: str
    last_seen: str
    seen_count: int


@dataclass
class ThreatDNA:
    case_id: str
    html_hash: str
    css_hash: str
    subject_pattern: str
    sender_domain: str
    registrar: str
    hosting_provider: str
    language: str
    timezone: str
    attachment_types: str
    form_action_domain: str
    url_patterns: str
    dna_vector: str


@dataclass
class CampaignRecord:
    campaign_id: str
    name: str
    description: str
    first_seen: str
    last_seen: str
    case_count: int
    confidence: str
    iocs: str


@dataclass
class AnalystNote:
    note_id: int
    case_id: str
    note: str
    created_at: str


@dataclass
class RuleSuggestion:
    rule_id: int
    case_id: str
    rule_type: str
    rule_content: str
    description: str
    created_at: str


class MemoryDB:
    def __init__(self, db_path: Path = Path("phishx_memory.db")):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _init_db(self) -> None:
        with _DB_LOCK:
            conn = self._conn()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    email_path TEXT NOT NULL,
                    case_dir TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    confidence TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS iocs (
                    ioc_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    seen_count INTEGER NOT NULL DEFAULT 1,
                    FOREIGN KEY (case_id) REFERENCES cases(case_id)
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_unique ON iocs(case_id, ioc_type, value);

                CREATE TABLE IF NOT EXISTS threat_dna (
                    case_id TEXT PRIMARY KEY,
                    html_hash TEXT,
                    css_hash TEXT,
                    subject_pattern TEXT,
                    sender_domain TEXT,
                    registrar TEXT,
                    hosting_provider TEXT,
                    language TEXT,
                    timezone TEXT,
                    attachment_types TEXT,
                    form_action_domain TEXT,
                    url_patterns TEXT,
                    dna_vector TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(case_id)
                );

                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    case_count INTEGER NOT NULL DEFAULT 0,
                    confidence TEXT NOT NULL,
                    iocs TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS case_campaigns (
                    case_id TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    PRIMARY KEY (case_id, campaign_id),
                    FOREIGN KEY (case_id) REFERENCES cases(case_id),
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id)
                );

                CREATE TABLE IF NOT EXISTS analyst_notes (
                    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(case_id)
                );

                CREATE TABLE IF NOT EXISTS rule_suggestions (
                    rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    rule_type TEXT NOT NULL,
                    rule_content TEXT NOT NULL,
                    description TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(case_id)
                );

                CREATE TABLE IF NOT EXISTS case_similarity (
                    case_a TEXT NOT NULL,
                    case_b TEXT NOT NULL,
                    similarity REAL NOT NULL,
                    reason TEXT,
                    PRIMARY KEY (case_a, case_b),
                    FOREIGN KEY (case_a) REFERENCES cases(case_id),
                    FOREIGN KEY (case_b) REFERENCES cases(case_id)
                );
            """)
            conn.commit()

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    def save_case(self, case_id: str, email_path: str, case_dir: str,
                  verdict: str, score: int, confidence: str) -> None:
        now = datetime.utcnow().isoformat()
        with _DB_LOCK, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO cases (case_id, email_path, case_dir, verdict, score, confidence, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM cases WHERE case_id=?), ?), ?)""",
                (case_id, str(email_path), str(case_dir), verdict, score, confidence, case_id, now, now),
            )
            conn.commit()

    def save_iocs(self, case_id: str, iocs: Dict[str, List[str]], source: str = "parser") -> None:
        now = datetime.utcnow().isoformat()
        with _DB_LOCK, self._conn() as conn:
            for ioc_type, values in iocs.items():
                for value in values:
                    row = conn.execute(
                        """SELECT ioc_id, seen_count FROM iocs WHERE case_id=? AND ioc_type=? AND value=?""",
                        (case_id, ioc_type, value),
                    ).fetchone()
                    if row:
                        conn.execute(
                            """UPDATE iocs SET last_seen=?, seen_count=?, source=? WHERE ioc_id=?""",
                            (now, row["seen_count"] + 1, source, row["ioc_id"]),
                        )
                    else:
                        conn.execute(
                            """INSERT INTO iocs (case_id, ioc_type, value, source, first_seen, last_seen, seen_count)
                               VALUES (?, ?, ?, ?, ?, ?, 1)""",
                            (case_id, ioc_type, value, source, now, now),
                        )
            conn.commit()

    def save_threat_dna(self, case_id: str, dna: Dict[str, Any]) -> None:
        with _DB_LOCK, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO threat_dna
                   (case_id, html_hash, css_hash, subject_pattern, sender_domain, registrar,
                    hosting_provider, language, timezone, attachment_types, form_action_domain,
                    url_patterns, dna_vector)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    case_id,
                    dna.get("html_hash", ""),
                    dna.get("css_hash", ""),
                    dna.get("subject_pattern", ""),
                    dna.get("sender_domain", ""),
                    dna.get("registrar", ""),
                    dna.get("hosting_provider", ""),
                    dna.get("language", ""),
                    dna.get("timezone", ""),
                    json.dumps(dna.get("attachment_types", [])),
                    dna.get("form_action_domain", ""),
                    json.dumps(dna.get("url_patterns", [])),
                    json.dumps(dna.get("dna_vector", {})),
                ),
            )
            conn.commit()

    def save_campaign(self, campaign_id: str, name: str, description: str,
                      case_ids: List[str], iocs: Dict[str, List[str]], confidence: str = "MEDIUM") -> None:
        now = datetime.utcnow().isoformat()
        with _DB_LOCK, self._conn() as conn:
            row = conn.execute("SELECT case_count FROM campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
            existing_cases = json.loads(row["case_count"]) if row else []
            for c in case_ids:
                if c not in existing_cases:
                    existing_cases.append(c)
            conn.execute(
                """INSERT OR REPLACE INTO campaigns
                   (campaign_id, name, description, first_seen, last_seen, case_count, confidence, iocs)
                   VALUES (?, ?, ?, COALESCE((SELECT first_seen FROM campaigns WHERE campaign_id=?), ?), ?, ?, ?, ?)""",
                (
                    campaign_id, name, description, campaign_id,
                    now, now, json.dumps(existing_cases), confidence,
                    json.dumps(iocs),
                ),
            )
            for case_id in case_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO case_campaigns (case_id, campaign_id) VALUES (?, ?)",
                    (case_id, campaign_id),
                )
            conn.commit()

    def link_cases(self, case_a: str, case_b: str, similarity: float, reason: str = "") -> None:
        with _DB_LOCK, self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO case_similarity (case_a, case_b, similarity, reason)
                   VALUES (?, ?, ?, ?)""",
                (case_a, case_b, similarity, reason),
            )
            conn.commit()

    def add_analyst_note(self, case_id: str, note: str) -> int:
        now = datetime.utcnow().isoformat()
        with _DB_LOCK, self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO analyst_notes (case_id, note, created_at) VALUES (?, ?, ?)",
                (case_id, note, now),
            )
            conn.commit()
            return cur.lastrowid

    def save_rule_suggestion(self, case_id: str, rule_type: str, rule_content: str, description: str) -> int:
        now = datetime.utcnow().isoformat()
        with _DB_LOCK, self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO rule_suggestions (case_id, rule_type, rule_content, description, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (case_id, rule_type, rule_content, description, now),
            )
            conn.commit()
            return cur.lastrowid

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        return dict(row) if row else None

    def get_case_iocs(self, case_id: str) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute("SELECT * FROM iocs WHERE case_id=?", (case_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_ioc_history(self, value: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self._conn()
        if ioc_type:
            rows = conn.execute(
                "SELECT * FROM iocs WHERE value=? AND ioc_type=? ORDER BY last_seen DESC",
                (value, ioc_type),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM iocs WHERE value=? ORDER BY last_seen DESC",
                (value,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_related_cases(self, case_id: str, min_similarity: float = 0.3) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            """SELECT c.*, s.similarity, s.reason
               FROM case_similarity s
               JOIN cases c ON (c.case_id = s.case_b OR c.case_id = s.case_a)
               WHERE (s.case_a=? OR s.case_b=?) AND s.similarity >= ?
               AND c.case_id != ?""",
            (case_id, case_id, min_similarity, case_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_campaigns_for_case(self, case_id: str) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            """SELECT c.* FROM campaigns c
               JOIN case_campaigns cc ON c.campaign_id = cc.campaign_id
               WHERE cc.case_id=?""",
            (case_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_analyst_notes(self, case_id: str) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM analyst_notes WHERE case_id=? ORDER BY created_at DESC",
            (case_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_rule_suggestions(self, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self._conn()
        if case_id:
            rows = conn.execute(
                "SELECT * FROM rule_suggestions WHERE case_id=? ORDER BY created_at DESC",
                (case_id,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM rule_suggestions ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def get_top_iocs(self, limit: int = 20, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = self._conn()
        query = """SELECT value, ioc_type, SUM(seen_count) as total_seen, COUNT(DISTINCT case_id) as case_count,
                          MAX(last_seen) as last_seen
                   FROM iocs"""
        params: List[Any] = []
        if ioc_type:
            query += " WHERE ioc_type=?"
            params.append(ioc_type)
        query += " GROUP BY value, ioc_type ORDER BY total_seen DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_all_cases(self) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def get_threat_dna(self, case_id: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM threat_dna WHERE case_id=?", (case_id,)).fetchone()
        return dict(row) if row else None

    def find_similar_dna(self, dna_vector: Dict[str, Any], threshold: float = 0.7) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute("SELECT case_id, dna_vector FROM threat_dna").fetchall()
        results = []
        target = json.dumps(dna_vector, sort_keys=True)
        for row in rows:
            try:
                existing = json.loads(row["dna_vector"])
                if not existing:
                    continue
                match_score = self._dna_similarity(dna_vector, existing)
                if match_score >= threshold:
                    results.append({
                        "case_id": row["case_id"],
                        "similarity": round(match_score, 2),
                    })
            except Exception:
                continue
        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:10]

    def _dna_similarity(self, a: Dict[str, Any], b: Dict[str, Any]) -> float:
        if not a or not b:
            return 0.0
        matches = 0
        total = 0
        for key in a:
            if key in b:
                total += 1
                if a[key] and b[key] and a[key] == b[key]:
                    matches += 1
        return matches / total if total > 0 else 0.0


_db_instance: Optional[MemoryDB] = None


def get_db(db_path: Optional[Path] = None) -> MemoryDB:
    global _db_instance
    if _db_instance is None:
        _db_instance = MemoryDB(db_path=db_path or Path("phishx_memory.db"))
    return _db_instance
