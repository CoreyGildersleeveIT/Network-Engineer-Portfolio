"""
SQLite database layer for persistent storage of scan results,
profiles, credentials metadata, and device records.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator, Optional

from .config import get_db_path


class Database:
    """SQLite database manager."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = str(db_path or get_db_path())
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # --- Scan Sessions ---

    def create_scan_session(self, profile_id: str, profile_name: str,
                            scanner_host: str, scanner_ip: str) -> str:
        """Create a new scan session, return its ID."""
        import uuid
        session_id = str(uuid.uuid4())
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO scan_sessions
                   (id, profile_id, profile_name, scanner_host, scanner_ip,
                    start_time, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (session_id, profile_id, profile_name, scanner_host,
                 scanner_ip, datetime.now().isoformat(), "running"),
            )
        return session_id

    def finish_scan_session(self, session_id: str, status: str = "completed",
                            summary_json: str = "{}") -> None:
        with self._connect() as conn:
            conn.execute(
                """UPDATE scan_sessions
                   SET end_time = ?, status = ?, summary_json = ?
                   WHERE id = ?""",
                (datetime.now().isoformat(), status, summary_json, session_id),
            )

    def get_scan_sessions(self, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_sessions ORDER BY start_time DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan_session(self, session_id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scan_sessions WHERE id = ?", (session_id,),
            ).fetchone()
        return dict(row) if row else None

    # --- Device Records ---

    def upsert_device(self, session_id: str, device_dict: dict) -> None:
        """Insert or update a device record for a scan session."""
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO devices
                   (id, session_id, ip_address, mac_address, vendor,
                    hostname, dns_name, os_hint, device_role, is_alive,
                    ip_assignment, domain, open_ports_json, switch_port_json,
                    full_json, overall_confidence, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    device_dict.get("id", ""),
                    session_id,
                    device_dict.get("ip_address", {}).get("value", ""),
                    device_dict.get("mac_address", {}).get("value", ""),
                    device_dict.get("vendor", {}).get("value", ""),
                    device_dict.get("hostname", {}).get("value", ""),
                    device_dict.get("dns_name", {}).get("value", ""),
                    device_dict.get("os_hint", {}).get("value", ""),
                    device_dict.get("device_role", {}).get("value", "unknown"),
                    1 if device_dict.get("is_alive", {}).get("value") else 0,
                    device_dict.get("ip_assignment", {}).get("value", "unknown"),
                    device_dict.get("domain", {}).get("value", ""),
                    json.dumps(device_dict.get("open_ports", [])),
                    json.dumps(device_dict.get("switch_port")),
                    json.dumps(device_dict),
                    device_dict.get("overall_confidence", 0),
                    device_dict.get("first_seen", ""),
                    device_dict.get("last_seen", ""),
                ),
            )

    def get_devices(self, session_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM devices WHERE session_id = ? ORDER BY ip_address",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_device_full(self, device_id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT full_json FROM devices WHERE id = ?", (device_id,),
            ).fetchone()
        if row:
            return json.loads(row["full_json"])
        return None

    # --- Profiles ---

    def save_profile(self, profile_dict: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO profiles (id, name, json_data, modified)
                   VALUES (?, ?, ?, ?)""",
                (
                    profile_dict["id"],
                    profile_dict["name"],
                    json.dumps(profile_dict),
                    datetime.now().isoformat(),
                ),
            )

    def get_profiles(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM profiles ORDER BY modified DESC"
            ).fetchall()
        return [json.loads(r["json_data"]) for r in rows]

    def delete_profile(self, profile_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))

    # --- Credentials Metadata ---

    def save_credential_meta(self, cred_dict: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO credentials
                   (id, name, cred_type, username, domain, secret_ref, created)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    cred_dict["id"],
                    cred_dict["name"],
                    cred_dict.get("cred_type", ""),
                    cred_dict.get("username", ""),
                    cred_dict.get("domain", ""),
                    cred_dict.get("secret_ref", ""),
                    cred_dict.get("created", datetime.now().isoformat()),
                ),
            )

    def get_credentials(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM credentials ORDER BY name"
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_credential(self, cred_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))

    # --- Topology Edges ---

    def save_topology_edge(self, session_id: str, src: str, dst: str,
                           edge_type: str, details_json: str = "{}") -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO topology_edges
                   (session_id, source_id, target_id, edge_type, details_json)
                   VALUES (?, ?, ?, ?, ?)""",
                (session_id, src, dst, edge_type, details_json),
            )

    def get_topology_edges(self, session_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM topology_edges WHERE session_id = ?",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    profile_id TEXT,
    profile_name TEXT,
    scanner_host TEXT,
    scanner_ip TEXT,
    start_time TEXT,
    end_time TEXT,
    status TEXT DEFAULT 'running',
    summary_json TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    ip_address TEXT,
    mac_address TEXT,
    vendor TEXT,
    hostname TEXT,
    dns_name TEXT,
    os_hint TEXT,
    device_role TEXT DEFAULT 'unknown',
    is_alive INTEGER DEFAULT 0,
    ip_assignment TEXT DEFAULT 'unknown',
    domain TEXT,
    open_ports_json TEXT DEFAULT '[]',
    switch_port_json TEXT DEFAULT 'null',
    full_json TEXT DEFAULT '{}',
    overall_confidence REAL DEFAULT 0.0,
    first_seen TEXT,
    last_seen TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_devices_session ON devices(session_id);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);

CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    json_data TEXT DEFAULT '{}',
    modified TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    cred_type TEXT,
    username TEXT,
    domain TEXT,
    secret_ref TEXT,
    created TEXT
);

CREATE TABLE IF NOT EXISTS topology_edges (
    session_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    edge_type TEXT,
    details_json TEXT DEFAULT '{}',
    PRIMARY KEY (session_id, source_id, target_id),
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);
"""
