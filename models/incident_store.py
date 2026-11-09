"""
models/incident_store.py
------------------------
SQLite-backed persistent Incident Store for MedFlow AI.

Enables long-term persistence, audit trail archiving, and historical query capabilities:
  - `save_incident`: Persists/updates an incident record (from dict or Incident object).
  - `get_incident`: Retrieves a full incident state dictionary by `incident_id`.
  - `list_incidents`: Retrieves recent incidents with optional status/category filtering.
  - `get_audit_trail`: Extracts the append-only audit trail for compliance auditing.
  - `delete_incident`: Utility for test cleanup.

Database schema:
  - Table `incidents`: Contains indexed columns (incident_id, title, category, status, severity, risk_score, created_at, closed_at) and a full JSON payload column.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

from config import DATA_DIR

logger = logging.getLogger("medflow.models.incident_store")

DEFAULT_DB_PATH = DATA_DIR / "incidents.db"


class IncidentStore:
    """Persistent SQLite store for MedFlow AI incident records."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables and indexes if they do not exist."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT,
                    category TEXT,
                    status TEXT,
                    severity INTEGER,
                    risk_score INTEGER,
                    created_at TEXT,
                    closed_at TEXT,
                    data_json TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_category ON incidents(category)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at)")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS email_notifications (
                    incident_id TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 1,
                    last_error TEXT,
                    claimed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    sent_at TIMESTAMP,
                    PRIMARY KEY (incident_id, recipient)
                )
            """)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(email_notifications)")}
            if "attempt_count" not in columns:
                conn.execute("ALTER TABLE email_notifications ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 1")
            if "last_error" not in columns:
                conn.execute("ALTER TABLE email_notifications ADD COLUMN last_error TEXT")
            conn.commit()

    def claim_notification(self, incident_id: str, recipient: str) -> bool:
        """Reserve a send atomically; a crashed in-progress claim expires after 15 minutes."""
        recipient = recipient.casefold()
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            # SMTP acceptance cannot be queried atomically with SQLite. Mark an
            # expired in-flight attempt uncertain instead of blindly resending;
            # the relay may already have accepted it before a process crash.
            conn.execute(
                "UPDATE email_notifications SET status='uncertain', last_error='delivery_state_unknown' "
                "WHERE incident_id=? AND recipient=? AND status='sending' "
                "AND claimed_at < datetime('now', '-15 minutes')",
                (incident_id, recipient),
            )
            cursor = conn.execute(
                "INSERT INTO email_notifications (incident_id, recipient, status) VALUES (?, ?, 'sending') "
                "ON CONFLICT(incident_id, recipient) DO UPDATE SET "
                "status='sending', attempt_count=email_notifications.attempt_count + 1, "
                "last_error=NULL, claimed_at=CURRENT_TIMESTAMP, sent_at=NULL "
                "WHERE email_notifications.status IN ('failed', 'pending')",
                (incident_id, recipient),
            )
            conn.commit()
            return cursor.rowcount == 1

    def complete_notification(self, incident_id: str, recipient: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE email_notifications SET status = 'sent', sent_at = CURRENT_TIMESTAMP "
                ", last_error=NULL WHERE incident_id = ? AND recipient = ? AND status = 'sending'",
                (incident_id, recipient.casefold()),
            )
            conn.commit()

    def fail_notification(self, incident_id: str, recipient: str, error_code: str) -> None:
        """Keep a retryable failure record without retaining SMTP response text or credentials."""
        safe_code = "".join(character for character in str(error_code).casefold() if character.isalnum() or character in "_-")[:80]
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE email_notifications SET status='failed', last_error=?, sent_at=NULL "
                "WHERE incident_id=? AND recipient=? AND status='sending'",
                (safe_code or "delivery_failed", incident_id, recipient.casefold()),
            )
            conn.commit()

    def release_notification(self, incident_id: str, recipient: str) -> None:
        with self._get_connection() as conn:
            conn.execute(
                "DELETE FROM email_notifications WHERE incident_id = ? AND recipient = ? AND status = 'sending'",
                (incident_id, recipient.casefold()),
            )
            conn.commit()

    def save_incident(self, incident: dict[str, Any] | Any, *, notification_recipient: str | None = None) -> str:
        """
        Saves or updates an incident record in the database.
        Accepts either a state dictionary or an Incident dataclass instance.
        """
        if hasattr(incident, "to_dict"):
            data = incident.to_dict()
        elif isinstance(incident, dict):
            data = dict(incident)
        else:
            raise TypeError(f"Expected dict or Incident instance, got {type(incident).__name__}")

        incident_id = data.get("incident_id")
        if not incident_id:
            raise ValueError("Incident data must contain a valid 'incident_id'.")

        title = str(data.get("incident_title") or data.get("title") or "Untitled Incident")
        category = str(data.get("incident_category") or data.get("category") or "Unknown")
        status = str(data.get("incident_status") or data.get("status") or "investigating")
        severity = int(data.get("severity") or 0)
        risk_score = int(data.get("risk_score") or 0)
        created_at = str(data.get("timestamp") or data.get("detection_time") or "")
        closed_at = str(data.get("closure_time") or "")

        data_json = json.dumps(data, indent=None)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO incidents (incident_id, title, category, status, severity, risk_score, created_at, closed_at, data_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(incident_id) DO UPDATE SET
                    title=excluded.title,
                    category=excluded.category,
                    status=excluded.status,
                    severity=excluded.severity,
                    risk_score=excluded.risk_score,
                    closed_at=excluded.closed_at,
                    data_json=excluded.data_json,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (incident_id, title, category, status, severity, risk_score, created_at, closed_at, data_json),
            )
            if notification_recipient:
                conn.execute(
                    "INSERT OR IGNORE INTO email_notifications "
                    "(incident_id, recipient, status, attempt_count) VALUES (?, ?, 'pending', 0)",
                    (incident_id, notification_recipient.strip().casefold()),
                )
            conn.commit()

        logger.info(f"Incident {incident_id} saved to persistent store ({self.db_path}). Status: '{status}'")
        return incident_id

    def list_pending_notifications(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return durable notification outbox rows with their persisted incident payloads."""
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE email_notifications SET status='uncertain', last_error='delivery_state_unknown' "
                "WHERE status='sending' AND claimed_at < datetime('now', '-15 minutes')"
            )
            rows = conn.execute(
                "SELECT n.incident_id, n.recipient, i.data_json FROM email_notifications n "
                "JOIN incidents i ON i.incident_id=n.incident_id "
                "WHERE n.status='pending' OR "
                "(n.status='failed' AND n.claimed_at < datetime('now', '-1 minute')) "
                "ORDER BY n.claimed_at LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
        return [
            {"incident_id": row["incident_id"], "recipient": row["recipient"], "incident": json.loads(row["data_json"])}
            for row in rows
        ]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        """Retrieves a full incident dictionary by ID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT data_json FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if row and row["data_json"]:
                return json.loads(row["data_json"])
        return None

    def list_incidents(
        self,
        limit: int = 50,
        status: str | None = None,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Lists recent incidents with optional filtering."""
        query = "SELECT data_json FROM incidents"
        params: list[Any] = []
        conditions: list[str] = []

        if status:
            conditions.append("status = ?")
            params.append(status)

        if category:
            conditions.append("category = ?")
            params.append(category)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)

        results: list[dict[str, Any]] = []
        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            for row in rows:
                if row["data_json"]:
                    results.append(json.loads(row["data_json"]))

        return results

    def get_audit_trail(self, incident_id: str) -> list[dict[str, Any]]:
        """Extracts the audit trail array for a given incident."""
        incident = self.get_incident(incident_id)
        if incident:
            return incident.get("audit_log") or []
        return []

    def delete_incident(self, incident_id: str) -> bool:
        """Deletes an incident by ID (useful for tests)."""
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM incidents WHERE incident_id = ?", (incident_id,))
            conn.commit()
            return cursor.rowcount > 0
