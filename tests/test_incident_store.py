"""
tests/test_incident_store.py
-----------------------------
Unit tests for models/incident_store.py (SQLite Persistent Incident Store).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from models.incident_store import IncidentStore


@pytest.fixture
def temp_store(tmp_path: Path) -> IncidentStore:
    db_file = tmp_path / "test_incidents.db"
    return IncidentStore(db_path=db_file)


def test_save_and_get_incident(temp_store: IncidentStore) -> None:
    sample_incident = {
        "incident_id": "INC-TEST-101",
        "incident_title": "Test Ransomware Outbreak",
        "incident_category": "Ransomware",
        "incident_status": "contained",
        "severity": 14,
        "risk_score": 88,
        "timestamp": "2026-07-28T12:00:00Z",
        "closure_time": "2026-07-28T12:05:00Z",
        "audit_log": [
            {
                "actor": "system:closure_node",
                "timestamp": "2026-07-28T12:05:00Z",
                "action": "INCIDENT_CLOSED",
                "justification": "Contained successfully.",
            }
        ],
    }

    saved_id = temp_store.save_incident(sample_incident)
    assert saved_id == "INC-TEST-101"

    fetched = temp_store.get_incident("INC-TEST-101")
    assert fetched is not None
    assert fetched["incident_title"] == "Test Ransomware Outbreak"
    assert fetched["incident_status"] == "contained"


def test_list_and_filter_incidents(temp_store: IncidentStore) -> None:
    inc1 = {"incident_id": "INC-1", "incident_title": "Brute Force 1", "incident_category": "Credential Access", "incident_status": "contained"}
    inc2 = {"incident_id": "INC-2", "incident_title": "Ransomware 2", "incident_category": "Ransomware", "incident_status": "escalated"}
    inc3 = {"incident_id": "INC-3", "incident_title": "Brute Force 3", "incident_category": "Credential Access", "incident_status": "contained"}

    temp_store.save_incident(inc1)
    temp_store.save_incident(inc2)
    temp_store.save_incident(inc3)

    all_incidents = temp_store.list_incidents()
    assert len(all_incidents) == 3

    contained = temp_store.list_incidents(status="contained")
    assert len(contained) == 2

    cred_access = temp_store.list_incidents(category="Credential Access")
    assert len(cred_access) == 2


def test_get_audit_trail(temp_store: IncidentStore) -> None:
    inc = {
        "incident_id": "INC-AUDIT-1",
        "incident_title": "Audit Test",
        "incident_category": "Test",
        "incident_status": "contained",
        "audit_log": [
            {"actor": "analyst", "timestamp": "2026-07-28T10:00:00Z", "action": "APPROVED", "justification": "Approved"},
            {"actor": "system:closure_node", "timestamp": "2026-07-28T10:01:00Z", "action": "INCIDENT_CLOSED", "justification": "Closed"},
        ],
    }
    temp_store.save_incident(inc)

    audit = temp_store.get_audit_trail("INC-AUDIT-1")
    assert len(audit) == 2
    assert audit[0]["actor"] == "analyst"
    assert audit[1]["action"] == "INCIDENT_CLOSED"
