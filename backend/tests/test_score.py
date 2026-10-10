"""
Tests for the score service.
"""
import pytest
from app.services.score_service import calculate_score, save_score
from app.database.db import get_connection


def _finding(rule_id="SOME_RULE", severity="info", device_id=None):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "device_id": device_id,
    }


def test_empty_findings_gives_100():
    result = calculate_score([])
    assert result["score"] == 100
    assert result["provisional"] is False


def test_one_high_finding_deducts_15():
    result = calculate_score([_finding(severity="high")])
    assert result["score"] == 85


def test_score_floors_at_zero():
    # 8 high findings × 15 = 120 → clamped to 0
    findings = [_finding(severity="high") for _ in range(8)]
    result = calculate_score(findings)
    assert result["score"] == 0


def test_provisional_flag_when_incomplete_scan_finding():
    findings = [_finding(rule_id="INCOMPLETE_SCAN_001", severity="low")]
    result = calculate_score(findings)
    assert result["provisional"] is True


def test_no_provisional_flag_without_incomplete_scan():
    findings = [_finding(rule_id="SENSITIVE_PORT_001", severity="high")]
    result = calculate_score(findings)
    assert result["provisional"] is False


def test_medium_deducts_8():
    result = calculate_score([_finding(severity="medium")])
    assert result["score"] == 92


def test_low_deducts_3():
    result = calculate_score([_finding(severity="low")])
    assert result["score"] == 97


def test_info_does_not_deduct():
    result = calculate_score([_finding(severity="info")])
    assert result["score"] == 100


def test_save_score_persists(tmp_db):
    from app.database.db import get_connection
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO scans(scan_id, target_scope, scan_type, started_at, status) "
            "VALUES('s1','t','discovery','2024-01-01T00:00:00+00:00','completed')"
        )
        conn.commit()
        score_dict = calculate_score([_finding(severity="high")])
        save_score(conn, "s1", score_dict)
        conn.commit()
        row = conn.execute("SELECT score FROM scan_scores WHERE scan_id='s1'").fetchone()
    assert row is not None
    assert row["score"] == 85
