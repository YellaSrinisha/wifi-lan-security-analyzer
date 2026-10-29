"""
Security score service.

Calculates a 0-100 score from a list of findings and persists it to scan_scores.
"""
import uuid
from datetime import datetime, timezone

# Deduction per finding by severity
_DEDUCTIONS = {
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
    "informational": 0,
}

SCORING_VERSION = 1


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_findings_for_scan(conn, scan_id: str) -> list[dict]:
    """
    Get ALL relevant findings for a scan — including port findings that were
    deduplicated (INSERT OR IGNORE) into an earlier scan_id but still apply
    to this scan's observed open ports.

    Strategy:
    1. Get findings directly stored under this scan_id.
    2. For port scans: also find findings for the same (rule, target_ip, port)
       combinations that were observed as open in this scan — they may have been
       stored under a different scan_id due to dedup.
    """
    # Direct findings for this scan
    direct = conn.execute(
        "SELECT * FROM security_findings WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    direct_dedup_keys = {row["dedup_key"] for row in direct}

    # For port-based rules, find findings for open ports in this scan
    # even if they were stored under a different scan_id
    port_obs = conn.execute(
        "SELECT target_ip, port_number, state FROM port_observations WHERE scan_id = ? AND state = 'open'",
        (scan_id,)
    ).fetchall()

    extra_findings = []
    for po in port_obs:
        target_ip = po["target_ip"]
        port_number = po["port_number"]
        # Find any finding for SENSITIVE_PORT_001 or POLICY_PORT_001
        # that matches this IP and port (via evidence string)
        evidence_pattern = f"Port {port_number}/% open on {target_ip}"
        rows = conn.execute(
            """
            SELECT * FROM security_findings
            WHERE rule_id IN ('SENSITIVE_PORT_001', 'POLICY_PORT_001')
            AND evidence LIKE ?
            AND dedup_key NOT IN ({})
            """.format(",".join("?" * len(direct_dedup_keys)) if direct_dedup_keys else "'__none__'"),
            [evidence_pattern] + list(direct_dedup_keys)
        ).fetchall()
        for row in rows:
            extra_findings.append(dict(row))
            direct_dedup_keys.add(row["dedup_key"])  # avoid duplicates

    return [dict(r) for r in direct] + extra_findings


def calculate_score(findings: list[dict]) -> dict:
    """
    Compute security score from a list of finding dicts.
    Deduplicates by dedup_key before scoring.
    """
    # Deduplicate findings by dedup_key
    seen_keys = set()
    unique_findings = []
    for f in findings:
        key = f.get("dedup_key") or f.get("finding_id", "")
        if key not in seen_keys:
            seen_keys.add(key)
            unique_findings.append(f)

    score = 100
    counts: dict[str, int] = {}

    for finding in unique_findings:
        sev = (finding.get("severity") or "info").lower()
        deduction = _DEDUCTIONS.get(sev, 0)
        score -= deduction
        counts[sev] = counts.get(sev, 0) + 1

    score = max(0, min(100, score))

    provisional = any(
        f.get("rule_id") == "INCOMPLETE_SCAN_001" for f in unique_findings
    )

    total = len(unique_findings)
    if total == 0:
        explanation = "No findings — network looks clean."
    else:
        parts = [f"{v} {k}" for k, v in sorted(counts.items()) if v > 0]
        explanation = f"{total} finding{'s' if total != 1 else ''}: {', '.join(parts)}"

    return {
        "score": score,
        "provisional": provisional,
        "explanation": explanation,
        "scoring_version": SCORING_VERSION,
    }


def calculate_score_for_scan(conn, scan_id: str) -> dict:
    """
    Calculate score for a specific scan, including deduplicated port findings
    from other scans that apply to this scan's observed open ports.
    """
    findings = get_findings_for_scan(conn, scan_id)
    return calculate_score(findings)


def save_score(conn, scan_id: str, score_dict: dict) -> None:
    """
    Persist (or replace) a scan score in scan_scores.
    Uses INSERT OR REPLACE so re-running the risk engine is safe.
    """
    score_id = str(uuid.uuid4())
    now = _now_iso()
    conn.execute(
        """
        INSERT OR REPLACE INTO scan_scores
            (score_id, scan_id, score, scoring_version, provisional, explanation, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            score_id,
            scan_id,
            score_dict["score"],
            score_dict["scoring_version"],
            1 if score_dict.get("provisional") else 0,
            score_dict["explanation"],
            now,
        ),
    )
