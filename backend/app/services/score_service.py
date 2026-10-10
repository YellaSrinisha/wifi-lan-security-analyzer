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
}

SCORING_VERSION = 1


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def calculate_score(findings: list[dict]) -> dict:
    """
    Compute security score from a list of finding dicts.

    Returns:
        {
            "score": int (0-100),
            "provisional": bool,
            "explanation": str,
            "scoring_version": int,
        }
    """
    score = 100
    counts: dict[str, int] = {}

    for finding in findings:
        sev = (finding.get("severity") or "info").lower()
        deduction = _DEDUCTIONS.get(sev, 0)
        score -= deduction
        counts[sev] = counts.get(sev, 0) + 1

    # Clamp to [0, 100]
    score = max(0, min(100, score))

    provisional = any(
        f.get("rule_id") == "INCOMPLETE_SCAN_001" for f in findings
    )

    # Build human-readable explanation
    total = len(findings)
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
