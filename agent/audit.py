"""Append-only audit log of every tuning decision (data/audit_log.jsonl, one JSON per line)."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from agent.engine import ROOT

# SIEM_AUDIT_LOG lets the test suite use a temporary log instead of the live one.
LOG_PATH = Path(os.environ.get("SIEM_AUDIT_LOG", ROOT / "data" / "audit_log.jsonl"))


def _metrics(view: dict | None) -> dict | None:
    """Flatten a compare() view into the before/after numbers worth keeping."""
    if not view:
        return None
    b, a = view["before"], view["after"]
    return {"alerts_before": b["alerts"], "alerts_after": a["alerts"],
            "fp_before": b["false_positives"], "fp_after": a["false_positives"],
            "tp_before": b["true_positives"], "tp_after": a["true_positives"],
            "fp_rate_before": b["fp_rate"], "fp_rate_after": a["fp_rate"],
            "missed_attacks": view["missed"]}


def record(rule_id: str, action: str, exclusions: list[dict], reason: str,
           week1: dict | None = None, holdout: dict | None = None) -> dict:
    """Append one decision. action: auto-applied | queued for review | rejected |
    human-approved | human-rejected."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rule_id": rule_id,
        "action": action,
        "exclusions": exclusions,
        "reason": reason,
        "week1": _metrics(week1),
        "holdout": _metrics(holdout),
    }
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def read_log() -> list[dict]:
    if not LOG_PATH.exists():
        return []
    with open(LOG_PATH) as f:
        return [json.loads(line) for line in f if line.strip()]


def clear_log() -> None:
    LOG_PATH.unlink(missing_ok=True)


def tuned_rule_ids() -> set[str]:
    """Rules whose agent-proposed change is live (auto-applied or approved by a human)."""
    return {e["rule_id"] for e in read_log() if e["action"] in ("auto-applied", "human-approved")}
