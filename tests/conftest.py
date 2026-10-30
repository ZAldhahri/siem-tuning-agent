"""Shared helpers: build small event tables by hand.

Before any agent module is imported, point rules.json and the audit log at temporary copies,
so the suite never touches the live files (it can run while the dashboard is in use)."""
import json
import os
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_TMP = Path(tempfile.mkdtemp(prefix="siem-tests-"))
_rules = json.loads((_ROOT / "rules" / "rules.json").read_text())
(_TMP / "rules.json").write_text(json.dumps([{**r, "exclusions": []} for r in _rules], indent=2))
os.environ["SIEM_RULES_PATH"] = str(_TMP / "rules.json")
os.environ["SIEM_AUDIT_LOG"] = str(_TMP / "audit_log.jsonl")

import pandas as pd  # noqa: E402
import pytest  # noqa: E402

DEFAULTS = dict(timestamp="2026-10-01T00:00:00", week=1, event_type="", user="user1",
                src_ip="10.0.1.5", host="PC-1", process="", parent_process="", encoded=False,
                failed_count=0, impossible_travel=False, via_vpn=False, is_malicious=False)


def make_events(*rows: dict) -> pd.DataFrame:
    return pd.DataFrame([{**DEFAULTS, **r} for r in rows])


def cond(field, op, value):
    return {"field": field, "op": op, "value": value}


@pytest.fixture
def brute_force_rule():
    return {"id": "T1", "name": "test brute force",
            "conditions": [cond("event_type", "==", "login_failure_burst"),
                           cond("failed_count", ">", 5)],
            "exclusions": []}
