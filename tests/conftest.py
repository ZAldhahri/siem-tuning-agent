"""Shared helpers: build small event tables by hand."""
import pandas as pd
import pytest

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
