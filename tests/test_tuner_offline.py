"""Tuner loop with Claude replaced by canned proposals (no API calls)."""
import json

import pytest

from agent import tuner
from agent.engine import load_events, load_rules
from tests.conftest import cond

RISKY = {"root_cause": "vpn", "exclusions": [
    {"reason": "all VPN", "conditions": [cond("via_vpn", "==", True)]}]}
NARROW = {"root_cause": "vpn", "exclusions": [
    {"reason": "VPN pool", "conditions": [cond("via_vpn", "==", True), cond("src_ip", "startswith", "10.8.")]}]}
LABEL = {"root_cause": "cheat", "exclusions": [
    {"reason": "label", "conditions": [cond("is_malicious", "==", False), cond("via_vpn", "==", True)]}]}


@pytest.fixture
def canned(monkeypatch):
    def install(*proposals):
        queue = list(proposals)
        usage = {"model": tuner.MODEL, "input_tokens": 1, "output_tokens": 1}
        monkeypatch.setattr(tuner, "ask_claude",
                            lambda messages: (p := queue.pop(0), [{"type": "text", "text": json.dumps(p)}], usage))
    return install


def r3():
    return {**next(r for r in load_rules() if r["id"] == "R3"), "exclusions": []}


def test_holdout_rejects_risky_then_accepts_narrow(canned):
    canned(RISKY, NARROW)
    res = tuner.tune_rule(r3(), load_events(), log=lambda *a: None)
    assert [a["status"] for a in res["attempts"]] == ["rejected", "accepted"]
    assert "Holdout" in res["attempts"][0]["reason"]
    assert res["success"] and res["holdout"]["missed"] == 0


def test_without_holdout_validation_risky_is_accepted(canned):
    canned(RISKY)
    res = tuner.tune_rule(r3(), load_events(), log=lambda *a: None, validate_holdout=False)
    assert res["success"] and res["holdout"]["missed"] == 1


def test_label_field_is_forbidden(canned):
    canned(LABEL, LABEL, LABEL)
    res = tuner.tune_rule(r3(), load_events(), log=lambda *a: None)
    assert not res["success"]
    assert all("not allowed" in a["reason"] for a in res["attempts"])


def test_usage_is_totalled(canned):
    canned(RISKY, NARROW)
    res = tuner.tune_rule(r3(), load_events(), log=lambda *a: None)
    assert res["usage"]["input_tokens"] == 2 and res["usage"]["models"] == [tuner.MODEL]


def test_empty_proposal_means_no_change(canned):
    canned(RISKY, {"root_cause": "nothing is safe", "exclusions": []})
    res = tuner.tune_rule(r3(), load_events(), log=lambda *a: None)
    assert not res["success"] and res["proposed_rule"] is None
    assert len(res["attempts"]) == 2 and "no exclusions" in res["attempts"][-1]["reason"]
