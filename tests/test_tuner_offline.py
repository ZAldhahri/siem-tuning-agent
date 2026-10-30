"""Tuner loop with Claude replaced by canned proposals (no API calls)."""
import json

import pytest

from agent import tuner
from agent.backtest import split_weeks
from agent.engine import evaluate, load_events, load_rules
from tests.conftest import cond

RISKY = {"root_cause": "vpn", "exclusions": [
    {"reason": "all VPN", "conditions": [cond("via_vpn", "==", True)]}]}
NARROW = {"root_cause": "vpn", "exclusions": [
    {"reason": "VPN pool", "conditions": [cond("via_vpn", "==", True), cond("src_ip", "startswith", "10.8.")]}]}
LABEL = {"root_cause": "cheat", "exclusions": [
    {"reason": "label", "conditions": [cond("is_malicious", "==", False), cond("via_vpn", "==", True)]}]}


@pytest.fixture
def canned(monkeypatch):
    """Replace Claude with a queue of proposals. Returns the list of message histories it received."""
    seen = []

    def install(*proposals):
        queue = list(proposals)
        usage = {"model": tuner.MODEL, "input_tokens": 1, "output_tokens": 1}

        def ask(messages):
            seen.append([dict(m) for m in messages])
            p = queue.pop(0)
            return p, [{"type": "text", "text": json.dumps(p)}], usage
        monkeypatch.setattr(tuner, "ask_claude", ask)
        return seen
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


def overfit_proposal() -> dict:
    """Exclusions pinned to one week 1 false positive (its IP and user) that never recurs in week 2."""
    week1, week2 = split_weeks(load_events())
    alerts = evaluate(r3(), week1)
    fps = alerts[~alerts["is_malicious"]]
    row = next(r for _, r in fps.iterrows() if r["src_ip"] not in set(week2["src_ip"]))
    return {"root_cause": "pinned to week 1", "exclusions": [
        {"reason": "one host", "conditions": [cond("src_ip", "==", row["src_ip"]), cond("user", "==", row["user"])]}]}


def test_overfit_proposal_is_rejected_then_generalized(canned):
    seen = canned(overfit_proposal(), NARROW)
    res = tuner.tune_rule(r3(), load_events(), log=lambda *a: None)
    first, second = res["attempts"]
    assert first["status"] == "rejected" and first["reason"] == tuner.OVERFIT_REASON
    assert first["week1"]["missed"] == 0 and first["holdout"]["missed"] == 0   # safe, just useless
    assert first["holdout"]["fp_removed"] == 0
    assert second["status"] == "accepted" and res["success"]
    feedback = seen[1][-1]["content"]                                          # sent with attempt 2
    assert "generalize it" in feedback and "only matches week 1 values" in feedback


def test_overfit_gate_needs_holdout_validation(canned):
    canned(overfit_proposal())
    res = tuner.tune_rule(r3(), load_events(), log=lambda *a: None, validate_holdout=False)
    assert res["success"] and res["holdout"]["fp_removed"] == 0
