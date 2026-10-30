"""Narrowness / safety guard that decides auto-apply vs human review."""
from agent.autonomous import MIN_CONDITIONS, decide, noisy_rules
from tests.conftest import cond, make_events


def result(group_sizes, success=True, w1_missed=0, ho_missed=0):
    excl = [{"reason": "r", "conditions": [cond("user", "==", "u")] * n} for n in group_sizes]
    return {"success": success, "attempts": [{"proposal": {"exclusions": excl}}],
            "week1": {"missed": w1_missed}, "holdout": {"missed": ho_missed}}


def test_min_conditions_is_two():
    assert MIN_CONDITIONS == 2


def test_narrow_and_safe_is_auto_applied():
    assert decide(result([2, 3]))[0] == "auto-applied"


def test_single_condition_group_is_queued():
    assert decide(result([2, 1]))[0] == "queued for review"


def test_hidden_attacks_are_never_auto_applied():
    assert decide(result([2], w1_missed=1))[0] == "queued for review"
    assert decide(result([2], ho_missed=1))[0] == "queued for review"


def test_failed_tuning_is_rejected():
    assert decide(result([2], success=False))[0] == "rejected"


def test_noisy_rules_threshold_and_order(brute_force_rule):
    burst = {"event_type": "login_failure_burst", "failed_count": 10}
    df = make_events(*[burst] * 4, {**burst, "is_malicious": True},
                     {"event_type": "login_success", "impossible_travel": True})
    travel = {"id": "T2", "name": "t", "conditions": [cond("impossible_travel", "==", True)],
              "exclusions": []}
    # T1: 4 FP of 5 alerts (80%), T2: 1 FP of 1 alert (100%); ordered by FP count
    assert [r["id"] for r in noisy_rules([travel, brute_force_rule], df, 0.3)] == ["T1", "T2"]
    assert [r["id"] for r in noisy_rules([travel, brute_force_rule], df, 0.9)] == ["T2"]
