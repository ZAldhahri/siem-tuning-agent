from agent.backtest import backtest, compare, exclusions_hiding, split_weeks
from tests.conftest import cond, make_events

BURST = {"event_type": "login_failure_burst", "failed_count": 10}


def events():
    return make_events({**BURST, "user": "scanner"}, {**BURST, "user": "scanner"},
                       {**BURST, "user": "scanner", "is_malicious": True, "week": 2},
                       {**BURST, "user": "evil", "is_malicious": True})


def test_counts(brute_force_rule):
    m = backtest(brute_force_rule, events())
    assert (m["alerts"], m["true_positives"], m["false_positives"]) == (4, 2, 2)
    assert m["fp_rate"] == 0.5
    assert len(m["missed_true_positives"]) == 0


def test_missed_attack_is_reported(brute_force_rule):
    rule = {**brute_force_rule, "exclusions": [{"reason": "x", "conditions": [cond("user", "==", "scanner")]}]}
    m = backtest(rule, events())
    assert (m["alerts"], m["false_positives"]) == (1, 0)
    assert list(m["missed_true_positives"].index) == [2]


def test_split_weeks_and_compare(brute_force_rule):
    w1, w2 = split_weeks(events())
    assert len(w1) == 3 and len(w2) == 1
    rule = {**brute_force_rule, "exclusions": [{"reason": "x", "conditions": [cond("user", "==", "scanner")]}]}
    v = compare(brute_force_rule, rule, w1)
    assert (v["fp_removed"], v["fp_before"], v["tp_kept"], v["missed"]) == (2, 2, 1, 0)
    assert compare(brute_force_rule, rule, w2)["missed"] == 1


def test_exclusions_hiding_names_the_culprit(brute_force_rule):
    rule = {**brute_force_rule, "exclusions": [
        {"reason": "safe", "conditions": [cond("user", "==", "nobody")]},
        {"reason": "broad", "conditions": [cond("user", "==", "scanner")]}]}
    hits = exclusions_hiding(rule, backtest(rule, events())["missed_true_positives"])
    assert [(h["index"], h["attacks_hidden"]) for h in hits] == [(2, 1)]
