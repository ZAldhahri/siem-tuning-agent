import pytest

from agent.engine import evaluate, load_events
from tests.conftest import cond, make_events


def test_conditions_are_anded(brute_force_rule):
    df = make_events({"event_type": "login_failure_burst", "failed_count": 10},
                     {"event_type": "login_failure_burst", "failed_count": 3},
                     {"event_type": "login_success", "failed_count": 10})
    assert list(evaluate(brute_force_rule, df).index) == [0]


def test_exclusion_groups_or_between_and_within(brute_force_rule):
    df = make_events({"event_type": "login_failure_burst", "failed_count": 9, "user": "scanner", "src_ip": "10.0.5.20"},
                     {"event_type": "login_failure_burst", "failed_count": 9, "user": "scanner", "src_ip": "8.8.8.8"},
                     {"event_type": "login_failure_burst", "failed_count": 9, "user": "backup"})
    rule = {**brute_force_rule, "exclusions": [
        {"reason": "a", "conditions": [cond("user", "==", "scanner"), cond("src_ip", "==", "10.0.5.20")]},
        {"reason": "b", "conditions": [cond("user", "==", "backup")]}]}
    # row 0 matches group a (both conditions); row 2 matches group b; row 1 matches neither fully
    assert list(evaluate(rule, df).index) == [1]


@pytest.mark.parametrize("op,value,expected", [
    ("in", ["a", "b"], [0, 1]), ("not_in", ["a"], [1, 2]), ("startswith", "10.", [0]),
    ("contains", "x", [2]), ("!=", "a", [1, 2]),
])
def test_operators(op, value, expected):
    df = make_events({"user": "a", "src_ip": "10.1.1.1"}, {"user": "b", "src_ip": "8.8.8.8"},
                     {"user": "xx", "src_ip": "9.9.9.9"})
    field = "src_ip" if op == "startswith" else "user"
    rule = {"id": "T", "name": "t", "conditions": [cond(field, op, value)], "exclusions": []}
    assert list(evaluate(rule, df).index) == expected


def test_unknown_field_and_operator_raise():
    df = make_events({})
    with pytest.raises(ValueError):
        evaluate({"conditions": [cond("nope", "==", 1)], "exclusions": []}, df)
    with pytest.raises(ValueError):
        evaluate({"conditions": [cond("user", "~=", 1)], "exclusions": []}, df)


def test_load_events_blank_text_is_empty_string():
    df = load_events()
    assert (df["parent_process"] == "").any()
    assert not df["parent_process"].isna().any()
