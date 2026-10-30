import pytest

from agent import audit


@pytest.fixture(autouse=True)
def tmp_log(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "LOG_PATH", tmp_path / "audit_log.jsonl")


VIEW = {"before": {"alerts": 10, "false_positives": 9, "true_positives": 1, "fp_rate": 0.9},
        "after": {"alerts": 2, "false_positives": 1, "true_positives": 1, "fp_rate": 0.5},
        "missed": 0}


def test_record_and_read_roundtrip():
    e = audit.record("R1", "auto-applied", [{"reason": "x", "conditions": []}], "ok", VIEW, VIEW)
    log = audit.read_log()
    assert log == [e]
    assert e["week1"]["alerts_before"] == 10 and e["holdout"]["alerts_after"] == 2
    assert set(e) >= {"timestamp", "rule_id", "action", "exclusions", "reason", "week1", "holdout"}


def test_tuned_rule_ids_only_counts_live_changes():
    for rid, action in [("R1", "auto-applied"), ("R2", "human-approved"),
                        ("R3", "queued for review"), ("R4", "rejected"), ("R5", "human-rejected")]:
        audit.record(rid, action, [], "r")
    assert audit.tuned_rule_ids() == {"R1", "R2"}


def test_clear_log():
    audit.record("R1", "rejected", [], "r")
    audit.clear_log()
    assert audit.read_log() == []
    audit.clear_log()                      # clearing a missing log is fine
