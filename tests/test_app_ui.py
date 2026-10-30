"""Dashboard tests with Streamlit's AppTest harness. Claude is replaced by canned answers,
so no API calls are made. rules.json and the audit log are temporary copies (see conftest.py)."""
import json

import pytest
from streamlit.testing.v1 import AppTest

from agent import audit, tuner
from agent.engine import ROOT, RULES_PATH
from tests.conftest import cond

GOOD = {
    "R1": [[cond("user", "==", "vuln_scanner"), cond("src_ip", "==", "10.0.5.20")],
           [cond("user", "==", "svc_backup"), cond("src_ip", "startswith", "10.0.")]],
    "R2": [[cond("user", "==", "svc_deploy"), cond("parent_process", "==", "ccmexec.exe")]],
    "R3": [[cond("via_vpn", "==", True), cond("src_ip", "startswith", "10.8.")]],
}
BROAD = {"R1": [[cond("user", "==", "vuln_scanner")]], "R2": [[cond("user", "==", "svc_deploy")]],
         "R3": [[cond("src_ip", "startswith", "10.8.")]]}


@pytest.fixture
def sandbox():
    """Start every test from bare rules and an empty log (temporary files, see conftest.py)."""
    assert "siem-tests-" in str(RULES_PATH), "tests must not run against the live rules.json"
    rules = json.loads(RULES_PATH.read_text())
    RULES_PATH.write_text(json.dumps([{**r, "exclusions": []} for r in rules], indent=2))
    audit.clear_log()
    yield


@pytest.fixture
def fake_claude(monkeypatch):
    def install(table):
        def ask(messages):
            rid = json.loads(messages[0]["content"].split("Rule under review:\n")[1].split("\n\nAvailable")[0])["id"]
            p = {"root_cause": f"canned {rid}",
                 "exclusions": [{"reason": "canned", "conditions": g} for g in table[rid]]}
            return p, [{"type": "text", "text": json.dumps(p)}], {"model": tuner.MODEL, "input_tokens": 1, "output_tokens": 1}
        monkeypatch.setattr(tuner, "ask_claude", ask)
    return install


def app():
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
    assert not at.exception, at.exception
    return at


def click(at, label):
    next(b for b in at.button if label in b.label).click().run()
    assert not at.exception, at.exception


def htmls(at) -> str:
    return " ".join(el.proto.body for el in at.get("html"))


def test_initial_render_has_all_tabs(sandbox):
    at = app()
    assert [t.label.split(" ", 1)[1] for t in at.tabs] == \
        ["Live Agent", "Safety & Audit", "Impact", "Evaluation", "How it works"]
    page = htmls(at)
    assert "Rule health" in page and "Held-out results on three unseen datasets" in page


def test_autonomous_run_with_demo_injection(sandbox, fake_claude):
    fake_claude(GOOD)
    at = app()
    at.toggle[0].set_value(False).run()                       # no animation pauses in tests
    at.checkbox[0].check().run()
    click(at, "Run autonomous tuning on all rules")
    page = htmls(at)
    assert "UNSAFE CHANGE BLOCKED" in page and "Injected demo proposal" in page
    assert "Exclude all VPN logins" in page
    assert page.count("Auto-applied") >= 3
    actions = [(x["rule_id"], x["action"]) for x in audit.read_log()]
    assert ("R3", "rejected") in actions and actions.count(("R3", "auto-applied")) == 1
    assert all(r["exclusions"] for r in json.loads(RULES_PATH.read_text()))
    # second run skips everything already tuned
    click(at, "Run autonomous tuning on all rules")
    assert "already tuned" in htmls(at)


def test_queued_changes_approve_and_reject(sandbox, fake_claude):
    fake_claude(BROAD)                                        # safe but single-condition: queued
    at = app()
    at.toggle[0].set_value(False).run()
    click(at, "Propose only")
    assert htmls(at).count("Needs human review") >= 3
    click(at, "Approve & apply")
    click(at, "Reject")
    actions = [x["action"] for x in audit.read_log()]
    assert "human-approved" in actions and "human-rejected" in actions
    assert sum(bool(r["exclusions"]) for r in json.loads(RULES_PATH.read_text())) == 1


def test_reset_clears_rules_audit_and_results(sandbox, fake_claude):
    fake_claude(GOOD)
    at = app()
    at.toggle[0].set_value(False).run()
    click(at, "Run autonomous tuning on all rules")
    click(at, "Reset rules and audit log")
    assert audit.read_log() == []
    assert not any(r["exclusions"] for r in json.loads(RULES_PATH.read_text()))
    assert "Run summary" not in htmls(at)


def test_impact_slider_changes_hours(sandbox, fake_claude):
    fake_claude(GOOD)
    at = app()
    at.toggle[0].set_value(False).run()
    click(at, "Run autonomous tuning on all rules")
    hours = lambda: next(p for p in htmls(at).split('<div class="kpi') if "Analyst hours saved per week" in p)
    before = hours()
    next(s for s in at.slider if "triage" in s.label).set_value(20).run()
    assert hours() != before


def test_evaluation_tab_reads_results_json(sandbox):
    results = json.loads((ROOT / "eval" / "results.json").read_text())
    page = htmls(app())
    assert "Do approved exclusions go stale when attackers change tactics?" in page
    assert "STALE: re-tune needed" in page and "After agent re-tunes" in page
    hidden = sum(x["missed"] for x in results["regression"] if x["dataset"] == "adversarial")
    total = sum(x["attacks"] for x in results["regression"] if x["dataset"] == "adversarial")
    assert f"{hidden} of {total} attacks slip past" in page
    assert ">FAIL<" not in page


def test_evaluation_tab_without_results(sandbox, monkeypatch):
    import ui.tabs
    monkeypatch.setattr(ui.tabs, "EVAL_RESULTS", ROOT / "eval" / "does_not_exist.json")
    assert "No evaluation results yet" in htmls(app())


def test_overfit_rejection_is_shown_and_logged(sandbox, monkeypatch):
    from tests.test_tuner_offline import overfit_proposal
    calls = {}

    def ask(messages):
        rid = json.loads(messages[0]["content"].split("Rule under review:\n")[1].split("\n\nAvailable")[0])["id"]
        calls[rid] = calls.get(rid, 0) + 1
        if rid == "R3" and calls[rid] == 1:
            p = overfit_proposal()
        else:
            p = {"root_cause": f"canned {rid}",
                 "exclusions": [{"reason": "canned", "conditions": g} for g in GOOD[rid]]}
        return p, [{"type": "text", "text": json.dumps(p)}], {"model": tuner.MODEL, "input_tokens": 1, "output_tokens": 1}
    monkeypatch.setattr(tuner, "ask_claude", ask)
    at = app()
    at.toggle[0].set_value(False).run()
    click(at, "Run autonomous tuning on all rules")
    page = htmls(at)
    assert "OVERFIT" in page and "Overfit · removes 0 /" in page
    log = audit.read_log()
    assert any(x["action"] == "rejected" and tuner.OVERFIT_REASON in x["reason"] for x in log)
    assert any(x["rule_id"] == "R3" and x["action"] == "auto-applied" for x in log)
