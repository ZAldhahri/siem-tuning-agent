"""Autonomous mode: tune every noisy rule and apply only the changes that are provably safe.

A change is auto-applied only if ALL hold:
  - week 1 backtest hides 0 real attacks
  - week 2 holdout hides 0 real attacks
  - every new exclusion group has at least MIN_CONDITIONS conditions (ANDed = narrow)
Anything else is queued for human review (Approve/Reject in the app). Every decision,
including each rejected proposal, is written to the audit log.

Usage:  python -m agent.autonomous [--threshold 0.3] [--propose-only]
"""
import argparse

from agent import audit
from agent.backtest import backtest, split_weeks
from agent.engine import load_events, load_rules, save_rules
from agent.tuner import tune_rule

MIN_CONDITIONS = 2
DEFAULT_THRESHOLD = 0.30  # week 1 FP rate above which a rule gets tuned

# Demo: a tempting but unsafe first proposal for the impossible travel rule. It passes
# week 1 but hides the stolen-VPN-credentials attack in the week 2 holdout.
DEMO_RULE_ID = "R3"
RISKY_DEMO_PROPOSAL = {
    "root_cause": "(Injected demo proposal) Impossible travel alerts come from VPN users.",
    "exclusions": [{"reason": "Exclude all VPN logins",
                    "conditions": [{"field": "via_vpn", "op": "==", "value": True}]}],
}


def noisy_rules(rules: list[dict], df, threshold: float) -> list[dict]:
    """Rules whose week 1 FP rate exceeds the threshold, noisiest first."""
    week1, _ = split_weeks(df)
    scored = [(r, backtest(r, week1)) for r in rules]
    noisy = [(r, m) for r, m in scored if m["fp_rate"] > threshold]
    noisy.sort(key=lambda rm: rm[1]["false_positives"], reverse=True)
    return [r for r, _ in noisy]


def new_exclusions(result: dict) -> list[dict]:
    """The exclusions this run proposed (on top of any the rule already had)."""
    return result["attempts"][-1]["proposal"]["exclusions"]


def decide(result: dict) -> tuple[str, str]:
    """Return (action, reason) for a tuning result."""
    if not result["success"]:
        return "rejected", "No proposal passed both safety checks; rule left unchanged"
    if result["week1"]["missed"] or result["holdout"]["missed"]:   # defensive re-check
        return "queued for review", "Proposal hides real attacks"
    broad = [e for e in new_exclusions(result) if len(e["conditions"]) < MIN_CONDITIONS]
    if broad:
        return "queued for review", (f"{len(broad)} exclusion group(s) have fewer than "
                                     f"{MIN_CONDITIONS} conditions, which is too broad to auto-apply")
    return "auto-applied", ("0 attacks hidden in week 1 and holdout; every exclusion "
                            f"has at least {MIN_CONDITIONS} conditions")


def apply_rule(new_rule: dict) -> None:
    """Replace one rule in rules.json (re-reads the file so other changes are kept)."""
    save_rules([new_rule if r["id"] == new_rule["id"] else r for r in load_rules()])


def run_autonomous(df, threshold: float = DEFAULT_THRESHOLD, auto_apply: bool = True,
                   log=print, inject_risky: bool = False, on_event=None) -> list[dict]:
    """Tune every noisy rule; auto-apply the safe changes, queue the rest, log everything.

    Rules the agent already tuned (per the audit log) are skipped. inject_risky forces a
    risky first proposal on the demo rule to show the safety checks at work.
    on_event(kind, data) (optional): structured progress for UIs. Adds run_start,
    rule_start, decision and error to the tuner's events.
    """
    emit = on_event or (lambda kind, data: None)
    results = []
    tuned = audit.tuned_rule_ids()
    noisy = noisy_rules(load_rules(), df, threshold)
    skipped = [r["id"] for r in noisy if r["id"] in tuned]
    targets = [r for r in noisy if r["id"] not in tuned]
    log(f"{len(noisy)} rule(s) above {threshold:.0%} week 1 FP rate: "
        + (", ".join(r["id"] for r in noisy) or "none"))
    if skipped:
        log(f"Skipping already tuned rule(s): {', '.join(skipped)}")
    inject_skipped = inject_risky and DEMO_RULE_ID not in [r["id"] for r in targets]
    if inject_skipped:
        log(f"Demo injection skipped: {DEMO_RULE_ID} is not being tuned this run "
            "(already tuned or below the threshold). Reset to replay the demo.")
    emit("run_start", {"targets": [r["id"] for r in targets], "skipped": skipped,
                       "inject_skipped": inject_skipped})
    for rule in targets:
        log(f"--- {rule['id']} {rule['name']}")
        emit("rule_start", {"rule": rule})
        forced = RISKY_DEMO_PROPOSAL if inject_risky and rule["id"] == DEMO_RULE_ID else None
        try:
            res = tune_rule(rule, df, log=log, first_proposal=forced, on_event=on_event)
        except Exception as e:                       # API failure: log it and keep going
            log(f"{rule['id']}: agent error: {e}")
            emit("error", {"rule_id": rule["id"], "error": str(e)})
            audit.record(rule["id"], "rejected", [], f"Agent error: {e}")
            continue

        for att in res["attempts"]:                   # keep a record of every risky proposal
            if att["status"] == "rejected":
                audit.record(rule["id"], "rejected", att["proposal"]["exclusions"],
                             f"Attempt {att['attempt']}"
                             + (" (injected demo proposal)" if att.get("injected") else "")
                             + f": {att['reason']}",
                             att["week1"], att["holdout"])

        action, reason = decide(res)
        if action == "auto-applied" and not auto_apply:
            action, reason = "queued for review", "Propose-only mode: " + reason
        if action == "auto-applied":
            apply_rule(res["proposed_rule"])
            res["applied"] = True
        if res["success"]:
            audit.record(rule["id"], action, new_exclusions(res), reason,
                         res["week1"], res["holdout"])

        res["decision"] = {"action": action, "reason": reason}
        emit("decision", {"rule_id": rule["id"], "action": action, "reason": reason})
        log(f"{rule['id']} decision: {action.upper()} - {reason}")
        results.append(res)
    return results


def summarize(results: list[dict], df) -> dict:
    """Headline numbers for a run, measured on all data with rules.json as it is now."""
    applied = [r for r in results if r.get("applied")]          # by the agent or a human
    queued = [r for r in results
              if r["decision"]["action"] == "queued for review" and not r.get("applied")]

    def removed(r):
        return (backtest(r["original_rule"], df)["alerts"]
                - backtest(r["proposed_rule"], df)["alerts"])

    live = [backtest(r, df) for r in load_rules()]
    return {
        "auto_applied": len([r for r in results if r["decision"]["action"] == "auto-applied"]),
        "human_approved": len([r for r in applied if r["decision"]["action"] != "auto-applied"]),
        "queued": len(queued),
        "rejected": len([r for r in results if r["decision"]["action"] == "rejected"]),
        "alerts_removed": sum(removed(r) for r in applied),
        "alerts_removable_if_approved": sum(removed(r) for r in queued),
        "attacks_caught": sum(m["true_positives"] for m in live),
        "attacks_total": sum(m["true_positives"] + len(m["missed_true_positives"]) for m in live),
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--propose-only", action="store_true", help="never auto-apply")
    ap.add_argument("--demo-inject", action="store_true",
                    help=f"force a risky first proposal on {DEMO_RULE_ID}")
    args = ap.parse_args()

    events = load_events()
    results = run_autonomous(events, args.threshold, auto_apply=not args.propose_only,
                             inject_risky=args.demo_inject)
    s = summarize(results, events)
    print("\n=== Run summary ===")
    print(f"Auto-applied: {s['auto_applied']}   Queued for review: {s['queued']}   "
          f"Rejected: {s['rejected']}")
    print(f"Alerts removed: {s['alerts_removed']} "
          f"(+{s['alerts_removable_if_approved']} if queued changes are approved)")
    print(f"Attacks still caught: {s['attacks_caught']} / {s['attacks_total']}")
    print(f"Audit log: {audit.LOG_PATH} ({len(audit.read_log())} entries)")
