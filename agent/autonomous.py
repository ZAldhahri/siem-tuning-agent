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
                   log=print) -> list[dict]:
    """Tune every noisy rule; auto-apply the safe changes, queue the rest, log everything."""
    results = []
    targets = noisy_rules(load_rules(), df, threshold)
    log(f"{len(targets)} rule(s) above {threshold:.0%} week 1 FP rate: "
        + ", ".join(r["id"] for r in targets))
    for rule in targets:
        log(f"--- {rule['id']} {rule['name']}")
        try:
            res = tune_rule(rule, df, log=log)
        except Exception as e:                       # API failure: log it and keep going
            log(f"{rule['id']}: agent error: {e}")
            audit.record(rule["id"], "rejected", [], f"Agent error: {e}")
            continue

        for att in res["attempts"]:                   # keep a record of every risky proposal
            if att["status"] == "rejected":
                audit.record(rule["id"], "rejected", att["proposal"]["exclusions"],
                             f"Attempt {att['attempt']}: {att['reason']}",
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
    args = ap.parse_args()

    events = load_events()
    results = run_autonomous(events, args.threshold, auto_apply=not args.propose_only)
    s = summarize(results, events)
    print("\n=== Run summary ===")
    print(f"Auto-applied: {s['auto_applied']}   Queued for review: {s['queued']}   "
          f"Rejected: {s['rejected']}")
    print(f"Alerts removed: {s['alerts_removed']} "
          f"(+{s['alerts_removable_if_approved']} if queued changes are approved)")
    print(f"Attacks still caught: {s['attacks_caught']} / {s['attacks_total']}")
    print(f"Audit log: {audit.LOG_PATH} ({len(audit.read_log())} entries)")
