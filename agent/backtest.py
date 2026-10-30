"""Backtest: score a rule against the labeled event history (is_malicious = ground truth)."""
import pandas as pd

from agent.engine import all_of, evaluate, load_events, load_rules


def backtest(rule: dict, df: pd.DataFrame) -> dict:
    """Return alert count, TP/FP counts, FP rate, and true positives the exclusions suppressed.

    "Missed" = malicious events that match the rule's conditions but are hidden by an
    exclusion, i.e. real attacks that tuning would cause us to stop alerting on.
    """
    alerts = evaluate(rule, df)
    tp = int(alerts["is_malicious"].sum())
    fp = len(alerts) - tp

    candidates = df[all_of(df, rule["conditions"])]          # matches before exclusions
    missed = candidates[candidates["is_malicious"] & ~candidates.index.isin(alerts.index)]

    return {
        "rule_id": rule["id"],
        "alerts": len(alerts),
        "true_positives": tp,
        "false_positives": fp,
        "fp_rate": round(fp / len(alerts), 3) if len(alerts) else 0.0,
        "missed_true_positives": missed,                     # DataFrame of lost attacks
    }


def summary_line(m: dict) -> str:
    return (f"{m['rule_id']}: alerts={m['alerts']} TP={m['true_positives']} "
            f"FP={m['false_positives']} FP-rate={m['fp_rate']:.1%} "
            f"missed={len(m['missed_true_positives'])}")


if __name__ == "__main__":
    events = load_events()
    for r in load_rules():
        print(summary_line(backtest(r, events)))

    # Sanity check: a deliberately bad exclusion must show up as missed true positives.
    bad = {**load_rules()[0], "exclusions": [
        {"reason": "test", "conditions": [{"field": "failed_count", "op": ">", "value": 20}]}]}
    print("bad-exclusion test ->", summary_line(backtest(bad, events)))
