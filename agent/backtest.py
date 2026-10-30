"""Backtest: score a rule against the labeled event history (is_malicious = ground truth).

Week 1 is the training window the agent tunes on; week 2 is the holdout used to check
that a proposed tuning still catches attacks it has never seen.
"""
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


def public_metrics(m: dict) -> dict:
    """Backtest metrics with the missed-TP DataFrame turned into plain records (JSON-safe)."""
    out = {k: v for k, v in m.items() if k != "missed_true_positives"}
    out["missed_true_positives"] = m["missed_true_positives"].to_dict("records")
    return out


def split_weeks(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """(week 1 training events, week 2 holdout events)."""
    return df[df["week"] == 1], df[df["week"] == 2]


def compare(original: dict, candidate: dict, df: pd.DataFrame) -> dict:
    """Before/after view of a tuning on one slice of data."""
    b, a = backtest(original, df), backtest(candidate, df)
    return {
        "before": public_metrics(b),
        "after": public_metrics(a),
        "tp_kept": a["true_positives"],
        "tp_before": b["true_positives"],
        "fp_removed": b["false_positives"] - a["false_positives"],
        "fp_before": b["false_positives"],
        "missed": len(a["missed_true_positives"]),
        "missed_events": a["missed_true_positives"],         # DataFrame, for feedback
    }


def exclusions_hiding(rule: dict, missed: pd.DataFrame) -> list[dict]:
    """Which exclusion groups matched the missed attacks (to say which one is too broad)."""
    hits = []
    for i, exc in enumerate(rule.get("exclusions", []), start=1):
        n = int(all_of(missed, exc["conditions"]).sum()) if len(missed) else 0
        if n:
            hits.append({"index": i, "reason": exc["reason"], "conditions": exc["conditions"],
                         "attacks_hidden": n})
    return hits


def summary_line(m: dict) -> str:
    return (f"{m['rule_id']}: alerts={m['alerts']} TP={m['true_positives']} "
            f"FP={m['false_positives']} FP-rate={m['fp_rate']:.1%} "
            f"missed={len(m['missed_true_positives'])}")


if __name__ == "__main__":
    events = load_events()
    week1, week2 = split_weeks(events)
    for r in load_rules():
        print(summary_line(backtest(r, events)))
        print("   week 1:", summary_line(backtest(r, week1)))
        print("   week 2:", summary_line(backtest(r, week2)))

    # Sanity check: a deliberately bad exclusion must show up as missed true positives.
    bad = {**load_rules()[0], "exclusions": [
        {"reason": "test", "conditions": [{"field": "failed_count", "op": ">", "value": 20}]}]}
    print("bad-exclusion test ->", summary_line(backtest(bad, events)))
