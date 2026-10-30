"""Business impact: what the live rules (rules/rules.json) save versus the untuned rules."""
from agent.backtest import backtest
from agent.engine import load_events, load_rules

DEFAULT_TRIAGE_MINUTES = 10


def business_impact(df, rules: list[dict], triage_minutes: float = DEFAULT_TRIAGE_MINUTES) -> dict:
    """Per-week alerts removed and analyst hours saved, plus noise reduction and attacks caught.

    "Before" is each rule with no exclusions; "after" is the rule as it is now.
    """
    weeks = []
    for wk in sorted(df["week"].unique()):
        part = df[df["week"] == wk]
        before = [backtest({**r, "exclusions": []}, part) for r in rules]
        after = [backtest(r, part) for r in rules]
        a_before = sum(m["alerts"] for m in before)
        a_after = sum(m["alerts"] for m in after)
        removed = a_before - a_after
        weeks.append({"week": int(wk), "alerts_before": a_before, "alerts_after": a_after,
                      "alerts_removed": removed,
                      "hours_saved": round(removed * triage_minutes / 60, 1)})

    before_all = [backtest({**r, "exclusions": []}, df) for r in rules]
    after_all = [backtest(r, df) for r in rules]
    fp_before = sum(m["false_positives"] for m in before_all)
    fp_after = sum(m["false_positives"] for m in after_all)
    n = len(weeks)
    return {
        "weeks": weeks,
        "alerts_removed_per_week": round(sum(w["alerts_removed"] for w in weeks) / n, 1),
        "hours_saved_per_week": round(sum(w["hours_saved"] for w in weeks) / n, 1),
        "noise_reduction_pct": round(100 * (fp_before - fp_after) / fp_before, 1) if fp_before else 0.0,
        "attacks_caught": sum(m["true_positives"] for m in after_all),
        "attacks_total": sum(m["true_positives"] for m in before_all),
    }


if __name__ == "__main__":
    imp = business_impact(load_events(), load_rules())
    for w in imp["weeks"]:
        print(f"Week {w['week']}: {w['alerts_before']} -> {w['alerts_after']} alerts "
              f"({w['alerts_removed']} removed, {w['hours_saved']} analyst hours saved)")
    print(f"Average per week: {imp['alerts_removed_per_week']} alerts removed, "
          f"{imp['hours_saved_per_week']} hours saved at {DEFAULT_TRIAGE_MINUTES} min/alert")
    print(f"Noise reduction: {imp['noise_reduction_pct']}% of false positives removed")
    print(f"Attacks still caught: {imp['attacks_caught']} / {imp['attacks_total']}")
