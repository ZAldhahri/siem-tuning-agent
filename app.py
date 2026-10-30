"""Streamlit dashboard for the SIEM Tuning Agent.

Run:  streamlit run app.py
"""
import difflib
import json

import pandas as pd
import streamlit as st

from agent import audit
from agent.autonomous import DEFAULT_THRESHOLD, MIN_CONDITIONS, run_autonomous, summarize
from agent.backtest import backtest, split_weeks
from agent.engine import load_events, load_rules, save_rules
from agent.tuner import MODEL

st.set_page_config(page_title="SIEM Tuning Agent", page_icon="🛡️", layout="wide")
st.title("🛡️ SIEM Tuning Agent")
st.caption(f"Finds noisy detection rules, diagnoses them with {MODEL}, proves each fix on "
           "training data and an unseen holdout week, and applies only the provably safe ones.")

events = load_events()
week1, _ = split_weeks(events)
rules = load_rules()
results = st.session_state.setdefault("results", {})   # rule_id -> tuner result


def overview_table(rules):
    rows = []
    for r in rules:
        m, m1 = backtest(r, events), backtest(r, week1)
        rows.append({"Rule": f"{r['id']} {r['name']}", "Alerts (2 weeks)": m["alerts"],
                     "Attacks caught": m["true_positives"],
                     "False positives": m["false_positives"],
                     "FP rate": f"{m['fp_rate']:.0%}", "Week 1 FP rate": f"{m1['fp_rate']:.0%}",
                     "Exclusions": len(r["exclusions"])})
    return pd.DataFrame(rows)


def rule_diff(old: dict, new: dict) -> str:
    a = json.dumps(old, indent=2).splitlines()
    b = json.dumps(new, indent=2).splitlines()
    return "\n".join(difflib.unified_diff(a, b, "current", "proposed", lineterm=""))


def fmt_exclusions(exclusions: list[dict]) -> str:
    return "; ".join(" AND ".join(f"{c['field']} {c['op']} {c['value']}" for c in e["conditions"])
                     for e in exclusions) or "-"


def impact_row(label: str, v: dict):
    """One row of before/after metrics for a slice of data (week 1 or holdout)."""
    b, a = v["before"], v["after"]
    st.markdown(f"**{label}**")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Alerts", a["alerts"], a["alerts"] - b["alerts"], delta_color="inverse")
    c2.metric("False positives removed", f"{v['fp_removed']} / {v['fp_before']}")
    c3.metric("Attacks still caught", f"{v['tp_kept']} / {v['tp_before']}")
    c4.metric("FP rate", f"{a['fp_rate']:.0%}", f"{(a['fp_rate'] - b['fp_rate']) * 100:.0f} pts",
              delta_color="inverse")


def safety_panel(attempts: list[dict]):
    """Every proposal the agent made, including the risky ones that were rejected."""
    rows = [{
        "Attempt": att["attempt"],
        "Result": "✅ accepted" if att["status"] == "accepted" else "❌ rejected",
        "Why": att["reason"],
        "Week 1 attacks hidden": att["week1"]["missed"] if att["week1"] else "-",
        "Holdout attacks hidden": att["holdout"]["missed"] if att["holdout"] else "not run",
        "Exclusions": fmt_exclusions(att["proposal"]["exclusions"]),
    } for att in attempts]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def audit_table() -> pd.DataFrame:
    rows = []
    for e in reversed(audit.read_log()):                       # newest first
        w1, ho = e["week1"] or {}, e["holdout"] or {}
        rows.append({
            "Time (UTC)": e["timestamp"], "Rule": e["rule_id"], "Action": e["action"],
            "Exclusion": fmt_exclusions(e["exclusions"]), "Reason": e["reason"],
            "Wk1 alerts": f"{w1['alerts_before']} → {w1['alerts_after']}" if w1 else "-",
            "Wk1 attacks hidden": w1.get("missed_attacks", "-"),
            "Holdout alerts": f"{ho['alerts_before']} → {ho['alerts_after']}" if ho else "-",
            "Holdout attacks hidden": ho.get("missed_attacks", "-"),
        })
    return pd.DataFrame(rows)


# --- Sidebar: demo controls ------------------------------------------------------
with st.sidebar:
    st.header("Settings")
    threshold = st.slider("Tune rules with week 1 FP rate above", 0, 100,
                          int(DEFAULT_THRESHOLD * 100), step=5, format="%d%%") / 100
    st.caption(f"Auto-apply needs: 0 attacks hidden in week 1, 0 in the holdout, and at "
               f"least {MIN_CONDITIONS} conditions in every exclusion. Anything else is "
               "queued for human review.")
    st.header("Demo controls")
    if st.button("Reset rules and audit log"):
        save_rules([{**r, "exclusions": []} for r in rules])
        audit.clear_log()
        results.clear()
        st.rerun()

# --- 1. Current state ---------------------------------------------------------
st.subheader("Current rule health")
st.dataframe(overview_table(rules), hide_index=True, width="stretch")

# --- 2. Run the agent ---------------------------------------------------------
col_auto, col_prop, _ = st.columns([2, 2, 3])
run_auto = col_auto.button("🤖 Run autonomous tuning on all rules", type="primary")
run_prop = col_prop.button("Propose only (human approves everything)")
if run_auto or run_prop:
    with st.status("Agent running...", expanded=True) as status:
        try:
            for res in run_autonomous(events, threshold, auto_apply=run_auto, log=st.write):
                results[res["rule_id"]] = res
            status.update(label="Agent run complete", state="complete", expanded=False)
        except Exception as e:
            status.update(label=f"Agent run failed: {e}", state="error")
    st.rerun()                                     # redraw health table with applied changes

# --- 3. Run summary -----------------------------------------------------------
if results:
    s = summarize(list(results.values()), events)
    st.subheader("Run summary")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Rules auto-applied", s["auto_applied"])
    c2.metric("Awaiting human review", s["queued"])
    c3.metric("Alerts removed (2 weeks)", s["alerts_removed"],
              help=f"{s['alerts_removable_if_approved']} more if queued changes are approved")
    c4.metric("Attacks still caught", f"{s['attacks_caught']} / {s['attacks_total']}")

# --- 4. Per-rule results ------------------------------------------------------
BADGES = {"auto-applied": "🤖 Auto-applied", "queued for review": "🕵️ Needs human review",
          "rejected": "⛔ Rejected"}

for rule_id, res in results.items():
    st.divider()
    decision = res["decision"]
    if res.get("applied") and decision["action"] != "auto-applied":
        badge = "✅ Approved by human"
    else:
        badge = BADGES[decision["action"]]
    st.subheader(f"{rule_id} · {res['rule_name']} · {badge}")
    st.caption(f"Agent decision: {decision['reason']}")

    st.markdown(f"**Root cause (agent's explanation):** {res['explanation']}")
    st.markdown("**🔒 Safety check**: every proposal is backtested on week 1, then validated "
                "on the week 2 holdout the agent never saw.")
    safety_panel(res["attempts"])

    if not res["success"]:
        st.error("No proposal passed both safety checks. The rule was left unchanged.")
        continue

    impact_row("Week 1 (training)", res["week1"])
    impact_row("Week 2 (holdout, unseen)", res["holdout"])
    st.markdown("**Rule diff**")
    st.code(rule_diff(res["original_rule"], res["proposed_rule"]), language="diff")

    if res.get("applied"):
        live = next(r for r in load_rules() if r["id"] == rule_id)
        v = backtest(live, events)
        st.success(f"Live in rules.json. Verified on all data: {v['alerts']} alerts, "
                   f"{v['true_positives']} attacks caught, {v['false_positives']} false positives.")
        continue

    col_ok, col_no, _ = st.columns([1, 1, 4])
    if col_ok.button("✅ Approve & apply", key=f"approve_{rule_id}", type="primary"):
        save_rules([res["proposed_rule"] if r["id"] == rule_id else r for r in load_rules()])
        audit.record(rule_id, "human-approved", res["attempts"][-1]["proposal"]["exclusions"],
                     "Approved by analyst in the dashboard", res["week1"], res["holdout"])
        res["applied"] = True
        st.rerun()
    if col_no.button("Reject", key=f"reject_{rule_id}"):
        audit.record(rule_id, "human-rejected", res["attempts"][-1]["proposal"]["exclusions"],
                     "Rejected by analyst in the dashboard", res["week1"], res["holdout"])
        del results[rule_id]
        st.rerun()

# --- 5. Audit log -------------------------------------------------------------
st.divider()
st.subheader("📜 Audit log")
log_df = audit_table()
if log_df.empty:
    st.caption("No decisions yet.")
else:
    st.dataframe(log_df, hide_index=True, width="stretch")
