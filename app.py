"""Streamlit dashboard for the SIEM Tuning Agent.

Run:  streamlit run app.py
"""
import difflib
import json

import pandas as pd
import streamlit as st

from agent.backtest import backtest
from agent.engine import load_events, load_rules, save_rules
from agent.tuner import MODEL, tune_rule

FP_RATE_THRESHOLD = 0.2  # rules noisier than this get tuned

st.set_page_config(page_title="SIEM Tuning Agent", page_icon="🛡️", layout="wide")
st.title("🛡️ SIEM Tuning Agent")
st.caption(f"Finds noisy detection rules, diagnoses them with {MODEL}, "
           "proves the fix with a backtest, and applies it after your approval.")

events = load_events()
rules = load_rules()
results = st.session_state.setdefault("results", {})   # rule_id -> tuner result


def overview_table(rules):
    rows = []
    for r in rules:
        m = backtest(r, events)
        rows.append({"Rule": f"{r['id']} {r['name']}", "Alerts": m["alerts"],
                     "True positives": m["true_positives"],
                     "False positives": m["false_positives"],
                     "FP rate": f"{m['fp_rate']:.0%}", "Exclusions": len(r["exclusions"])})
    return pd.DataFrame(rows)


def rule_diff(old: dict, new: dict) -> str:
    a = json.dumps(old, indent=2).splitlines()
    b = json.dumps(new, indent=2).splitlines()
    return "\n".join(difflib.unified_diff(a, b, "current", "proposed", lineterm=""))


# --- Sidebar: demo controls ------------------------------------------------------
with st.sidebar:
    st.header("Demo controls")
    if st.button("Reset rules (remove all exclusions)"):
        save_rules([{**r, "exclusions": []} for r in rules])
        results.clear()
        st.rerun()

# --- 1. Current state ---------------------------------------------------------
st.subheader("Current rule health")
st.dataframe(overview_table(rules), hide_index=True, width="stretch")

# --- 2. Run the agent ---------------------------------------------------------
if st.button("▶ Run tuning agent", type="primary"):
    noisy = [r for r in rules if backtest(r, events)["fp_rate"] > FP_RATE_THRESHOLD]
    noisy.sort(key=lambda r: backtest(r, events)["false_positives"], reverse=True)
    if not noisy:
        st.success("No noisy rules. Nothing to tune.")
    for r in noisy:                                             # noisiest first
        with st.status(f"Tuning {r['id']} {r['name']}...", expanded=True) as status:
            try:
                results[r["id"]] = tune_rule(r, events, log=st.write)
                status.update(label=f"{r['id']} done", state="complete", expanded=False)
            except Exception as e:                                # show API errors, keep going
                status.update(label=f"{r['id']} failed: {e}", state="error")

# --- 3. Proposals awaiting approval -------------------------------------------
for rule_id, res in results.items():
    st.divider()
    st.subheader(f"{rule_id} · {res['rule_name']}")
    b, a = res["before"], res["after"]

    if res.get("applied"):
        st.success("✅ Approved and applied. Verification against rules.json on disk:")
        live = next(r for r in load_rules() if r["id"] == rule_id)
        v = backtest(live, events)
        c1, c2, c3 = st.columns(3)
        c1.metric("Alerts now", v["alerts"], v["alerts"] - b["alerts"], delta_color="inverse")
        c2.metric("True positives", v["true_positives"])
        c3.metric("False positives", v["false_positives"],
                  v["false_positives"] - b["false_positives"], delta_color="inverse")
        continue

    if not res["success"]:
        st.error(f"The agent could not find exclusions that keep every true positive "
                 f"after {len(res['attempts'])} attempts. The rule was left unchanged.")
        st.markdown(f"**Agent's diagnosis:** {res['explanation']}")
        continue

    # Before/after metrics
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Alerts", a["alerts"], a["alerts"] - b["alerts"], delta_color="inverse")
    c2.metric("False positives", a["false_positives"],
              a["false_positives"] - b["false_positives"], delta_color="inverse")
    c3.metric("True positives kept", f"{a['true_positives']} / {b['true_positives']}")
    c4.metric("FP rate", f"{a['fp_rate']:.0%}", f"{(a['fp_rate'] - b['fp_rate']) * 100:.0f} pts",
              delta_color="inverse")

    st.markdown(f"**Root cause (agent's explanation):** {res['explanation']}")
    with st.expander(f"Agent reasoning trail ({len(res['attempts'])} attempt(s))"):
        for att in res["attempts"]:
            m = att["metrics"]
            if att["error"]:
                st.write(f"Attempt {att['attempt']}: ❌ invalid proposal: {att['error']}")
            elif att["ok"]:
                st.write(f"Attempt {att['attempt']}: ✅ backtest passed "
                         f"({m['alerts']} alerts, 0 attacks lost)")
            else:
                st.write(f"Attempt {att['attempt']}: ❌ would have missed "
                         f"{len(m['missed_true_positives'])} real attacks, sent back to the agent")

    st.markdown("**Rule diff**")
    st.code(rule_diff(res["original_rule"], res["proposed_rule"]), language="diff")

    col_ok, col_no, _ = st.columns([1, 1, 4])
    if col_ok.button("✅ Approve & apply", key=f"approve_{rule_id}", type="primary"):
        current = load_rules()                       # re-read so other approvals aren't lost
        current = [res["proposed_rule"] if r["id"] == rule_id else r for r in current]
        save_rules(current)
        res["applied"] = True
        st.rerun()
    if col_no.button("Reject", key=f"reject_{rule_id}"):
        del results[rule_id]
        st.rerun()
