"""SIEM Tuning Agent dashboard.

Run:  streamlit run app.py
"""
import time

import streamlit as st

from agent import audit
from agent.autonomous import DEFAULT_THRESHOLD, DEMO_RULE_ID, MIN_CONDITIONS, run_autonomous, summarize
from agent.backtest import backtest, split_weeks
from agent.engine import load_events, load_rules, save_rules
from agent.tuner import MODEL
from ui.agent_view import LiveRun, render_result
from ui.components import badge, hero, html, kpis, note, rule_card, section
from ui.tabs import render_evaluation, render_how, render_impact, render_safety
from ui.theme import ATTACK, CRITICAL, GOOD, NOISE, WARNING, inject_css

st.set_page_config(page_title="SIEM Tuning Agent", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")
inject_css()

events = load_events()
week1, _ = split_weeks(events)
rules = load_rules()
results = st.session_state.setdefault("results", {})   # rule_id -> tuner result (this session)


# ---------------------------------------------------------------- human decisions
def approve(rule_id: str) -> None:
    res = results[rule_id]
    save_rules([res["proposed_rule"] if r["id"] == rule_id else r for r in load_rules()])
    audit.record(rule_id, "human-approved", res["attempts"][-1]["proposal"]["exclusions"],
                 "Approved by analyst in the dashboard", res["week1"], res["holdout"])
    res["applied"] = True
    st.rerun()


def reject(rule_id: str) -> None:
    res = results[rule_id]
    audit.record(rule_id, "human-rejected", res["attempts"][-1]["proposal"]["exclusions"],
                 "Rejected by analyst in the dashboard", res["week1"], res["holdout"])
    del results[rule_id]
    st.rerun()


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    html('<div style="display:flex;gap:.7rem;align-items:center;margin:.2rem 0 1rem">'
         '<div class="logo" style="width:38px;height:38px;font-size:1.2rem">🛡️</div>'
         '<div><div style="font-weight:800;font-size:1rem">SIEM Tuning Agent</div>'
         '<div class="muted" style="font-size:.75rem">HUMAIN × Misk · Challenge 3</div></div></div>')
    html('<div class="eyebrow">Agent settings</div>')
    threshold = st.slider("Tune rules with week 1 FP rate above", 0, 100, int(DEFAULT_THRESHOLD * 100),
                          step=5, format="%d%%") / 100
    html(f'<div class="lead" style="font-size:.78rem">Auto-apply needs 0 attacks hidden in week 1, 0 in the '
         f'holdout, and at least {MIN_CONDITIONS} conditions per exclusion. Anything else waits for a human.</div>')
    html('<div class="eyebrow" style="margin-top:1rem">Demo controls</div>')
    inject = st.checkbox("Demo: inject risky proposal",
                         help=f"Forces a first proposal of 'exclude all VPN logins' on {DEMO_RULE_ID}. It passes "
                              "week 1 but hides a real attack in the holdout, so the run shows blocked, retry, accepted.")
    animate = st.toggle("Step-by-step animation", value=True,
                        help="Paces the live run so each step is visible. Turn off for a fast run.")
    if st.button("Reset rules and audit log", width="stretch", icon=":material/restart_alt:"):
        save_rules([{**r, "exclusions": []} for r in rules])
        audit.clear_log()
        results.clear()
        st.session_state.pop("last_run", None)
        st.rerun()
    html(f'<div class="muted" style="font-size:.72rem;margin-top:1rem">Model <span class="mono">{MODEL}</span><br>'
         f'{len(events):,} labelled events · weeks 1–2</div>')

# ---------------------------------------------------------------- header
tuned_ids = audit.tuned_rule_ids()
html(hero("SIEM Tuning Agent",
          f"Finds noisy detection rules, diagnoses them with {MODEL}, proves every fix on training data "
          "and an unseen holdout week, and applies only the provably safe ones.",
          [("AGENT", "ONLINE"), ("MODEL", MODEL), ("EVENTS", f"{len(events):,} · 2 weeks"),
           ("RULES", f"{len(rules)}"), ("LIVE EXCLUSIONS", f"{sum(len(r['exclusions']) for r in rules)}")]))

tab_live, tab_safety, tab_impact, tab_eval, tab_how = st.tabs(
    [":material/bolt: Live Agent", ":material/verified_user: Safety & Audit", ":material/trending_down: Impact",
     ":material/science: Evaluation", ":material/schema: How it works"])

# ================================================================ Live Agent
with tab_live:
    html(section("Detection rules", "Rule health", "Backtested on the labelled event history. "
                 "Rules marked Already tuned are skipped by later autonomous runs until you reset."))
    cols = st.columns(len(rules), gap="small")
    for col, r in zip(cols, rules):
        m, m1 = backtest(r, events), backtest(r, week1)
        status = "already tuned" if r["id"] in tuned_ids else ("noisy" if m1["fp_rate"] > threshold else "ok")
        with col:
            html(rule_card(r, m, m1, status))

    html(section("Agent", "Run the agent",
                 "Detect → diagnose → propose → backtest → holdout → apply, for every rule above the threshold."))
    c1, c2, c3 = st.columns([1.75, 1.75, 1.3])
    run_auto = c1.button("Run autonomous tuning on all rules", type="primary", width="stretch",
                         icon=":material/play_arrow:")
    run_prop = c2.button("Propose only (human approves everything)", width="stretch",
                         icon=":material/rule:")
    with c3:
        chips = [badge(f"Threshold {threshold:.0%}", "info", "◎")]
        if inject:
            chips.append(badge("Demo injection armed", "bad", "⚠"))
        if not animate:
            chips.append(badge("Fast mode", "", "»"))
        html('<div class="checks" style="margin-top:.35rem">' + "".join(chips) + "</div>")

    live_box = st.container()
    if run_auto or run_prop:
        live = LiveRun(live_box, pace=0.45 if animate else 0)
        try:
            for res in run_autonomous(events, threshold, auto_apply=run_auto, log=lambda *a: None,
                                      inject_risky=inject, on_event=live):
                results[res["rule_id"]] = res
            st.session_state["last_run"] = live.meta
        except Exception as ex:                                  # surface API failures, keep the app up
            st.session_state["last_run"] = {**live.meta, "errors": live.meta["errors"] + [{"error": str(ex)}]}
        live.sleep(3)
        st.rerun()

    last = st.session_state.get("last_run")
    if last:
        bits = []
        if last["skipped"]:
            bits.append(f"Skipped {', '.join(last['skipped'])}: already tuned.")
        if last["inject_skipped"]:
            bits.append("Demo injection was armed, but the impossible travel rule was not tuned this run. "
                        "Reset to replay it.")
        if not last["targets"] and not last["skipped"]:
            bits.append("No rule is above the threshold.")
        for err in last["errors"]:
            bits.append(f"Agent error: {err['error']}")
        if bits:
            html(note(" ".join(bits)))

    if results:
        s = summarize(list(results.values()), events)
        blocked = sum(a["status"] == "rejected" for res in results.values() for a in res["attempts"])
        html(section("Run summary", "What the agent did"))
        html(kpis([
            {"label": "Rules auto-applied", "value": s["auto_applied"], "accent": GOOD},
            {"label": "Awaiting human review", "value": s["queued"], "accent": WARNING},
            {"label": "Unsafe proposals blocked", "value": blocked, "accent": CRITICAL},
            {"label": "Alerts removed · 2 weeks", "value": s["alerts_removed"], "accent": NOISE,
             "sub": f"+{s['alerts_removable_if_approved']} if queued changes are approved"},
            {"label": "Attacks still caught", "value": f"{s['attacks_caught']} / {s['attacks_total']}",
             "accent": GOOD if s["attacks_caught"] == s["attacks_total"] else CRITICAL},
        ]))
        for res in results.values():
            render_result(res, events, approve, reject)
    elif not (run_auto or run_prop):
        with live_box:   # inside the live area, so a run replaces it instead of leaving it stale
            html(note("Press Run to watch the agent work. Arm the demo injection in the sidebar to see the "
                      "safety gates block an unsafe change live."))

with tab_safety:
    render_safety(events, results)
with tab_impact:
    render_impact(events)
with tab_eval:
    render_evaluation()
with tab_how:
    render_how(events)
