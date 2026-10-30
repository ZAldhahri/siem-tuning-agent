"""Live (animated) and static views of agent runs."""
import time

import streamlit as st

from agent.backtest import backtest, split_weeks
from agent.engine import load_rules
from ui import charts
from ui.components import (attempt_card, attempt_state_from_record, badge, blocked_banner,
                           decision_badge, e, html, note, safe_banner, table, tracker)

STEP_KEYS = ["detect", "diagnose", "propose", "backtest", "holdout", "apply"]
APPLY_STATE = {"auto-applied": ("done", "Applied"), "human-approved": ("done", "Approved"),
               "queued for review": ("warn", "Needs review"), "rejected": ("fail", "Not applied")}


def rule_header(rule: dict, meta: str, right: str = "") -> str:
    return (f'<div class="run-head"><div><div class="run-title"><span class="rule-id">{e(rule["id"])}</span>'
            f'{e(rule["name"])}</div><div class="run-meta">{e(meta)}</div></div><div>{right}</div></div>')


def baseline_meta(alerts: int, fp: int, tp: int, fp_rate: float) -> str:
    return (f"Week 1: {alerts} alerts · {fp} false positives ({fp_rate:.0%}) · "
            f"{tp} real attacks")


def proposal_label(proposal: dict) -> str:
    reasons = [g.get("reason", "") for g in proposal.get("exclusions", []) if g.get("reason")]
    text = "; ".join(reasons) or "this exclusion"
    return text if len(text) <= 140 else text[:137] + "…"


# ====================================================================== live view
class LiveRun:
    """Receives agent events (see agent.tuner / agent.autonomous) and animates them."""

    def __init__(self, container, pace: float):
        self.box, self.pace = container, pace
        self.rule = None                 # state of the rule being tuned right now
        self.meta = {"targets": [], "skipped": [], "inject_skipped": False, "errors": []}

    def __call__(self, kind: str, data: dict) -> None:
        handler = getattr(self, f"on_{kind}", None)
        if handler:
            handler(data)

    def sleep(self, k: float = 1.0) -> None:
        if self.pace:
            time.sleep(self.pace * k)

    # ---- rendering helpers
    def _render_tracker(self):
        r = self.rule
        r["ph_tracker"].html(tracker(r["states"], r["subs"]))

    def _render_header(self, right=""):
        r = self.rule
        r["ph_head"].html(rule_header(r["rule"], r["meta"], right))

    def _render_card(self):
        r = self.rule
        r["cards"][r["n"]].html(attempt_card(r["card"]))

    def _render_banners(self):
        r = self.rule
        r["ph_banner"].html("".join(r["banners"])) if r["banners"] else r["ph_banner"].empty()

    def _set(self, step, state, sub=None):
        self.rule["states"][step] = state
        if sub is not None:
            self.rule["subs"][step] = sub
        self._render_tracker()

    # ---- events
    def on_run_start(self, d):
        self.meta.update(targets=d["targets"], skipped=d["skipped"], inject_skipped=d["inject_skipped"])
        bits = [f"Tuning {', '.join(d['targets'])}" if d["targets"] else "No noisy rules to tune"]
        if d["skipped"]:
            bits.append(f"skipping {', '.join(d['skipped'])} (already tuned)")
        with self.box:
            html(note(" · ".join(bits) + "."))
            if d["inject_skipped"]:
                html(note("Demo injection is armed, but the impossible travel rule is not being tuned "
                          "this run. Reset the demo to replay it."))

    def on_rule_start(self, d):
        with self.box:
            c = st.container(border=True)
        with c:
            ph_head, ph_tracker, ph_banner = st.empty(), st.empty(), st.empty()
            cards = st.container()
        self.rule = {"rule": d["rule"], "meta": "Scanning week 1 alerts…", "states": {"detect": "active"},
                     "subs": {}, "ph_head": ph_head, "ph_tracker": ph_tracker, "ph_banner": ph_banner,
                     "cards_box": cards, "cards": {}, "banners": [], "n": 0, "card": None}
        self._render_header(badge("Agent working", "info", "…"))
        self._render_tracker()
        self.sleep()

    def on_detect(self, d):
        self.rule["meta"] = baseline_meta(d["alerts"], d["false_positives"], d["true_positives"], d["fp_rate"])
        self._render_header(badge("Agent working", "info", "…"))
        self._set("detect", "done", f"{d['fp_rate']:.0%} noise")
        self.sleep()

    def on_diagnose(self, d):
        r = self.rule
        r["n"] = d["attempt"]
        for k in ("propose", "backtest", "holdout"):
            r["states"][k] = "pending"
            r["subs"].pop(k, None)
        self._set("diagnose", "active", "Injected" if d["injected"] else f"Attempt {d['attempt']}")
        with r["cards_box"]:
            r["cards"][d["attempt"]] = st.empty()
        r["card"] = {"attempt": d["attempt"], "injected": d["injected"], "proposal": None,
                     "backtest": None, "holdout": None, "status": "pending"}
        self._render_card()
        self.sleep(1.5 if d["injected"] else 0.5)

    def on_propose(self, d):
        r = self.rule
        r["card"]["proposal"] = d["proposal"]
        self._set("diagnose", "done")
        self._set("propose", "active", f"{len(d['proposal']['exclusions'])} exclusion(s)")
        self._render_card()
        self.sleep()
        self._set("propose", "done")
        if d["proposal"]["exclusions"]:
            self._set("backtest", "active")
        self.sleep(0.6)

    def on_backtest(self, d):
        r = self.rule
        r["card"]["backtest"] = d
        self._set("backtest", "done" if d["passed"] else "fail",
                  "0 hidden" if d["passed"] else f"hides {d['missed']}" if not d.get("error") else "invalid")
        self._render_card()
        if d["passed"]:
            self.sleep()
            self._set("holdout", "active", "unseen week")
        self.sleep()

    def on_holdout(self, d):
        r = self.rule
        r["card"]["holdout"] = d
        if d["passed"]:
            self._set("holdout", "done", "0 hidden")
        elif not d["gated"]:
            self._set("holdout", "warn", f"hides {d['missed']} (not enforced)")
        else:
            self._set("holdout", "fail", f"hides {d['missed']}")
        self._render_card()
        if not d["passed"] and d["gated"]:
            r["banners"].append(blocked_banner(proposal_label(r["card"]["proposal"]), d["missed"],
                                               "week 2, data the agent never saw"))
            self._render_banners()
            self.sleep(5)            # the dramatic pause
        else:
            self.sleep()

    def on_attempt(self, d):
        r = self.rule
        rec = d["record"]
        r["card"] = attempt_state_from_record(rec)
        self._render_card()
        if rec["status"] == "rejected" and rec.get("week1") and rec["week1"]["missed"]:
            self.sleep(1.5)
        if rec["status"] == "accepted" and r["banners"]:
            r["banners"].append(safe_banner(f"Attempt {rec['attempt']} passed both safety checks: "
                                            "0 attacks hidden in training and in the holdout."))
            self._render_banners()
            self.sleep(1.5)

    def on_decision(self, d):
        state, sub = APPLY_STATE.get(d["action"], ("warn", d["action"]))
        self._set("apply", "active")
        self.sleep(0.8)
        self._set("apply", state, sub)
        self._render_header(decision_badge(d["action"]))
        self.sleep()

    def on_error(self, d):
        self.meta["errors"].append(d)
        if self.rule:
            self._render_header(badge("Agent error", "bad", "✕"))
            with self.rule["cards_box"]:
                html(note(f"Agent error: {d['error']}"))


# ====================================================================== static view
def static_states(res: dict) -> tuple[dict, dict]:
    states = {"detect": "done", "diagnose": "done", "propose": "done"}
    attempts = res["attempts"]
    subs = {"diagnose": f"{len(attempts)} attempt(s)"}
    last = attempt_state_from_record(attempts[-1])
    if last["status"] == "nochange":
        states["propose"] = "warn"
        subs["propose"] = "no safe change"
    else:
        subs["propose"] = f"{len(last['proposal']['exclusions'])} exclusion(s)"
    bt, ho = last["backtest"], last["holdout"]
    if bt is not None:
        states["backtest"] = "done" if bt["passed"] else "fail"
        subs["backtest"] = "0 hidden" if bt["passed"] else (f"hides {bt['missed']}" if not bt["error"] else "invalid")
    if ho is not None:
        states["holdout"] = "done" if ho["passed"] else "fail"
        subs["holdout"] = "0 hidden" if ho["passed"] else f"hides {ho['missed']}"
    action = "human-approved" if res.get("applied") and res["decision"]["action"] != "auto-applied" \
        else res["decision"]["action"]
    states["apply"], subs["apply"] = APPLY_STATE.get(action, ("warn", action))
    return states, subs


def impact_table(res: dict) -> str:
    rows, cls = [], []
    for label, v in (("Week 1", res["week1"]), ("Holdout", res["holdout"])):
        b, a = v["before"], v["after"]
        rows.append([label, f"{b['alerts']} → {a['alerts']}", f"{v['fp_removed']} / {v['fp_before']}",
                     f"{v['tp_kept']} / {v['tp_before']}"])
        cls.append(["nw", "num", "num", "num good" if v["tp_kept"] == v["tp_before"] else "num bad"])
    return table(["Data", "Alerts", "FP removed", "Attacks kept"], rows, cls, compact=True)


def render_result(res: dict, events, on_approve, on_reject) -> None:
    rule = res["original_rule"]
    week1, _ = split_weeks(events)
    base = backtest(rule, week1)
    action = "human-approved" if res.get("applied") and res["decision"]["action"] != "auto-applied" \
        else res["decision"]["action"]
    with st.container(border=True):
        html(rule_header(rule, baseline_meta(base["alerts"], base["false_positives"],
                                             base["true_positives"], base["fp_rate"]), decision_badge(action)))
        states, subs = static_states(res)
        html(tracker(states, subs))

        blocked = [a for a in res["attempts"] if a["status"] == "rejected"]
        banners = ""
        for a in blocked:
            s = attempt_state_from_record(a)
            if s["holdout"] and not s["holdout"]["passed"]:
                banners += blocked_banner(proposal_label(a["proposal"]), s["holdout"]["missed"],
                                          "week 2, data the agent never saw")
        if blocked and res["success"]:
            banners += safe_banner(f"After {len(blocked)} blocked attempt(s), attempt {len(res['attempts'])} "
                                   "passed both safety checks: 0 attacks hidden in training and in the holdout.")
        if banners:
            html(banners)
        html(f'<div class="lead"><b>Agent decision:</b> {e(res["decision"]["reason"])}</div>')

        left, right = st.columns([3, 2], gap="large")
        with left:
            html('<div class="eyebrow">Attempts · every proposal the agent made</div>')
            html("".join(attempt_card(attempt_state_from_record(a)) for a in res["attempts"]))
        with right:
            if res["success"]:
                html('<div class="eyebrow">Alerts before vs after this change</div>')
                st.altair_chart(charts.before_after_chart([rule], [res["proposed_rule"]], events,
                                                          height=170, width=105), theme=None)
                html(impact_table(res))
            else:
                html(note("No proposal passed every safety check, so the rule is unchanged."))

        if res.get("applied"):
            live = next(r for r in load_rules() if r["id"] == rule["id"])
            v = backtest(live, events)
            html(safe_banner(f"Live in rules.json. Verified on all data: {v['alerts']} alerts, "
                             f"{v['true_positives']} real attacks still caught, {v['false_positives']} false positives."))
        elif res["success"] and res["decision"]["action"] == "queued for review":
            c1, c2, _ = st.columns([1.2, 1, 4])
            if c1.button("✓ Approve & apply", key=f"approve_{rule['id']}", type="primary"):
                on_approve(rule["id"])
            if c2.button("✕ Reject", key=f"reject_{rule['id']}"):
                on_reject(rule["id"])
