"""Safety & Audit, Impact, Evaluation and How-it-works tabs."""
import json
import re

import streamlit as st

from agent import audit
from agent.autonomous import MIN_CONDITIONS
from agent.backtest import backtest
from agent.engine import ROOT, load_rules
from agent.impact import business_impact
from agent.tuner import MAX_ATTEMPTS, MODEL
from ui import charts
from ui.components import (Safe, badge, decision_badge, diff_html, e, exclusions_html, html, kpis, note,
                           section, table)
from ui.theme import ATTACK, CRITICAL, GOOD, NOISE, WARNING

EVAL_RESULTS = ROOT / "eval" / "results.json"
EVAL_REPORT = ROOT / "eval" / "REPORT.md"


def _metrics_cell(m: dict | None) -> str:
    if not m:
        return "–"
    return f"{m['alerts_before']} → {m['alerts_after']} alerts · {m['missed_attacks']} hidden"


# ====================================================================== safety & audit
def gates_html(counts: dict | None = None) -> str:
    counts = counts or {}
    gates = [
        ("Gate 1 · Training backtest", "Replays the proposal on week 1. If any labelled attack would be "
         "hidden, the proposal is rejected and Claude sees the missed events as feedback.", counts.get("g1")),
        ("Gate 2 · Unseen holdout", "Replays it on week 2, which Claude never sees. A hidden attack means "
         "rejection; Claude is only told which exclusion was too broad.", counts.get("g2")),
        (f"Gate 3 · Narrowness", f"Auto-apply needs at least {MIN_CONDITIONS} ANDed conditions in every "
         "exclusion. Anything broader waits for a human to approve or reject it.", counts.get("g3")),
    ]
    cells = []
    for title, text, n in gates:
        stat = f'<div style="margin-top:.5rem">{badge(f"{n} caught so far", "bad" if n else "", "✕" if n else "")}</div>' \
            if n is not None else ""
        cells.append(f'<div class="gate"><div class="eyebrow">Safety gate</div><div class="ttl">{e(title)}</div>'
                     f'<div class="txt">{e(text)}</div>{stat}</div>')
    return '<div class="gates">' + "".join(cells) + "</div>"


def render_safety(events, results: dict) -> None:
    log = audit.read_log()
    rejected = [x for x in log if x["action"] == "rejected"]
    counts = {"g1": sum("Week 1" in x["reason"] for x in rejected),
              "g2": sum("Holdout" in x["reason"] for x in rejected),
              "g3": sum(x["action"] == "queued for review" and "conditions" in x["reason"] for x in log)}
    html(section("Safety", "Three gates between the model and production",
                 "Every proposal passes through these checks before anything touches rules.json."))
    html(gates_html(counts))
    html(kpis([
        {"label": "Decisions logged", "value": len(log), "sub": "data/audit_log.jsonl"},
        {"label": "Auto-applied", "value": sum(x["action"] == "auto-applied" for x in log), "accent": GOOD},
        {"label": "Human decisions", "value": sum(x["action"].startswith("human") for x in log), "accent": WARNING},
        {"label": "Proposals blocked", "value": len(rejected), "accent": CRITICAL},
    ]))

    html(section("Blocked", "Proposals the gates rejected",
                 "Kept on record so a reviewer can see what the agent tried and why it was stopped."))
    if not rejected:
        html(note("No proposal has been blocked yet. Run the agent with the demo injection armed to see one."))
    for x in reversed(rejected):
        html(f'<div class="attempt rejected"><div class="stamp">BLOCKED</div><div class="att-head">'
             f'<span class="att-n">{e(x["rule_id"])} · {e(x["timestamp"])}</span>{badge("Rejected", "bad", "✕")}</div>'
             f'<div class="att-cause">{e(x["reason"])}</div>{exclusions_html(x["exclusions"])}'
             f'<div class="checks"><span class="check">Week 1: {e(_metrics_cell(x["week1"]))}</span>'
             f'<span class="check">Holdout: {e(_metrics_cell(x["holdout"]))}</span></div></div>')

    html(section("Changes", "Rule diffs", "What is live in rules.json compared with the untuned rule, "
                 "and any proposal still waiting for review."))
    pending = {rid: r for rid, r in results.items()
               if r["success"] and not r.get("applied") and r["decision"]["action"] == "queued for review"}
    for rule in load_rules():
        label = badge("Live", "good", "●") if rule["exclusions"] else badge("Untuned", "", "○")
        html(f'<div class="rule-top" style="margin-top:.9rem"><span class="rule-id">{e(rule["id"])} · '
             f'{len(rule["exclusions"])} exclusion(s)</span>{label}</div>'
             f'<div class="rule-name" style="margin:.3rem 0 .5rem">{e(rule["name"])}</div>')
        html(diff_html({**rule, "exclusions": []}, rule, "untuned", "live"))
        if rule["id"] in pending:
            html('<div class="eyebrow" style="margin-top:.6rem">Pending review</div>')
            html(diff_html(pending[rule["id"]]["original_rule"], pending[rule["id"]]["proposed_rule"]))

    html(section("Audit", "Audit log", "Newest first. Every auto-apply, queue, rejection and human decision."))
    if not log:
        html(note("No decisions yet."))
        return
    rows, cls = [], []
    for x in reversed(log):
        when = x["timestamp"].replace("+00:00", "")
        rows.append([Safe(f'{e(when[:10])}<br>{e(when[11:])}'), x["rule_id"], Safe(decision_badge(x["action"])),
                     Safe(exclusions_html(x["exclusions"])),
                     Safe(f'{e(x["reason"])}<div class="metrics-line">Week 1: {e(_metrics_cell(x["week1"]))}'
                          f'<br>Holdout: {e(_metrics_cell(x["holdout"]))}</div>')])
        cls.append(["mono nw", "mono", "", "", "reason"])
    html(table(["Time (UTC)", "Rule", "Action", "Exclusion", "Reason · before → after"], rows, cls, scroll=True))


# ====================================================================== impact
def render_impact(events) -> None:
    html(section("Business impact", "What the live rules save your SOC",
                 "Live rules.json compared with the same rules without exclusions, on the two weeks of event data."))
    minutes = st.slider("Assumed triage time per alert (minutes)", 1, 60, 10, key="triage")
    rules = load_rules()
    imp = business_impact(events, rules, minutes)
    all_caught = imp["attacks_caught"] == imp["attacks_total"]
    html(kpis([
        {"label": "Analyst hours saved per week", "value": f"{imp['hours_saved_per_week']:g}", "hero": True,
         "sub": f"≈ {imp['hours_saved_per_week'] * 52:,.0f} hours a year at this rate · {minutes} min per alert"},
        {"label": "Alerts removed per week", "value": f"{imp['alerts_removed_per_week']:g}", "hero": True,
         "sub": "average of week 1 and week 2", "accent": NOISE},
    ]))
    html(kpis([
        {"label": "Noise reduction", "value": f"{imp['noise_reduction_pct']:g}%",
         "sub": "share of false-positive alerts removed", "accent": NOISE},
        {"label": "Attacks still caught", "value": f"{imp['attacks_caught']} / {imp['attacks_total']}",
         "sub": "✓ none hidden" if all_caught else "✕ some attacks hidden", "accent": GOOD if all_caught else CRITICAL},
        {"label": "Rules tuned", "value": f"{sum(bool(r['exclusions']) for r in rules)} / {len(rules)}",
         "sub": "with live exclusions", "accent": ATTACK},
    ]))
    if not any(r["exclusions"] for r in rules):
        html(note("No tuning is live yet, so savings are zero. Run the agent from the Live Agent tab."))

    left, right = st.columns([1, 1], gap="large")
    with left:
        html('<div class="eyebrow">All rules · alerts per week, untuned vs live</div>')
        st.altair_chart(charts.before_after_chart([{**r, "exclusions": []} for r in rules], rules, events,
                                                  height=230, width=160), theme=None)
    with right:
        html('<div class="eyebrow">Per week</div>')
        html(table(["Week", "Before", "After", "Removed", "Hours saved"],
                   [[f"Week {w['week']} ({'training' if w['week'] == 1 else 'holdout'})", w["alerts_before"],
                     w["alerts_after"], w["alerts_removed"], f"{w['hours_saved']:g}"] for w in imp["weeks"]],
                   [["nw", "num", "num", "num", "num"]] * len(imp["weeks"]), compact=True))
    html('<div class="eyebrow" style="margin-top:1rem">Per rule · both weeks</div>')
    rows, cls = [], []
    for r in rules:
        b, a = backtest({**r, "exclusions": []}, events), backtest(r, events)
        rows.append([f"{r['id']} · {r['name']}", f"{b['alerts']} → {a['alerts']}",
                     f"{b['false_positives'] - a['false_positives']} / {b['false_positives']}",
                     f"{a['true_positives']} / {b['true_positives']}", len(r["exclusions"])])
        cls.append(["nw", "num", "num", "num good" if a["true_positives"] == b["true_positives"] else "num bad", "num"])
    html(table(["Rule", "Alerts", "False positives removed", "Attacks still caught", "Exclusions"], rows, cls))


# ====================================================================== evaluation
def _fmt(stat, pct=False):
    if stat is None:
        return "n/a"
    u = "%" if pct else ""
    return f"{stat['mean']:g}{u}" if stat["std"] == 0 else f"{stat['mean']:g}{u} ± {stat['std']:g}"


def _known_limits() -> str:
    if not EVAL_REPORT.exists():
        return ""
    m = re.search(r"## Known limits of this evaluation\n(.*?)(?=\n## )", EVAL_REPORT.read_text(), re.S)
    return m.group(1).strip() if m else ""


def render_evaluation() -> None:
    html(section("Evaluation", "Held-out results on three unseen datasets",
                 "Read live from eval/results.json. Every variant tunes bare rules on week 1 and is scored "
                 "on week 3, a test week no variant ever touches. Week 2 is the full agent's holdout gate."))
    if not EVAL_RESULTS.exists():
        html(note("No evaluation results yet. Run the command below (needs the API key)."))
        st.code("python -m eval.run_eval", language="bash")
        return
    r = json.loads(EVAL_RESULTS.read_text())
    S = {(s["dataset"], s["variant"]): s for s in r["summary"]}
    ds = r["datasets"]
    llm_costs = [x["cost_usd"] for x in r["runs_detail"] if x["variant"] in ("C", "D")]
    pt = r["pytest"]
    total_cost = "n/a" if None in llm_costs else f"${sum(llm_costs):.2f}"
    html('<div class="pills" style="margin:.2rem 0 .6rem">'
         f'<span class="pill">GENERATED <b>{e(r["generated_at"].replace("T", " ").replace("+00:00", " UTC"))}</b></span>'
         f'<span class="pill">MODEL <b>{e(r["model"])}</b></span>'
         f'<span class="pill">RUNS PER LLM VARIANT <b>{r["runs"]}</b></span>'
         f'<span class="pill">TOTAL API COST <b>{e(total_cost)}</b></span>'
         f'<span class="pill">WALL TIME <b>{r["wall_seconds"]:g} s</b></span>'
         f'<span class="pill">PYTEST <b>{e(pt["summary"])}</b></span></div>')

    # ---- headline: full agent
    html('<div class="eyebrow" style="margin-top:.8rem">Full agent (D) on the unseen test week</div>')
    cards = []
    for d in ds:
        s = S[(d, "D")]
        missed = s["test_missed"]["values"]
        ok = sum(missed) == 0
        cards.append({"label": f"{d} · noise removed", "value": _fmt(s["test_noise_reduction_pct"], pct=True),
                      "accent": GOOD if ok else CRITICAL,
                      "sub": f"{'✓' if ok else '✕'} attacks kept {s['test_attacks_kept']['mean']:g}/{s['test_attacks_total']} · "
                             f"missed per run {', '.join(f'{v:g}' for v in missed)} · "
                             f"{s['rejected']['mean']:g} proposals blocked · ${s['cost_usd']['mean']:.3f}/run"})
    html(kpis(cards))

    # ---- ablations
    html(section("Ablations", "What each component buys you",
                 "A = bare rules · B = exclude the most frequent false-positive value (no LLM) · "
                 "C = agent without holdout validation · D = full agent. Bars are the mean across runs, "
                 "white dots are individual runs."))
    st.altair_chart(charts.ablation_chart(r["summary"], ds, "test_missed", "Missed attacks", ATTACK), theme=None)
    st.altair_chart(charts.ablation_chart(r["summary"], ds, "test_noise_reduction_pct", "Noise reduction %",
                                          NOISE, pct=True), theme=None)
    rows, cls, rc = [], [], []
    names = {"A": "A · No agent", "B": "B · Heuristic, no LLM", "C": "C · Agent, no holdout", "D": "D · Full agent"}
    for d in ds:
        for v in "ABCD":
            s = S[(d, v)]
            missed = s["test_missed"]["values"]
            rows.append([d, names[v], _fmt(s["test_noise_reduction_pct"], pct=True),
                         f"{s['test_attacks_kept']['mean']:g} / {s['test_attacks_total']}",
                         ", ".join(f"{x:g}" for x in missed), ", ".join(f"{x:g}" for x in s["val_missed"]["values"]),
                         f"{s['rules_unchanged']['mean']:g} / 3"])
            cls.append(["nw", "nw", "num", "num", "num bad" if sum(missed) else "num good", "num", "num"])
            rc.append("hl" if v == "D" else "")
    html(table(["Dataset", "Variant", "Noise reduction", "Attacks kept", "Missed · test",
                "Missed · validation", "Rules unchanged"], rows, cls, row_classes=rc))

    html('<div class="eyebrow" style="margin-top:1rem">Computed findings</div>')
    lines = []
    for d in ds:
        b, c, dd = (S[(d, v)] for v in "BCD")
        lines.append(f"- **{d}**: missed test attacks summed over runs: heuristic {sum(b['test_missed']['values']):g}, "
                     f"agent without holdout {sum(c['test_missed']['values']):g}, full agent "
                     f"{sum(dd['test_missed']['values']):g}. Mean noise reduction: "
                     f"{b['test_noise_reduction_pct']['mean']:g}% / {c['test_noise_reduction_pct']['mean']:g}% / "
                     f"{dd['test_noise_reduction_pct']['mean']:g}%.")
    helped = [d for d in ds if sum(S[(d, "C")]["test_missed"]["values"]) > sum(S[(d, "D")]["test_missed"]["values"])]
    lines.append(f"- Holdout validation reduced missed attacks on: **{', '.join(helped) or 'none of the datasets'}**. "
                 f"On the others C and D missed the same number of attacks.")
    st.markdown("\n".join(lines))

    # ---- variance
    html(section("Variance", "Run-to-run variation (LLM nondeterminism)",
                 f"Each LLM variant ran {r['runs']} times on every dataset with identical inputs."))
    worst = max((s for s in r["summary"] if s["variant"] in "CD"),
                key=lambda s: s["test_noise_reduction_pct"]["std"])
    html(note(f"Largest spread: {worst['dataset']} · variant {worst['variant']} · noise reduction "
              f"{_fmt(worst['test_noise_reduction_pct'], pct=True)} "
              f"(runs: {', '.join(f'{v:g}%' for v in worst['test_noise_reduction_pct']['values'])}). "
              "Missed attacks did not vary between runs for any variant."
              if all(s["test_missed"]["std"] == 0 for s in r["summary"]) else
              f"Largest spread: {worst['dataset']} · variant {worst['variant']}."))
    rows, cls = [], []
    for x in r["runs_detail"]:
        if x["variant"] not in ("C", "D"):
            continue
        rows.append([x["dataset"], x["variant"], x["run"], f"{x['week3']['noise_reduction_pct']:g}%",
                     x["week3"]["missed"], x["week2"]["missed"], x["attempts"], x["rejected"],
                     "n/a" if x["cost_usd"] is None else f"${x['cost_usd']:.3f}", f"{x['seconds']:g} s", x["errors"]])
        cls.append(["nw", "", "num", "num", "num bad" if x["week3"]["missed"] else "num", "num", "num", "num",
                    "num", "num", "num bad" if x["errors"] else "num"])
    html(table(["Dataset", "Var.", "Run", "Noise ↓ test", "Missed test", "Missed val.",
                "Attempts", "Blocked", "Cost", "Time", "Errors"], rows, cls, scroll=True))

    # ---- regression
    html(section("Regression", "Do previously accepted rules still hold?",
                 "eval/accepted_rules.json holds the exclusions accepted on the development data. "
                 "A dataset passes if they hide 0 attacks across all its weeks."))
    reg = r["regression"]
    rule_ids = sorted({x["rule_id"] for x in reg})
    datasets = list(dict.fromkeys(x["dataset"] for x in reg))
    rows, cls = [], []
    for d in datasets:
        cells = {x["rule_id"]: x for x in reg if x["dataset"] == d}
        ok = all(c["passed"] for c in cells.values())
        rows.append([d] + [Safe(badge(f"{cells[i]['missed']} / {cells[i]['attacks']} hidden",
                                      "good" if cells[i]["passed"] else "bad", "✓" if cells[i]["passed"] else "✕"))
                           for i in rule_ids] + [Safe(badge("PASS" if ok else "FAIL", "good" if ok else "bad",
                                                            "✓" if ok else "✕"))])
        cls.append([""] * (len(rule_ids) + 2))
    html(table(["Dataset"] + rule_ids + ["Result"], rows, cls))
    pt_ok = pt["exit_code"] == 0
    html(f'<div class="checks" style="margin-top:.6rem">{badge("pytest " + pt["summary"], "good" if pt_ok else "bad", "✓" if pt_ok else "✕")}</div>')
    for x in pt.get("xfail", []):
        html(note("Expected failure, documented in the test suite: " + x.replace("XFAIL ", "")))

    limits = _known_limits()
    if limits:
        html(section("Caveats", "Known limits of this evaluation"))
        st.markdown(limits)
    errors = [j for j in r["jobs"] if j.get("error")]
    html(section("Errors", f"{len(errors)} agent error(s) during the evaluation"))
    for j in errors:
        html(note(f"{j['dataset']} {j['variant']} run {j['run']} {j['rule_id']}: {j['error']}"))
    html('<div class="eyebrow" style="margin-top:1rem">Reproduce</div>')
    st.code("python -m eval.run_eval            # full run, writes eval/results.json and eval/REPORT.md\n"
            "python -m eval.run_eval --report-only\npython -m pytest", language="bash")


# ====================================================================== how it works
ARCH_HTML = """
<div class="arch">
  <div class="lane"><div class="lane-t">1 · Data & detection</div>
    <div class="node">events.csv<small>labelled events · week 1 and week 2</small></div>
    <div class="node">rules.json<small>conditions + exclusions</small></div>
    <div class="node">Rule engine<small>conditions AND · exclusion groups OR</small></div>
    <div class="node">Autonomous runner<small>FP rate above threshold · skips tuned rules</small></div></div>
  <div class="arrow">➜</div>
  <div class="lane"><div class="lane-t">2 · Reasoning</div>
    <div class="node">Week 1 false-positive profile<small>top values per field + a sample</small></div>
    <div class="node accent">Claude Sonnet 5.5<small>root cause in plain English + exclusions as schema-checked JSON</small></div>
    <div class="node bad">Feedback on rejection<small>week 1: the missed events · holdout: only which exclusion was too broad · up to 3 attempts</small></div></div>
  <div class="arrow">➜</div>
  <div class="lane"><div class="lane-t">3 · Safety gates</div>
    <div class="node gate">Gate 1 · training backtest<small>0 attacks hidden in week 1</small></div>
    <div class="node gate">Gate 2 · unseen holdout<small>0 attacks hidden in week 2</small></div>
    <div class="node gate">Gate 3 · narrowness<small>every exclusion has ≥ 2 conditions</small></div>
    <div class="node bad">Any gate fails<small>blocked, logged, sent back to Claude</small></div></div>
  <div class="arrow">➜</div>
  <div class="lane"><div class="lane-t">4 · Action & record</div>
    <div class="node good">Auto-apply<small>all gates pass → rules.json</small></div>
    <div class="node warn">Human review<small>Approve / Reject in this dashboard</small></div>
    <div class="node">audit_log.jsonl<small>every decision with before / after metrics</small></div>
    <div class="node">Impact<small>alerts removed · analyst hours saved</small></div></div>
</div>
"""


def render_how(events) -> None:
    html(section("How it works", "An agent that owns rule tuning end to end",
                 "Six steps, with three safety gates between the model and production."))
    steps = [("01", "Detect", "Backtest every rule on week 1 and pick those whose false-positive rate is above "
              "the threshold. Rules already tuned are skipped."),
             ("02", "Diagnose", f"{MODEL} reads a profile of the false positives (top values per field plus a "
              "sample) and explains the root cause in plain English."),
             ("03", "Propose", "It returns exclusions as schema-checked JSON: groups of ANDed conditions. "
              "The label, week and timestamp fields are off limits."),
             ("04", "Backtest", "The proposal is replayed on week 1. Any hidden attack is a rejection, and "
              "Claude sees those events as feedback."),
             ("05", "Holdout", "It is replayed on week 2, which Claude never sees. On a failure, Claude only "
              f"learns which exclusion was too broad. Up to {MAX_ATTEMPTS} attempts."),
             ("06", "Apply", "Narrow and safe changes are auto-applied to rules.json; the rest wait for a human. "
              "Every decision is written to the audit log.")]
    html('<div class="pipeline">' + "".join(
        f'<div class="pstep"><div class="num">{n}</div><div class="ttl">{e(t)}</div><div class="txt">{e(x)}</div></div>'
        for n, t, x in steps) + "</div>")
    html('<div class="eyebrow">Architecture</div>')
    html(ARCH_HTML)
    html(section("Safety", "The three gates"))
    html(gates_html())
    html(section("Data", "What the agent sees and what it doesn't"))
    html(table(["Slice", "Shown to Claude", "Used for"],
               [["Week 1 · training", "False-positive profile and sample; missed attacks as feedback",
                 "Diagnosis and Gate 1"],
                ["Week 2 · holdout", "Never. Only which exclusion was too broad", "Gate 2"],
                ["Week 3 · test (evaluation only)", "Never", "Scoring every variant in eval/REPORT.md"],
                ["is_malicious label", "Never usable in exclusions", "Scoring only"]]))
    html(section("Run it", "Commands"))
    st.code("streamlit run app.py                       # this dashboard\n"
            "python -m agent.autonomous --demo-inject   # same agent run from the terminal\n"
            "python -m agent.impact                     # business impact of the live rules\n"
            "python -m eval.run_eval                    # full evaluation\n"
            "python -m pytest                           # unit and regression tests", language="bash")
