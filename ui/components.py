"""HTML building blocks for the dashboard. Every dynamic value is HTML-escaped."""
import difflib
import json
from datetime import datetime
from html import escape

import streamlit as st

STEPS = [("detect", "Detect"), ("diagnose", "Diagnose"), ("propose", "Propose"),
         ("backtest", "Backtest"), ("holdout", "Holdout"), ("apply", "Apply")]
STEP_ICON = {"pending": "", "active": "…", "done": "✓", "fail": "✕", "warn": "!"}


def html(markup: str, where=None) -> None:
    """Render a compact HTML fragment (no markdown processing)."""
    (where or st).html("".join(line.strip() for line in markup.splitlines()))


def e(value) -> str:
    return escape(str(value), quote=True)


# ------------------------------------------------------------------ small pieces
def badge(label: str, kind: str = "", icon: str = "") -> str:
    ic = f'<span class="ic">{e(icon)}</span>' if icon else ""
    return f'<span class="badge {kind}">{ic}{e(label)}</span>'


DECISION_BADGE = {
    "auto-applied": ("Auto-applied", "good", "✓"),
    "human-approved": ("Approved by analyst", "good", "✓"),
    "queued for review": ("Needs human review", "warn", "⏸"),
    "rejected": ("Rejected", "bad", "✕"),
    "human-rejected": ("Rejected by analyst", "bad", "✕"),
    "already tuned": ("Already tuned", "good", "✓"),
    "noisy": ("Noisy", "warn", "!"),
    "ok": ("Healthy", "info", "●"),
}


def decision_badge(action: str) -> str:
    label, kind, icon = DECISION_BADGE.get(action, (action, "", ""))
    return badge(label, kind, icon)


def cond_text(c: dict) -> str:
    v = c["value"]
    if isinstance(v, bool):
        v = str(v).lower()
    elif isinstance(v, list):
        v = "[" + ", ".join(map(str, v)) + "]"
    return f'{c["field"]} {c["op"]} {v}'


def exclusions_html(exclusions: list[dict]) -> str:
    if not exclusions:
        return '<div class="excl"><span class="muted">No exclusions proposed</span></div>'
    groups = []
    for ex in exclusions:
        conds = '<span class="op">AND</span>'.join(
            f'<span class="chip">{e(cond_text(c))}</span>' for c in ex["conditions"])
        warn = badge("single condition", "warn", "!") if len(ex["conditions"]) < 2 else ""
        groups.append(f'<div class="group">{conds}{warn}</div>')
    return '<div class="excl">' + '<div class="or">OR</div>'.join(groups) + "</div>"


def kpis(items: list[dict]) -> str:
    """items: {label, value, sub?, accent?, hero?}"""
    cells = []
    for it in items:
        style = f' style="--kpi-accent:{it["accent"]}"' if it.get("accent") else ""
        cls = "kpi hero-kpi" if it.get("hero") else "kpi"
        sub = f'<div class="sub">{e(it["sub"])}</div>' if it.get("sub") else ""
        cells.append(f'<div class="{cls}"{style}><div class="lbl">{e(it["label"])}</div>'
                     f'<div class="val">{e(it["value"])}</div>{sub}</div>')
    return '<div class="kpis">' + "".join(cells) + "</div>"


def section(eyebrow: str, title: str, lead: str = "") -> str:
    lead_html = f'<div class="lead">{e(lead)}</div>' if lead else ""
    return (f'<div class="sec"><div class="eyebrow">{e(eyebrow)}</div>'
            f'<div class="h-section">{e(title)}</div>{lead_html}</div>')


def hero(title: str, subtitle: str, pills: list[tuple[str, str]], live: bool = True) -> str:
    pill_html = []
    for i, (k, v) in enumerate(pills):
        dot = '<span class="live"></span>' if live and i == 0 else ""
        pill_html.append(f'<span class="pill">{dot}{e(k)} <b>{e(v)}</b></span>')
    return (f'<div class="hero"><div class="hero-left"><div class="logo">🛡️</div><div>'
            f'<h1>{e(title)}</h1><p>{e(subtitle)}</p></div></div>'
            f'<div class="pills">{"".join(pill_html)}</div></div>')


# ------------------------------------------------------------------ rule health
def rule_card(rule: dict, m_all: dict, m_week1: dict, status: str) -> str:
    rate = m_week1["fp_rate"]
    return f"""
    <div class="rule-card">
      <div class="rule-top"><span class="rule-id">{e(rule["id"])} · {len(rule["exclusions"])} exclusion(s)</span>
        {decision_badge(status)}</div>
      <div class="rule-name">{e(rule["name"])}</div>
      <div class="meter"><div style="width:{rate * 100:.0f}%"></div></div>
      <div class="meter-lbl"><span><span class="swatch" style="background:var(--noise)"></span>Week 1 false-positive rate</span>
        <b>{rate:.0%}</b></div>
      <div class="stats">
        <div class="stat"><div class="n">{m_all["alerts"]}</div><div class="t">Alerts</div></div>
        <div class="stat"><div class="n">{m_all["false_positives"]}</div><div class="t">False pos.</div></div>
        <div class="stat"><div class="n">{m_all["true_positives"]}</div><div class="t">Attacks</div></div>
      </div>
    </div>"""


# ------------------------------------------------------------------ pipeline tracker
def tracker(states: dict, subs: dict | None = None) -> str:
    subs = subs or {}
    parts = []
    for i, (key, label) in enumerate(STEPS):
        st_ = states.get(key, "pending")
        icon = STEP_ICON[st_] or str(i + 1)
        parts.append(f'<div class="step {st_}"><div class="dot">{e(icon)}</div>'
                     f'<div class="lbl">{e(label)}</div><div class="sub">{e(subs.get(key, ""))}</div></div>')
        if i < len(STEPS) - 1:
            nxt = states.get(STEPS[i + 1][0], "pending")
            link = "done" if st_ == "done" and nxt != "pending" else ("fail" if nxt == "fail" else "")
            parts.append(f'<div class="link {link}"></div>')
    return '<div class="tracker">' + "".join(parts) + "</div>"


# ------------------------------------------------------------------ attempts
def describe_event(ev: dict) -> str:
    """One-line human description of a (hidden) attack event."""
    bits = []
    kind = ev.get("event_type", "")
    if kind == "login_failure_burst":
        bits.append(f'burst of {ev.get("failed_count")} failed logins')
    elif kind == "login_success":
        bits.append("successful login")
    elif kind == "process_exec":
        proc = ev.get("process") or "process"
        enc = " (encoded)" if ev.get("encoded") else ""
        parent = f' ← {ev["parent_process"]}' if ev.get("parent_process") else ""
        bits.append(f"{proc}{enc}{parent}")
    who = f'{ev.get("user", "?")} · {", ".join(bits)} from {ev.get("src_ip", "?")} on {ev.get("host", "?")}'
    flags = [f for f, on in (("via VPN", ev.get("via_vpn")), ("impossible travel", ev.get("impossible_travel"))) if on]
    if flags:
        who += " · " + ", ".join(flags)
    try:
        when = datetime.fromisoformat(str(ev.get("timestamp"))).strftime("%b %d, %H:%M")
        who += f" · {when}"
    except ValueError:
        pass
    return who


def attempt_state_from_record(rec: dict) -> dict:
    """Card state for a finished attempt (from the tuner's attempt record)."""
    reason = rec.get("reason", "")
    bt = None
    if rec.get("week1"):
        w1 = rec["week1"]
        bt = {"passed": w1["missed"] == 0, "missed": w1["missed"], "error": None,
              "hidden": w1["after"]["missed_true_positives"]}
    elif reason.startswith("Invalid"):
        bt = {"passed": False, "missed": 0, "error": reason, "hidden": []}
    ho = None
    if rec.get("holdout"):
        h = rec["holdout"]
        ho = {"passed": h["missed"] == 0, "missed": h["missed"], "gated": True,
              "hidden": h["after"]["missed_true_positives"]}
    status = rec["status"]
    if status != "accepted" and not rec["proposal"]["exclusions"]:
        status = "nochange"
    gen = None
    if ho is not None and ho["passed"]:
        h = rec["holdout"]
        gen = {"passed": not reason.startswith("overfit"), "fp_removed": h["fp_removed"],
               "fp_before": h["fp_before"]}
    return {"attempt": rec["attempt"], "injected": rec.get("injected", False),
            "proposal": rec["proposal"], "backtest": bt, "holdout": ho, "generalize": gen,
            "status": status, "reason": reason,
            "week1": rec.get("week1"), "holdout_view": rec.get("holdout")}


def attempt_card(s: dict) -> str:
    status = s.get("status", "pending")
    proposal = s.get("proposal")
    head = [f'<span class="att-n">ATTEMPT {s["attempt"]}</span>']
    if s.get("injected"):
        head.append(badge("Injected demo proposal", "bad", "⚠"))
    else:
        head.append(badge("Proposed by Claude", "info", "✦"))
    head.append({"pending": badge("Checking", "info", "…"), "accepted": badge("Accepted", "good", "✓"),
                 "rejected": badge("Rejected", "bad", "✕"),
                 "nochange": badge("No safe change found", "warn", "!")}[status])

    body = []
    if proposal is None:
        body.append('<div class="att-cause">Claude is reading the week 1 false positives and '
                    'looking for the root cause…</div>')
    else:
        body.append(f'<div class="att-cause">{e(proposal.get("root_cause", ""))}</div>')
        body.append(exclusions_html(proposal["exclusions"]))

    checks = []
    bt, ho = s.get("backtest"), s.get("holdout")
    if proposal is not None and proposal["exclusions"]:
        if bt is None:
            checks.append('<span class="check pend">… Week 1 backtest</span>')
        elif bt.get("error"):
            checks.append(f'<span class="check fail">✕ Invalid: {e(bt["error"])}</span>')
        elif bt["passed"]:
            checks.append('<span class="check pass">✓ Week 1 backtest · 0 attacks hidden</span>')
        else:
            checks.append(f'<span class="check fail">✕ Week 1 backtest · hides {bt["missed"]} real attack(s)</span>')
        if bt is not None and bt.get("passed"):
            if ho is None:
                checks.append('<span class="check pend">… Holdout (unseen week 2)</span>')
            elif ho["passed"]:
                checks.append('<span class="check pass">✓ Holdout (unseen week 2) · 0 attacks hidden</span>')
                gen = s.get("generalize")
                if gen is not None and not gen["passed"]:
                    checks.append(f'<span class="check fail">✕ Overfit · removes 0 / {gen["fp_before"]} '
                                  'false positives in the unseen week</span>')
            elif not ho.get("gated", True):
                checks.append(f'<span class="check skip">Holdout not enforced · hides {ho["missed"]}</span>')
            else:
                checks.append(f'<span class="check fail">✕ Holdout (unseen week 2) · would hide '
                              f'{ho["missed"]} real attack(s)</span>')
        elif bt is not None:
            checks.append('<span class="check pend">Holdout not run</span>')
    if checks:
        body.append('<div class="checks">' + "".join(checks) + "</div>")

    # Accepted: how much noise it removes.  Rejected: the real attack it would have hidden.
    if status == "accepted" and s.get("week1") and s.get("holdout_view"):
        w1, hv = s["week1"], s["holdout_view"]
        body.append(f'<div class="checks"><span class="check">Removes {w1["fp_removed"]} / {w1["fp_before"]} '
                    f'false positives in week 1</span><span class="check">{hv["fp_removed"]} / {hv["fp_before"]} '
                    f'in the holdout</span></div>')
    hidden = []
    if bt and not bt.get("passed") and bt.get("hidden"):
        hidden, where = bt["hidden"], "week 1 (training)"
    elif ho and not ho["passed"] and ho.get("hidden"):
        hidden, where = ho["hidden"], "week 2 (holdout)"
    if hidden and status != "accepted":
        rows = "".join(f'<div class="who">🚨 {e(describe_event(h))}</div>' for h in hidden[:3])
        more = f'<div class="who">… and {len(hidden) - 3} more</div>' if len(hidden) > 3 else ""
        note = ("Revealed here for you. The agent was only told which exclusion was too broad."
                if "holdout" in where else "Shown to the agent as feedback (training data).")
        body.append(f'<div class="hidden-attack"><b>The real attack this would have silenced, {e(where)}:</b>'
                    f'{rows}{more}<span class="note">{e(note)}</span></div>')

    stamp = ""
    gen = s.get("generalize")
    if status == "rejected" and gen is not None and not gen["passed"]:
        stamp = '<div class="stamp warn">OVERFIT</div>'
    elif status == "rejected":
        stamp = '<div class="stamp">BLOCKED</div>'
    elif status == "accepted":
        stamp = '<div class="stamp ok">SAFE</div>'
    return (f'<div class="attempt {status}">{stamp}<div class="att-head">{"".join(head)}</div>'
            + "".join(body) + "</div>")


def blocked_banner(proposal_text: str, missed: int, where: str) -> str:
    return (f'<div class="blocked-banner"><div class="bb-icon">🛡️</div><div>'
            f'<div class="bb-title">UNSAFE CHANGE BLOCKED</div>'
            f'<div class="bb-text">“{e(proposal_text)}” would have silenced {missed} real attack(s) in '
            f'{e(where)}. Nothing was applied. The agent was sent back with feedback and retried.</div>'
            f'</div></div>')


def safe_banner(text: str) -> str:
    return f'<div class="safe-banner"><span style="font-size:1.3rem">✅</span><div>{e(text)}</div></div>'


def note(text: str) -> str:
    return f'<div class="note-banner">{e(text)}</div>'


# ------------------------------------------------------------------ tables & diffs
def table(columns: list[str], rows: list[list], classes: list[list] | None = None,
          scroll: bool = False, row_classes: list[str] | None = None, compact: bool = False) -> str:
    """rows hold already-safe HTML strings or plain values (plain values are escaped)."""
    head = "".join(f"<th>{e(c)}</th>" for c in columns)
    body = []
    for i, row in enumerate(rows):
        cells = []
        for j, v in enumerate(row):
            cls = classes[i][j] if classes else ""
            text = v if isinstance(v, Safe) else e(v)
            cells.append(f'<td class="{cls}">{text}</td>')
        rc = f' class="{row_classes[i]}"' if row_classes and row_classes[i] else ""
        body.append(f"<tr{rc}>" + "".join(cells) + "</tr>")
    wrap = "table-wrap scroll" if scroll else "table-wrap"
    tcls = "t compact" if compact else "t"
    return f'<div class="{wrap}"><table class="{tcls}"><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>'


class Safe(str):
    """Marks a string as pre-escaped HTML for table()."""


def rule_lines(rule: dict) -> list[str]:
    """Rule as JSON with one condition per line, so diffs stay short and readable."""
    out = ["{"]
    keys = list(rule)
    for i, k in enumerate(keys):
        comma = "," if i < len(keys) - 1 else ""
        v = rule[k]
        if k == "conditions":
            out.append('  "conditions": [')
            out += [f"    {json.dumps(c)}" + ("," if j < len(v) - 1 else "") for j, c in enumerate(v)]
            out.append(f"  ]{comma}")
        elif k == "exclusions":
            if not v:
                out.append(f'  "exclusions": []{comma}')
                continue
            out.append('  "exclusions": [')
            for j, ex in enumerate(v):
                out.append(f'    {{"reason": {json.dumps(ex.get("reason", ""))},')
                out.append('     "conditions": [')
                out += [f"       {json.dumps(c)}" + ("," if m < len(ex["conditions"]) - 1 else "")
                        for m, c in enumerate(ex["conditions"])]
                out.append("     ]}" + ("," if j < len(v) - 1 else ""))
            out.append(f"  ]{comma}")
        else:
            out.append(f"  {json.dumps(k)}: {json.dumps(v)}{comma}")
    out.append("}")
    return out


def diff_html(old: dict, new: dict, old_label="current", new_label="proposed") -> str:
    a, b = rule_lines(old), rule_lines(new)
    lines = list(difflib.unified_diff(a, b, old_label, new_label, lineterm=""))
    if not lines:
        return '<div class="diff"><div class="ctx">  (no changes)</div></div>'
    out = []
    for ln in lines:
        cls = ("hunk" if ln.startswith("@@") else "add" if ln.startswith("+")
               else "del" if ln.startswith("-") else "ctx")
        out.append(f'<div class="{cls}">{e(ln) or " "}</div>')
    return '<div class="diff">' + "".join(out) + "</div>"
