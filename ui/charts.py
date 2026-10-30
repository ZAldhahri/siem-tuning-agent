"""Altair charts in the dashboard's dark theme.

Encoding is the same everywhere: blue = false positives (noise), orange = real attacks.
Marks follow the data-viz spec: thin bars with a 2px surface gap, 4px rounded data ends on
single bars, >=8px dots with a 2px surface ring, hairline grid, hover tooltips.
"""
import altair as alt
import pandas as pd

from agent.backtest import backtest
from ui.theme import ATTACK, FONT, HAIRLINE, NOISE, SURFACE, TEXT, TEXT_2, TEXT_3

KINDS = ["False positives", "Real attacks"]


def _style(chart):
    return (chart.configure(background="transparent", font=FONT, padding={"top": 6, "left": 4, "right": 4, "bottom": 4})
            .configure_view(stroke=None)
            .configure_axis(labelColor=TEXT_2, titleColor=TEXT_3, gridColor=HAIRLINE, domainColor=HAIRLINE,
                            tickColor=HAIRLINE, labelFontSize=11, titleFontSize=11, titleFontWeight=600,
                            labelFont=FONT, titleFont=FONT)
            .configure_legend(labelColor=TEXT_2, titleColor=TEXT_3, labelFontSize=11, symbolType="square",
                              orient="top", direction="horizontal", title=None, labelFont=FONT)
            .configure_header(labelColor=TEXT, labelFontSize=12, labelFontWeight=600, title=None, labelFont=FONT)
            .configure_text(font=FONT))


def _week_label(w: int) -> str:
    return {1: "Week 1 · training", 2: "Week 2 · holdout", 3: "Week 3 · test"}.get(w, f"Week {w}")


def before_after_frame(before_rules: list[dict], after_rules: list[dict], df) -> pd.DataFrame:
    """Alert counts per week, before vs after, split into false positives and real attacks."""
    rows = []
    for wk in sorted(df["week"].unique()):
        part = df[df["week"] == wk]
        for stage, rules in (("Before", before_rules), ("After", after_rules)):
            ms = [backtest(r, part) for r in rules]
            fp, tp = sum(m["false_positives"] for m in ms), sum(m["true_positives"] for m in ms)
            for kind, n, order in (("False positives", fp, 0), ("Real attacks", tp, 1)):
                rows.append({"week": _week_label(int(wk)), "stage": stage, "kind": kind, "count": n,
                             "order": order, "total": fp + tp})
    return pd.DataFrame(rows)


def before_after_chart(before_rules, after_rules, df, height=190, width=120):
    data = before_after_frame(before_rules, after_rules, df)
    base = alt.Chart(data)
    bars = base.mark_bar(stroke=SURFACE, strokeWidth=2).encode(
        x=alt.X("stage:N", sort=["Before", "After"], title=None, axis=alt.Axis(labelAngle=0, domain=False, ticks=False)),
        y=alt.Y("count:Q", stack="zero", title="Alerts", axis=alt.Axis(grid=True, tickCount=4, domain=False)),
        color=alt.Color("kind:N", scale=alt.Scale(domain=KINDS, range=[NOISE, ATTACK]), legend=alt.Legend()),
        order=alt.Order("order:Q"),
        tooltip=[alt.Tooltip("week:N", title="Week"), alt.Tooltip("stage:N", title="Rules"),
                 alt.Tooltip("kind:N", title="Type"), alt.Tooltip("count:Q", title="Alerts")])
    totals = base.transform_filter(alt.datum.order == 0).mark_text(dy=-7, color=TEXT, fontSize=11, fontWeight=600).encode(
        x=alt.X("stage:N", sort=["Before", "After"]), y=alt.Y("total:Q"), text=alt.Text("total:Q"))
    chart = alt.layer(bars, totals).properties(width=width, height=height).facet(
        column=alt.Column("week:N", header=alt.Header(labelOrient="top")), spacing=18)
    return _style(chart)


def ablation_chart(summary: list[dict], datasets: list[str], metric: str, title: str, color: str,
                   pct: bool = False, height=180, width=250):
    """One panel per dataset: the mean across runs as a bar, each individual run as a dot.
    metric is a key of the eval summary, e.g. 'test_missed' or 'test_noise_reduction_pct'."""
    labels = {"A": "A|Bare", "B": "B|Heuristic", "C": "C|No holdout", "D": "D|Full agent"}
    rows = []
    for s in summary:
        if s["dataset"] not in datasets or s[metric] is None:
            continue
        name, stat = labels[s["variant"]], s[metric]
        rows.append({"layer": "bar", "dataset": s["dataset"], "variant": name, "mean": stat["mean"],
                     "runs": ", ".join(f"{v:g}" for v in stat["values"])})
        rows += [{"layer": "dot", "dataset": s["dataset"], "variant": name, "value": v, "run": i}
                 for i, v in enumerate(stat["values"], 1)]
    base = alt.Chart(pd.DataFrame(rows))
    x = alt.X("variant:N", sort=list(labels.values()), title=None,
              axis=alt.Axis(labelAngle=0, labelExpr="split(datum.label, '|')", domain=False, ticks=False,
                            labelLineHeight=14))
    y_scale = alt.Scale(domain=[0, 100]) if pct else alt.Scale(domainMin=0, nice=True)
    bars = base.transform_filter(alt.datum.layer == "bar").mark_bar(
        color=color, cornerRadiusTopLeft=4, cornerRadiusTopRight=4, size=26).encode(
        x=x, y=alt.Y("mean:Q", title=title, scale=y_scale, axis=alt.Axis(tickCount=4, domain=False)),
        tooltip=[alt.Tooltip("dataset:N", title="Dataset"), alt.Tooltip("variant:N", title="Variant"),
                 alt.Tooltip("mean:Q", title="Mean across runs", format=".1f"),
                 alt.Tooltip("runs:N", title="Per run")])
    labels_ = base.transform_filter(alt.datum.layer == "bar").mark_text(
        dy=-14, color=TEXT, fontSize=11, fontWeight=600).encode(
        x=x, y="mean:Q", text=alt.Text("mean:Q", format=".0f" if pct else ".3~g"))
    dots = base.transform_filter(alt.datum.layer == "dot").mark_circle(
        size=70, color=TEXT, stroke=SURFACE, strokeWidth=2, opacity=1).encode(
        x=x, y="value:Q",
        tooltip=[alt.Tooltip("dataset:N", title="Dataset"), alt.Tooltip("variant:N", title="Variant"),
                 alt.Tooltip("run:Q", title="Run"), alt.Tooltip("value:Q", title="Value", format=".1f")])
    chart = alt.layer(bars, dots, labels_).properties(width=width, height=height).facet(
        column=alt.Column("dataset:N", sort=datasets, header=alt.Header(labelOrient="top")), spacing=26)
    return _style(chart)
