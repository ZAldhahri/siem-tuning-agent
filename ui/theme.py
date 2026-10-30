"""Design tokens and the global stylesheet for the dashboard.

Chart colors are the validated dark-surface pair from the data-viz reference palette:
blue = false positives (noise), orange = real attacks. Status colors (good / critical /
warning) are reserved for state and always ship with an icon and a label.
"""
import streamlit as st

BG = "#0a0e14"
SURFACE = "#111821"        # cards and chart surface
SURFACE_2 = "#161f2b"      # inset panels
BORDER = "#1f2a37"
HAIRLINE = "#1b2430"       # chart grid
TEXT = "#e6edf3"
TEXT_2 = "#9aa7b4"
TEXT_3 = "#7d8a98"
NOISE = "#3987e5"          # series: false positives  (also the UI accent)
ATTACK = "#d95926"         # series: real attacks
GOOD = "#0ca30c"
CRITICAL = "#d03b3b"
WARNING = "#fab219"
FONT = "Inter, system-ui, -apple-system, Segoe UI, sans-serif"
MONO = "JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace"

CSS = f"""
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root {{
  --bg:{BG}; --surface:{SURFACE}; --surface-2:{SURFACE_2}; --border:{BORDER};
  --text:{TEXT}; --text-2:{TEXT_2}; --text-3:{TEXT_3};
  --accent:{NOISE}; --noise:{NOISE}; --attack:{ATTACK};
  --good:{GOOD}; --critical:{CRITICAL}; --warning:{WARNING};
  --good-tint: rgba(12,163,12,.13); --critical-tint: rgba(208,59,59,.14);
  --warning-tint: rgba(250,178,25,.12); --accent-tint: rgba(57,135,229,.13);
  --mono:{MONO};
}}

/* ---------- page chrome ---------- */
[data-testid="stHeader"] {{ background: transparent; }}
.block-container, [data-testid="stMainBlockContainer"] {{ padding-top: 2.2rem; max-width: 1320px; }}
[data-testid="stSidebar"] {{ border-right: 1px solid var(--border); }}
[role="tablist"] {{ gap: .25rem; border-bottom: 1px solid var(--border); }}
[data-testid="stTab"] {{ padding: .55rem .95rem; border-radius: .5rem .5rem 0 0; }}
[data-testid="stTab"] p {{ font-weight: 600; font-size: .92rem; letter-spacing: .01em; }}
[data-testid="stTab"][aria-selected="true"] {{ background: var(--accent-tint); }}
[role="tablist"] .react-aria-SelectionIndicator {{ background: var(--accent); height: 2px; }}
.stButton button {{ font-weight: 600; letter-spacing: .01em; }}
[data-testid="stBaseButton-primary"] {{ box-shadow: 0 0 0 1px rgba(57,135,229,.35), 0 6px 20px -6px rgba(57,135,229,.55); }}
[data-testid="stCode"] pre, code {{ font-family: var(--mono) !important; }}

/* ---------- typography helpers ---------- */
.eyebrow {{ font-size: .7rem; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; color: var(--text-3); }}
.h-section {{ font-size: 1.15rem; font-weight: 700; color: var(--text); margin: .2rem 0 .1rem; }}
.lead {{ color: var(--text-2); font-size: .92rem; line-height: 1.5; margin: .15rem 0 .2rem; }}
.mono {{ font-family: var(--mono); }}
.muted {{ color: var(--text-3); }}
.sec {{ margin: 1.6rem 0 .6rem; }}

/* ---------- hero header ---------- */
.hero {{ display:flex; align-items:center; justify-content:space-between; gap:1.5rem; flex-wrap:wrap;
  padding: 1.25rem 1.4rem; border:1px solid var(--border); border-radius: 1rem;
  background: radial-gradient(1200px 200px at 0% 0%, rgba(57,135,229,.16), transparent 60%),
              linear-gradient(180deg, #0f1620, #0c1219); margin-bottom: 1rem; }}
.hero-left {{ display:flex; align-items:center; gap:1rem; }}
.logo {{ width:46px; height:46px; border-radius:12px; display:grid; place-items:center; font-size:1.5rem;
  background: linear-gradient(135deg, rgba(57,135,229,.35), rgba(57,135,229,.08)); border:1px solid rgba(57,135,229,.45); }}
.hero h1 {{ font-size: 1.55rem; font-weight: 800; margin:0; padding:0; letter-spacing:-.01em; color: var(--text); }}
.hero p {{ margin:.15rem 0 0; color: var(--text-2); font-size:.92rem; }}
.pills {{ display:flex; gap:.45rem; flex-wrap:wrap; }}
.pill {{ font-family: var(--mono); font-size:.72rem; color: var(--text-2); padding:.32rem .6rem; border-radius:999px;
  border:1px solid var(--border); background: var(--surface); white-space:nowrap; }}
.pill b {{ color: var(--text); font-weight:600; }}
.pill .live {{ display:inline-block; width:7px; height:7px; border-radius:50%; background: var(--good); margin-right:.4rem;
  box-shadow: 0 0 0 0 rgba(12,163,12,.6); animation: ping 2s infinite; vertical-align: 1px; }}

/* ---------- cards / KPIs ---------- */
.card {{ background: var(--surface); border:1px solid var(--border); border-radius: .9rem; padding: 1rem 1.1rem; }}
.kpis {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:.75rem; margin:.4rem 0 .2rem; }}
.kpi {{ background: var(--surface); border:1px solid var(--border); border-radius:.9rem; padding:.9rem 1rem; position:relative; overflow:hidden; }}
.kpi::before {{ content:""; position:absolute; left:0; top:0; bottom:0; width:3px; background: var(--kpi-accent, var(--accent)); }}
.kpi .lbl {{ font-size:.7rem; font-weight:700; letter-spacing:.12em; text-transform:uppercase; color: var(--text-3); }}
.kpi .val {{ font-size:1.9rem; font-weight:800; color: var(--text); line-height:1.15; margin-top:.25rem; font-variant-numeric: tabular-nums; }}
.kpi .sub {{ font-size:.8rem; color: var(--text-2); margin-top:.15rem; }}
.kpi.hero-kpi .val {{ font-size: 3.2rem; letter-spacing:-.02em; }}

/* ---------- badges & chips ---------- */
.badge {{ display:inline-flex; align-items:center; gap:.35rem; font-size:.72rem; font-weight:700; letter-spacing:.04em;
  padding:.22rem .55rem; border-radius:999px; border:1px solid var(--border); color: var(--text); background: var(--surface-2); white-space:nowrap; }}
.badge.good {{ background: var(--good-tint); border-color: rgba(12,163,12,.55); }}
.badge.bad {{ background: var(--critical-tint); border-color: rgba(208,59,59,.6); }}
.badge.warn {{ background: var(--warning-tint); border-color: rgba(250,178,25,.55); }}
.badge.info {{ background: var(--accent-tint); border-color: rgba(57,135,229,.55); }}
.badge .ic {{ font-size:.8rem; line-height:1; }}
.chip {{ font-family: var(--mono); font-size:.76rem; padding:.18rem .5rem; border-radius:.4rem; background: var(--surface-2);
  border:1px solid var(--border); color: var(--text); white-space:nowrap; }}
.excl {{ display:flex; flex-direction:column; gap:.35rem; margin:.55rem 0; }}
.group {{ display:flex; align-items:center; flex-wrap:wrap; gap:.3rem; }}
.op {{ font-family: var(--mono); font-size:.66rem; font-weight:700; color: var(--text-3); letter-spacing:.08em; }}
.or {{ font-family: var(--mono); font-size:.66rem; font-weight:700; color: var(--text-3); letter-spacing:.08em; margin:.05rem 0; }}

/* ---------- rule health cards ---------- */
.rule-card {{ background: var(--surface); border:1px solid var(--border); border-radius:.9rem; padding:1rem 1.05rem; height:100%; }}
.rule-top {{ display:flex; justify-content:space-between; align-items:center; gap:.5rem; }}
.rule-id {{ font-family: var(--mono); font-size:.75rem; color: var(--text-3); }}
.rule-name {{ font-size:1.02rem; font-weight:700; color: var(--text); margin:.35rem 0 .7rem; }}
.meter {{ height:8px; border-radius:999px; background: var(--surface-2); overflow:hidden; border:1px solid var(--border); }}
.meter > div {{ height:100%; border-radius:999px; background: var(--noise); }}
.meter-lbl {{ display:flex; justify-content:space-between; font-size:.75rem; color: var(--text-2); margin:.35rem 0 .7rem; }}
.stats {{ display:grid; grid-template-columns: repeat(3,1fr); gap:.5rem; }}
.stat .n {{ font-size:1.15rem; font-weight:700; color: var(--text); font-variant-numeric: tabular-nums; }}
.stat .t {{ font-size:.68rem; color: var(--text-3); text-transform:uppercase; letter-spacing:.1em; font-weight:700; }}
.swatch {{ display:inline-block; width:9px; height:9px; border-radius:2px; margin-right:.35rem; vertical-align:0; }}

/* ---------- pipeline tracker ---------- */
.tracker {{ display:flex; align-items:flex-start; gap:0; margin:.7rem 0 .4rem; overflow-x:auto; padding-bottom:.2rem; }}
.step {{ display:flex; flex-direction:column; align-items:center; min-width:96px; flex:1; text-align:center; }}
.step .dot {{ width:34px; height:34px; border-radius:50%; display:grid; place-items:center; font-weight:800; font-size:.9rem;
  border:2px solid var(--border); background: var(--surface-2); color: var(--text-3); transition: all .3s ease; }}
.step .lbl {{ font-size:.74rem; font-weight:700; margin-top:.4rem; color: var(--text-2); letter-spacing:.02em; }}
.step .sub {{ font-size:.68rem; color: var(--text-3); margin-top:.1rem; min-height:1em; }}
.step.done .dot {{ border-color: var(--good); background: var(--good-tint); color: var(--text); }}
.step.fail .dot {{ border-color: var(--critical); background: var(--critical-tint); color: var(--text); animation: pop .35s ease; }}
.step.warn .dot {{ border-color: var(--warning); background: var(--warning-tint); color: var(--text); }}
.step.active .dot {{ border-color: var(--accent); color: var(--text); background: var(--accent-tint); animation: pulse 1.2s ease-in-out infinite; }}
.step.active .lbl {{ color: var(--text); }}
.link {{ flex:1; height:2px; background: var(--border); margin-top:17px; min-width:16px; }}
.link.done {{ background: linear-gradient(90deg, var(--good), var(--good)); }}
.link.fail {{ background: var(--critical); }}

/* ---------- live rule panel ---------- */
.run-rule {{ background: var(--surface); border:1px solid var(--border); border-radius: 1rem; padding: 1rem 1.15rem; margin:.8rem 0 .5rem; }}
.run-head {{ display:flex; justify-content:space-between; align-items:center; gap:.75rem; flex-wrap:wrap; }}
.run-title {{ font-size:1.08rem; font-weight:800; color: var(--text); }}
.run-title .rule-id {{ margin-right:.5rem; }}
.run-meta {{ color: var(--text-2); font-size:.82rem; margin-top:.15rem; }}

/* ---------- attempt cards ---------- */
.attempt {{ position:relative; border:1px solid var(--border); border-left:4px solid var(--border); border-radius:.8rem;
  background: var(--surface-2); padding:.85rem 1rem; margin:.55rem 0; animation: fadein .35s ease; overflow:hidden; }}
.attempt.pending {{ border-left-color: var(--accent); }}
.attempt.pending .att-head .badge {{ animation: pulse 1.2s ease-in-out infinite; }}
.attempt.accepted {{ border-left-color: var(--good); box-shadow: inset 0 0 0 1px rgba(12,163,12,.25), 0 0 24px -12px rgba(12,163,12,.6); }}
.attempt.rejected {{ border-left-color: var(--critical); box-shadow: inset 0 0 0 1px rgba(208,59,59,.25), 0 0 26px -12px rgba(208,59,59,.7);
  background: linear-gradient(90deg, rgba(208,59,59,.08), var(--surface-2) 45%); }}
.attempt.nochange {{ border-left-color: var(--warning); }}
.att-head {{ display:flex; align-items:center; gap:.5rem; flex-wrap:wrap; }}
.att-n {{ font-family: var(--mono); font-size:.72rem; font-weight:700; color: var(--text-3); letter-spacing:.1em; }}
.att-cause {{ color: var(--text-2); font-size:.85rem; line-height:1.45; margin:.45rem 0 0; max-width: 980px; }}
.checks {{ display:flex; gap:.5rem; flex-wrap:wrap; margin-top:.35rem; }}
.check {{ font-size:.78rem; font-weight:600; padding:.3rem .6rem; border-radius:.45rem; border:1px solid var(--border); color: var(--text); background: var(--surface); }}
.check.pass {{ border-color: rgba(12,163,12,.5); background: var(--good-tint); }}
.check.fail {{ border-color: rgba(208,59,59,.6); background: var(--critical-tint); }}
.check.pend {{ color: var(--text-3); }}
.check.skip {{ color: var(--text-2); border-style: dashed; }}
.hidden-attack {{ margin-top:.65rem; padding:.6rem .75rem; border-radius:.55rem; border:1px solid rgba(208,59,59,.55);
  background: rgba(208,59,59,.1); font-size:.82rem; color: var(--text); }}
.hidden-attack .who {{ font-family: var(--mono); font-size:.78rem; }}
.hidden-attack .note {{ display:block; color: var(--text-3); font-size:.72rem; margin-top:.2rem; }}
.stamp {{ position:absolute; right:1rem; top:.7rem; transform: rotate(-8deg); font-family: var(--mono); font-weight:800; font-size:1rem;
  letter-spacing:.2em; color: #ff8b8b; border:2px solid rgba(208,59,59,.85); padding:.15rem .55rem; border-radius:.35rem; opacity:.9;
  animation: stamp .45s cubic-bezier(.2,1.6,.4,1); }}
.stamp.ok {{ color:#7fe07f; border-color: rgba(12,163,12,.85); }}

/* ---------- dramatic blocked banner ---------- */
.blocked-banner {{ display:flex; gap:1rem; align-items:center; padding:1rem 1.15rem; border-radius:.9rem; margin:.7rem 0;
  border:1px solid rgba(208,59,59,.75); color: var(--text);
  background: linear-gradient(100deg, rgba(208,59,59,.32), rgba(208,59,59,.08) 70%);
  animation: shake .55s cubic-bezier(.36,.07,.19,.97) both, glow 2.4s ease-in-out infinite; }}
.blocked-banner .bb-icon {{ font-size:2rem; line-height:1; }}
.blocked-banner .bb-title {{ font-weight:800; letter-spacing:.12em; font-size:.95rem; }}
.blocked-banner .bb-text {{ color: #f3d6d6; font-size:.86rem; margin-top:.15rem; line-height:1.45; }}
.safe-banner {{ display:flex; gap:.8rem; align-items:center; padding:.8rem 1rem; border-radius:.9rem; margin:.6rem 0;
  border:1px solid rgba(12,163,12,.6); background: linear-gradient(100deg, rgba(12,163,12,.18), rgba(12,163,12,.04) 70%); color: var(--text); font-size:.88rem; }}
.note-banner {{ padding:.7rem .95rem; border-radius:.75rem; border:1px solid var(--border); background: var(--surface); color: var(--text-2); font-size:.86rem; margin:.5rem 0; }}

/* ---------- tables ---------- */
.table-wrap {{ overflow-x:auto; border:1px solid var(--border); border-radius:.8rem; background: var(--surface); }}
.table-wrap.scroll {{ max-height: 460px; overflow-y:auto; }}
table.t {{ width:100%; border-collapse: collapse; font-size:.82rem; }}
table.t th {{ position:sticky; top:0; background: #0f151d; color: var(--text-3); font-size:.68rem; font-weight:700; letter-spacing:.1em;
  text-transform:uppercase; text-align:left; padding:.6rem .75rem; border-bottom:1px solid var(--border); white-space:nowrap; }}
table.t td {{ padding:.55rem .75rem; border-bottom:1px solid var(--hairline, {HAIRLINE}); color: var(--text); vertical-align: top; }}
table.t tr:last-child td {{ border-bottom: none; }}
table.t tr:hover td {{ background: rgba(255,255,255,.02); }}
table.t td.num {{ font-variant-numeric: tabular-nums; text-align:right; white-space:nowrap; }}
table.t td.bad {{ color: #ff9a9a; font-weight:700; }}
table.t td.good {{ color: #8fe28f; font-weight:700; }}
table.t tr.hl td {{ background: rgba(57,135,229,.07); }}
table.t td.mono {{ font-family: var(--mono); font-size:.76rem; }}
table.t td.nw {{ white-space: nowrap; }}
table.t.compact th, table.t.compact td {{ padding: .45rem .55rem; }}
table.t td.reason {{ min-width: 240px; color: var(--text-2); }}
.metrics-line {{ margin-top:.35rem; font-size:.75rem; color: var(--text-3); font-variant-numeric: tabular-nums; white-space: nowrap; }}

/* ---------- diffs ---------- */
.diff {{ font-family: var(--mono); font-size:.76rem; line-height:1.5; border:1px solid var(--border); border-radius:.75rem;
  background: #0c1118; padding:.6rem 0; overflow-x:auto; white-space:pre; }}
.diff div {{ padding:0 .9rem; }}
.diff .add {{ background: rgba(12,163,12,.14); color:#b8f0b8; }}
.diff .del {{ background: rgba(208,59,59,.16); color:#ffc2c2; }}
.diff .hunk {{ color: var(--accent); }}
.diff .ctx {{ color: var(--text-3); }}

/* ---------- how it works ---------- */
.pipeline {{ display:grid; grid-template-columns: repeat(3, 1fr); gap:.7rem; margin:.5rem 0 1rem; }}
@media (max-width: 900px) {{ .pipeline {{ grid-template-columns: 1fr; }} }}
.arch {{ display:grid; grid-template-columns: 1fr 28px 1fr 28px 1fr 28px 1fr; align-items:stretch; gap:0; margin:.5rem 0 .4rem; }}
.lane {{ background: var(--surface); border:1px solid var(--border); border-radius:.9rem; padding:.8rem; display:flex; flex-direction:column; gap:.45rem; }}
.lane-t {{ font-size:.66rem; font-weight:800; letter-spacing:.14em; text-transform:uppercase; color: var(--text-3); margin-bottom:.1rem; }}
.node {{ background: var(--surface-2); border:1px solid #2a3848; border-radius:.6rem; padding:.5rem .6rem; font-weight:700; font-size:.84rem; color: var(--text); }}
.node small {{ display:block; font-weight:500; font-size:.72rem; color: var(--text-2); margin-top:.1rem; }}
.node.accent {{ border-color: var(--accent); box-shadow: 0 0 22px -10px rgba(57,135,229,.8); }}
.node.gate {{ border-left:3px solid var(--accent); }}
.node.good {{ border-color: rgba(12,163,12,.7); }}
.node.warn {{ border-color: rgba(250,178,25,.7); }}
.node.bad {{ border-color: rgba(208,59,59,.75); border-style: dashed; background: rgba(208,59,59,.08); }}
.arrow {{ display:grid; place-items:center; color: var(--text-3); font-size:1.2rem; }}
@media (max-width: 1000px) {{ .arch {{ grid-template-columns: 1fr; }} .arrow {{ transform: rotate(90deg); padding:.2rem 0; }} }}
.pstep {{ background: var(--surface); border:1px solid var(--border); border-radius:.9rem; padding:.9rem; position:relative; }}
.pstep .num {{ font-family: var(--mono); font-size:.7rem; color: var(--accent); font-weight:700; letter-spacing:.12em; }}
.pstep .ttl {{ font-weight:800; color: var(--text); margin:.25rem 0 .3rem; }}
.pstep .txt {{ color: var(--text-2); font-size:.82rem; line-height:1.45; }}
.gates {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(230px,1fr)); gap:.7rem; }}
.gate {{ background: var(--surface); border:1px solid var(--border); border-radius:.9rem; padding:.9rem 1rem; border-top:3px solid var(--accent); }}
.gate .ttl {{ font-weight:800; margin:.2rem 0 .25rem; color: var(--text); }}
.gate .txt {{ color: var(--text-2); font-size:.83rem; line-height:1.45; }}
.legend-row {{ display:flex; gap:1rem; flex-wrap:wrap; font-size:.78rem; color: var(--text-2); }}

/* ---------- motion ---------- */
@keyframes pulse {{ 0%,100% {{ box-shadow: 0 0 0 0 rgba(57,135,229,.55); }} 50% {{ box-shadow: 0 0 0 7px rgba(57,135,229,0); }} }}
@keyframes ping {{ 0% {{ box-shadow: 0 0 0 0 rgba(12,163,12,.6); }} 80%,100% {{ box-shadow: 0 0 0 6px rgba(12,163,12,0); }} }}
@keyframes fadein {{ from {{ opacity:0; transform: translateY(6px); }} to {{ opacity:1; transform:none; }} }}
@keyframes pop {{ 0% {{ transform: scale(.6); }} 70% {{ transform: scale(1.15); }} 100% {{ transform: scale(1); }} }}
@keyframes stamp {{ 0% {{ transform: rotate(-8deg) scale(2.2); opacity:0; }} 100% {{ transform: rotate(-8deg) scale(1); opacity:.9; }} }}
@keyframes shake {{ 10%,90% {{ transform: translateX(-2px); }} 20%,80% {{ transform: translateX(4px); }}
  30%,50%,70% {{ transform: translateX(-7px); }} 40%,60% {{ transform: translateX(7px); }} }}
@keyframes glow {{ 0%,100% {{ box-shadow: 0 0 0 0 rgba(208,59,59,.0); }} 50% {{ box-shadow: 0 0 34px -4px rgba(208,59,59,.55); }} }}
@media (prefers-reduced-motion: reduce) {{ * {{ animation: none !important; transition: none !important; }} }}
"""


def inject_css() -> None:
    st.markdown(f"<style>{CSS}</style>", unsafe_allow_html=True)
