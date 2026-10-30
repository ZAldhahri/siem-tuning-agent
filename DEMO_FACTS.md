# Demo facts

The source for each number is given in parentheses. Impact numbers come from real agent runs on
2026-10-30 and can shift slightly between runs, because Claude's exclusions vary a little.
Evaluation numbers come from `eval/REPORT.md`, generated 2026-10-30 13:14 UTC.

## 1. Click-by-click demo path

**Before you hit record**, complete the checklist in section 3.

| # | Action | What appears on screen | Time |
|---|---|---|---|
| 1 | Open `http://localhost:8501` | Dark dashboard with "AGENT ONLINE · MODEL claude-sonnet-5-5 · EVENTS 2,708 · 2 weeks · RULES 3 · LIVE EXCLUSIONS 0". The Live Agent tab is open. | 2–3 s to load |
| 2 | Point at the three rule cards | All three are marked **Noisy**. Brute force login: 304 alerts, 288 false positives, 16 attacks, 95% week 1 FP rate. Encoded PowerShell: 248 / 238 / 10, 96%. Impossible travel login: 156 / 148 / 8, 95%. | – |
| 3 | In the sidebar, tick **Demo: inject risky proposal**. Leave **Step-by-step animation** on. | A red "Demo injection armed" chip appears next to the run buttons. | instant |
| 4 | Click **Run autonomous tuning on all rules** | "Tuning R1, R2, R3." Each rule gets its own panel, and its tracker steps through Detect, Diagnose, Propose, Backtest, Holdout and Apply. The Diagnose step pulses while Claude thinks. | — |
| 5 | Brute force login (R1) finishes | One green **SAFE** card. It excludes `vuln_scanner` from `10.0.5.20` and `svc_backup` from internal IPs. "Removes 137 / 139 false positives in week 1 · 143 / 149 in the holdout." Badge: **Auto-applied**. | ≈ 8 s after click |
| 6 | Encoded PowerShell (R2) finishes | Green **SAFE** card. It excludes `svc_deploy` + `ccmexec.exe`, plus IT admins + their parent processes. "129 / 134 in week 1 · 101 / 104 in the holdout." **Auto-applied**. | ≈ 17 s |
| 7 | **The moment:** impossible travel (R3) | Attempt 1 carries the **Injected demo proposal** badge with `via_vpn == true` and a "single condition" warning. Week 1 backtest ✓ 0 attacks hidden. Holdout ✕ "would hide 1 real attack". A red **UNSAFE CHANGE BLOCKED** banner shakes in, and the card gets a **BLOCKED** stamp. | ≈ 20 s, then a ~2 s pause |
| 8 | Read the revealed attack aloud | "The real attack this would have silenced, week 2 (holdout): user4 · successful login from 87.146.159.75 on PC-25 · via VPN, impossible travel · Oct 10, 00:51". Below it: "The agent was only told which exclusion was too broad." This event is the same every time because the data is seeded. | – |
| 9 | Retry | Attempt 2 pulses, then turns green **SAFE**: VPN logins from the `10.8.` pool, with extra conditions. A green banner reads "After 1 blocked attempt(s), attempt 2 passed both safety checks". **Auto-applied**. | ≈ 30 s |
| 10 | Page settles into the final view | The rule cards now show **Already tuned**. Run summary: **3** auto-applied, **0** awaiting review, **1** unsafe proposal blocked, **650** alerts removed over 2 weeks, **34 / 34** attacks still caught. Each rule shows a before/after chart (blue = false positives, orange = real attacks). | ≈ 34 s after click |
| 11 | Open **Safety & Audit** | Gate 2 shows "1 caught so far". The KPI row reads 4 decisions logged, 3 auto-applied, 1 blocked. The blocked `via_vpn == true` card shows "Holdout: 69 → 6 alerts · 1 hidden". Below are the rule diffs and the audit log, newest first. | instant |
| 12 | Open **Impact** | 54.1 analyst hours saved per week, about 2,813 a year. 325 alerts removed per week, 96.4% noise reduction, 34 / 34 attacks still caught, 3 / 3 rules tuned. | instant |
| 13 | Drag **Assumed triage time per alert** from 10 to 20 | Hours saved roughly doubles, to about 108 per week. | instant |
| 14 | Open **Evaluation** | Full agent headline cards (same 96.5%, shifted 91.6%, adversarial 25.7%). Ablation charts, where adversarial shows B = 11 and C = 7 missed attacks against D = 0. Regression ("Do approved exclusions go stale when attackers change tactics?") has a blue takeaway above the table: 15 of 74 attacks slip past the stale rules on adversarial data, and re-tuning hides 0. Adversarial is marked amber **STALE: re-tune needed**, and the "After agent re-tunes" column is green 0 hidden on every row. The tests pill reads "running…" for about 7 s after the server starts, then the live count. | 1–2 s to render |
| 15 | Open **How it works** | Six step cards, the four-column architecture diagram, the three safety gates, and a table of what Claude sees and doesn't see. | instant |
| 16 | *(Optional)* Back on Live Agent, click Run again | "Skipped R1, R2, R3: already tuned." No API calls are made. | ≈ 2 s |

**Optional human-in-the-loop segment.** Reset, then click **Propose only (human approves
everything)**. Every rule ends as **Needs human review** with **✓ Approve & apply** and
**✕ Reject** buttons. Clicking them updates rules.json, the badges and the audit log
(human-approved / human-rejected).

## 2. Key real numbers

### Live demo data: 2 weeks, 2,708 events, 34 real attacks (Impact panel, last real run)

| Metric | Value |
|---|---|
| Analyst hours saved per week, at 10 min per alert | **54.1** (about 2,813 a year) |
| Alerts removed per week | **325** (week 1: 373 → 29, week 2: 335 → 29) |
| Noise reduction (share of false positives removed) | **96.4%** |
| Attacks still caught | **34 / 34** |
| Alerts per rule over both weeks | Brute force 304 → 24, PowerShell 248 → 18, Impossible travel 156 → 16 |
| False-positive rate on the holdout week, before → after | Brute force 95% → 43%, PowerShell 95% → 38%, Impossible travel 94% → 43% |

The false-positive rate stays around 40% after tuning because only about 8 hard-to-exclude
false positives remain per rule, so each one weighs heavily. The headline is alert volume,
down 92%, with zero attacks lost.

### Evaluation on 3 unseen datasets (`eval/REPORT.md`)

Each variant tunes on week 1 and is scored on week 3, which no variant ever touches. LLM
variants ran 3 times each.

| Dataset | Full agent noise reduction | Attacks kept | Missed per run | Cost per run |
|---|---|---|---|---|
| same distribution | 96.5% | 17 / 17 | 0, 0, 0 | $0.030 |
| shifted noise | 91.6% | 16 / 16 | 0, 0, 0 | $0.030 |
| adversarial traps | 25.7% ± 1.4 | 29 / 29 | 0, 0, 0 | $0.080 |

**Ablation on the adversarial dataset, missed test attacks:**

| Variant | Missed attacks | Noise reduction |
|---|---|---|
| B. Heuristic, no LLM | 11 / 29 | 96% |
| C. Agent without holdout validation | 7 / 29 in every run | 96% |
| D. Full agent | **0 / 29 in every run** | 25.7% |

**On same and shifted data, C and D tie.** Holdout validation only made a difference on
adversarial data. The heuristic missed 1 attack on same data.

**Variance:** the full agent's adversarial noise reduction was 27.3%, 25.0% and 24.7% across the
three runs. Missed attacks never varied between runs.

**Overfitting gate:** this rejects a proposal that is safe but removes no noise in the unseen
week. In this evaluation it fired 2 times, both on the adversarial impossible-travel rule.

**Regression:** the exclusions accepted on the development data hide 0 attacks on the
original, same and shifted datasets. On adversarial data they **fail**: R1 hides 6 / 33,
R2 6 / 24 and R3 3 / 17. This is by design. It contains compromised accounts that look
exactly like the benign sources.

**Total evaluation cost:** $0.65, with 42.3 s wall-clock time using 8 parallel workers.

**Tests:** 40 passed and 1 xfailed, both in the live dashboard pill and in the evaluation record.

### One-liners that are true

- "Removes 96% of false-positive alerts on the demo data and catches every one of the 34 attacks."
- "On adversarial data, the agent without the holdout gate missed 7 attacks in every run. The full agent missed none."
- "A full evaluation costs 65 cents. One agent run costs 3 to 8 cents."

### Claims to avoid

- "Zero false positives." About 8 remain per rule.
- "Holdout validation always helps." It made no difference on same and shifted data.
- "Works on real SIEM data." Everything is synthetic.
- "The agent never needs a human." Single-condition proposals and adversarial cases still go to human review.

## 3. Flaky, slow, or worth pre-running

### Checklist before recording

```bash
cd ~/siem-tuning-agent && source venv/bin/activate
python -m pytest -q                      # expect 40 passed, 1 xfailed
pkill -f "streamlit run" ; streamlit run app.py   # FRESH server (see below)
```

Then in the browser:

1. Click **Reset rules and audit log** in the sidebar. All cards must show **Noisy** and
   "LIVE EXCLUSIONS 0".
2. Do one full rehearsal run with the injection armed, then **Reset** again. This warms the
   API connection and confirms your key and network work.
3. Open the **Evaluation** tab once. After about 10 s, nudge a slider such as the triage
   time. Switching tabs alone doesn't rerun the page. The tests pill should change from
   "running…" to "40 passed, 1 xfailed". The suite runs in the background about 7 s after the server
   starts, and the pill only updates when the page reruns.

### Things that can bite you

| Risk | What happens | Avoid it by |
|---|---|---|
| **Rules already tuned** | A second run skips everything ("already tuned"). If R3 is already tuned, the injection does nothing and a note says so. | Reset before every take. |
| **Injection checkbox not ticked** | No blocked banner. All three rules pass on attempt 1. | Check for the red "Demo injection armed" chip before clicking Run. |
| **Stale server code** | Streamlit did not reload changes to the `ui/` modules during development, so the old layout kept showing. | Restart the server after any code change. Don't rely on auto-reload. |
| **Browser refresh mid-demo** | Live Agent results (attempt cards, run summary) are kept only for that browser session and disappear. Safety & Audit and Impact persist because they read files. | Don't refresh after the run. To show results again, reset and rerun. |
| **API latency** | Each Claude call takes about 5–10 s, so a run takes 30–45 s. Under load it can be slower. | Talk over the pulsing Diagnose step. The animation shows Claude is working. |
| **API error or no network** | An "Agent error" note appears, and the rule stays unchanged. The app keeps running. | Rehearse once before recording. Keep a pre-recorded take as backup. |
| **Claude's exclusions vary** | Wording, group count and exact conditions differ between runs. For example, R3's retry once added `failed_count == 0`. In every real run on this data, R1 and R2 passed on attempt 1 and R3 passed on attempt 2 after the block. That has not been tested hundreds of times. | Narrate the gates and the numbers, not the exact exclusion text. |
| **Fonts offline** | Inter and JetBrains Mono load from Google Fonts. Offline, system fonts are used. | Record online. The layout works either way. |
| **Narrow window** | The layout is tuned for a window about 1440 px wide. Narrower windows wrap cards and the architecture columns. | Record full-screen at 1440 px or wider, sidebar open. |
| **Animation toggle off** | The run skips its pauses, so only Claude's response time remains, and the block moment flashes by. | Keep **Step-by-step animation** on. |
| **Evaluation tab render** | It parses the results file and draws two faceted charts, which takes a second. | Click it once before recording. |
| **Terminal warnings** | Streamlit suggests installing watchdog. This is harmless. | Ignore it, or `pip install watchdog`. |

### Terminal fallback (no browser)

This runs the same flow from the terminal, including the blocked, retry and accepted
sequence, in about 30 s:

```bash
python -m agent.autonomous --demo-inject
python -m agent.impact
```
