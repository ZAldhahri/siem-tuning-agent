# SIEM Tuning Agent

An agent that tunes noisy SIEM detection rules end to end. It finds rules firing false
positives, diagnoses why with Claude, and proposes exclusions. Each proposal is then
checked twice: a backtest on week 1 (training) and a validation on week 2 (a holdout the
agent never sees). The agent retries up to 3 times if any real attack would be hidden.

In autonomous mode, a change is applied automatically only if it hides 0 attacks in week 1,
0 attacks in the holdout, and every exclusion has at least 2 ANDed conditions. Everything
else waits for a human to approve or reject it. Every decision goes to `data/audit_log.jsonl`.

## Setup
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
python data/generate_events.py        # optional: regenerate data/events.csv (fixed seed)
```

## Run each piece
```bash
python -m agent.engine                # alert count per rule
python -m agent.backtest              # TP / FP / FP rate / missed attacks, all data and per week
python -m agent.tuner                 # tune the noisiest rule with holdout validation (calls Claude)
python -m agent.tuner R2              # tune a specific rule
python -m agent.autonomous            # tune all rules above 30% week 1 FP rate, auto-apply safe ones
python -m agent.autonomous --threshold 0.5 --propose-only   # never auto-apply
streamlit run app.py                  # dashboard: autonomous run, safety checks, approvals, audit log
```

`agent.autonomous` without `--propose-only` writes to `rules/rules.json`. To start over, use
"Reset rules and audit log" in the dashboard sidebar.
