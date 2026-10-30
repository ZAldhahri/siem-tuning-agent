# SIEM Tuning Agent

An agent that tunes noisy SIEM detection rules end to end. It finds rules firing false
positives, diagnoses why with Claude, proposes exclusions, backtests them against labeled
history to prove no real attack is lost (retrying up to 3 times if one is), and applies
the change to `rules/rules.json` only after a human approves.

## Setup
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
python data/generate_events.py        # optional: regenerate data/events.csv
```

## Run each piece
```bash
python -m agent.engine                # alert count per rule
python -m agent.backtest              # TP / FP / FP rate / missed attacks per rule
python -m agent.tuner                 # tune the noisiest rule (calls Claude)
python -m agent.tuner R2              # tune a specific rule
streamlit run app.py                  # dashboard with Approve buttons
```
