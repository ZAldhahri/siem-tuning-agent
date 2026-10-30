"""Tuning agent: diagnose a noisy rule with Claude, propose exclusions, backtest, retry.

Flow for one rule:
  1. Backtest the current rule to get baseline metrics and its false-positive alerts.
  2. Ask Claude for a plain-English root cause and a JSON list of exclusions.
  3. Backtest the proposal. If any true positive would be suppressed, send those
     events back to Claude and ask for a narrower fix (up to MAX_ATTEMPTS).
  4. Return the final proposal with before/after metrics. Nothing is written to disk;
     applying the change is a separate human-approved step (see app.py).
"""
import copy
import json
import sys

import anthropic
from dotenv import load_dotenv

from agent.backtest import backtest, summary_line
from agent.engine import OPS, evaluate, load_events, load_rules

load_dotenv()  # reads ANTHROPIC_API_KEY from .env

MODEL = "claude-sonnet-5-5"
MAX_ATTEMPTS = 3
SAMPLE_ROWS = 25  # how many raw FP events to show Claude besides the field profile

SYSTEM_PROMPT = """You are a senior detection engineer tuning SIEM rules.
You receive a detection rule and the false-positive alerts it produced.
Find the root cause of the noise and propose exclusions that suppress the benign activity.

Exclusion design rules:
- Each exclusion is a list of conditions that are ANDed; separate exclusions are ORed.
- Keep exclusions as narrow as possible: combine identifying fields (e.g. user AND src_ip,
  or process AND parent_process) so a real attacker cannot easily hide inside them.
- Never weaken the rule's core logic and never exclude on the label or on the rule's own fields alone.
- The root cause should be 2-4 sentences a SOC manager can read, naming the benign sources."""

# Structured output schema: guarantees the reply parses into this shape.
CONDITION_SCHEMA = {
    "type": "object",
    "properties": {
        "field": {"type": "string"},
        "op": {"type": "string", "enum": list(OPS)},
        "value": {"anyOf": [
            {"type": "string"}, {"type": "number"}, {"type": "boolean"},
            {"type": "array", "items": {"type": "string"}},
        ]},
    },
    "required": ["field", "op", "value"],
    "additionalProperties": False,
}
PROPOSAL_SCHEMA = {
    "type": "object",
    "properties": {
        "root_cause": {"type": "string"},
        "exclusions": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "reason": {"type": "string"},
                "conditions": {"type": "array", "items": CONDITION_SCHEMA},
            },
            "required": ["reason", "conditions"],
            "additionalProperties": False,
        }},
    },
    "required": ["root_cause", "exclusions"],
    "additionalProperties": False,
}

_client = None


def client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic()
    return _client


def pick_noisiest(rules: list[dict], df) -> dict:
    """The rule with the most false positives (most wasted analyst time)."""
    return max(rules, key=lambda r: backtest(r, df)["false_positives"])


def profile_false_positives(fp_alerts, df) -> str:
    """Compact description of the FP alerts: top values per field plus a raw sample."""
    cols = [c for c in df.columns if c not in ("timestamp", "is_malicious")]
    lines = [f"{len(fp_alerts)} false-positive alerts. Top values per field (value: count):"]
    for col in cols:
        top = fp_alerts[col].value_counts().head(5)
        lines.append(f"- {col}: " + ", ".join(f"{v!r}: {n}" for v, n in top.items()))
    sample = fp_alerts[cols].sample(min(SAMPLE_ROWS, len(fp_alerts)), random_state=0)
    lines.append("\nRandom sample of false-positive events (CSV):\n" + sample.to_csv(index=False))
    return "\n".join(lines)


def ask_claude(messages: list[dict]):
    """One call to Claude. Returns (parsed proposal dict, raw response content)."""
    response = client().beta.messages.create(
        model=MODEL,
        max_tokens=16000,
        system=SYSTEM_PROMPT,
        messages=messages,
        output_config={"effort": "medium",
                       "format": {"type": "json_schema", "schema": PROPOSAL_SCHEMA}},
        # If a safety classifier declines, re-run on Anthropic's recommended fallback model.
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
    )
    if response.stop_reason == "refusal":
        raise RuntimeError(f"Claude declined the request: {response.stop_details}")
    if response.stop_reason == "max_tokens":
        raise RuntimeError("Claude's reply was cut off (max_tokens).")
    text = next(b.text for b in response.content if b.type == "text")
    return json.loads(text), response.content


def public_metrics(m: dict) -> dict:
    """Backtest metrics with the missed-TP DataFrame turned into plain records."""
    out = {k: v for k, v in m.items() if k != "missed_true_positives"}
    out["missed_true_positives"] = m["missed_true_positives"].to_dict("records")
    return out


def tune_rule(rule: dict, df, log=print) -> dict:
    """Run the diagnose -> propose -> backtest -> retry loop for one rule."""
    before = backtest(rule, df)
    log(f"Baseline   {summary_line(before)}")
    alerts = evaluate(rule, df)
    fp_alerts = alerts[~alerts["is_malicious"]]

    messages = [{"role": "user", "content": (
        f"Rule under review:\n{json.dumps(rule, indent=2)}\n\n"
        f"Available fields: {list(df.columns.drop('is_malicious'))}\n"
        f"Supported operators: {list(OPS)}\n\n"
        f"{profile_false_positives(fp_alerts, df)}\n"
        "Explain the root cause and propose exclusions."
    )}]

    attempts = []
    for attempt in range(1, MAX_ATTEMPTS + 1):
        log(f"Attempt {attempt}: asking {MODEL} for a diagnosis and exclusions...")
        proposal, raw_content = ask_claude(messages)
        candidate = copy.deepcopy(rule)
        candidate["exclusions"] = rule.get("exclusions", []) + proposal["exclusions"]

        try:
            after = backtest(candidate, df)
            error = None
        except (ValueError, TypeError) as e:          # unknown field/op or bad value type
            after, error = None, str(e)

        lost = after["missed_true_positives"] if after else None
        ok = error is None and len(lost) == 0
        attempts.append({"attempt": attempt, "proposal": proposal, "error": error,
                         "metrics": public_metrics(after) if after else None, "ok": ok})
        log(f"Attempt {attempt}: " + (f"invalid proposal ({error})" if error else summary_line(after)))
        if ok:
            break

        # Feed the failure back so Claude can narrow its exclusions.
        if error:
            feedback = f"Your exclusions could not be evaluated: {error}. Fix them."
        else:
            feedback = (f"Backtest failed: your exclusions suppress {len(lost)} confirmed "
                        "malicious events, which must still alert:\n"
                        f"{lost.drop(columns='is_malicious').to_csv(index=False)}\n"
                        "Propose narrower exclusions that keep these alerting. "
                        "Return the complete exclusion list, not just the changes.")
        messages += [{"role": "assistant", "content": raw_content},
                     {"role": "user", "content": feedback}]

    final = attempts[-1]
    return {
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "success": final["ok"],
        "explanation": final["proposal"]["root_cause"],
        "original_rule": rule,
        "proposed_rule": candidate if final["ok"] else None,
        "before": public_metrics(before),
        "after": final["metrics"],
        "attempts": attempts,
    }


if __name__ == "__main__":
    # Usage: python -m agent.tuner [RULE_ID]   (default: the noisiest rule)
    events = load_events()
    rules = load_rules()
    if len(sys.argv) > 1:
        target = next(r for r in rules if r["id"] == sys.argv[1])
    else:
        target = pick_noisiest(rules, events)
        print(f"Noisiest rule: {target['id']} ({target['name']})")

    result = tune_rule(target, events)
    print("\nRoot cause:\n " + result["explanation"])
    if result["success"]:
        print("\nProposed exclusions:")
        print(json.dumps(result["proposed_rule"]["exclusions"], indent=2))
        b, a = result["before"], result["after"]
        print(f"\nAlerts {b['alerts']} -> {a['alerts']}, FP {b['false_positives']} -> "
              f"{a['false_positives']}, TP {b['true_positives']} -> {a['true_positives']}")
    else:
        print(f"\nNo safe proposal after {MAX_ATTEMPTS} attempts; rule left unchanged.")
