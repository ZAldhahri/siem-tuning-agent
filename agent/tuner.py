"""Tuning agent: diagnose a noisy rule with Claude, propose exclusions, backtest, retry.

Flow for one rule:
  1. Profile the rule's false positives in WEEK 1 (training data) only.
  2. Ask Claude for a plain-English root cause and a JSON list of exclusions.
  3. Safety check 1: backtest on week 1. Any real attack suppressed = rejected.
  4. Safety check 2: validate on WEEK 2 (holdout, never shown to Claude).
     Any real attack suppressed = rejected.
  5. On rejection, feed the reason back and retry (up to MAX_ATTEMPTS).
  6. Return the final proposal, before/after metrics for both weeks, and every attempt.
     Nothing is written to disk; applying the change is a separate step (see app.py).
"""
import copy
import json
import sys
import time

import anthropic
from dotenv import load_dotenv

from agent.backtest import backtest, compare, exclusions_hiding, split_weeks, summary_line
from agent.engine import OPS, evaluate, load_events, load_rules

load_dotenv()  # reads ANTHROPIC_API_KEY from .env

MODEL = "claude-sonnet-5-5"
MAX_ATTEMPTS = 3
SAMPLE_ROWS = 25  # how many raw FP events to show Claude besides the field profile
HIDDEN_FIELDS = ["timestamp", "week", "is_malicious"]  # not shown to / usable by Claude

SYSTEM_PROMPT = """You are a senior detection engineer tuning SIEM rules.
You receive a detection rule and the false-positive alerts it produced.
Find the root cause of the noise and propose exclusions that suppress the benign activity.

Exclusion design rules:
- Each exclusion is a list of conditions that are ANDed; separate exclusions are ORed.
- Every exclusion MUST have at least 2 conditions. Combine identifying fields (e.g. user AND
  src_ip, or user AND parent_process) so a real attacker cannot easily hide inside them.
  Exclusions with a single condition are too broad and will be sent to a human for review.
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
    """The rule with the most week 1 false positives (most wasted analyst time)."""
    week1, _ = split_weeks(df)
    return max(rules, key=lambda r: backtest(r, week1)["false_positives"])


def usable_fields(df) -> list[str]:
    return [c for c in df.columns if c not in HIDDEN_FIELDS]


def profile_false_positives(fp_alerts, df) -> str:
    """Compact description of the FP alerts: top values per field plus a raw sample."""
    cols = usable_fields(df)
    lines = [f"{len(fp_alerts)} false-positive alerts. Top values per field (value: count):"]
    for col in cols:
        top = fp_alerts[col].value_counts().head(5)
        lines.append(f"- {col}: " + ", ".join(f"{v!r}: {n}" for v, n in top.items()))
    sample = fp_alerts[cols].sample(min(SAMPLE_ROWS, len(fp_alerts)), random_state=0)
    lines.append("\nRandom sample of false-positive events (CSV):\n" + sample.to_csv(index=False))
    return "\n".join(lines)


def ask_claude(messages: list[dict]):
    """One call to Claude. Returns (parsed proposal, raw response content, token usage)."""
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
    usage = {"model": response.model, "input_tokens": response.usage.input_tokens,
             "output_tokens": response.usage.output_tokens}
    return json.loads(text), response.content, usage


def check_fields(exclusions: list[dict], df) -> None:
    """Reject exclusions that reference unknown or forbidden fields."""
    allowed = set(usable_fields(df))
    for exc in exclusions:
        for cond in exc["conditions"]:
            if cond["field"] not in allowed:
                raise ValueError(f"field {cond['field']!r} is not allowed in exclusions")


def slim(view: dict) -> dict:
    """compare() output without the DataFrame, for storing in the attempt log."""
    return {k: v for k, v in view.items() if k != "missed_events"}


def tune_rule(rule: dict, df, log=print, first_proposal: dict | None = None,
              validate_holdout: bool = True) -> dict:
    """Run the diagnose -> propose -> week 1 check -> holdout check -> retry loop.

    first_proposal (demo only): use this instead of Claude's answer on attempt 1, to show
    the safety checks rejecting a risky change. Later attempts come from Claude as usual.
    validate_holdout=False (ablation only): accept after the week 1 check alone. The holdout
    result is still recorded, but it no longer gates the proposal.
    """
    started = time.monotonic()
    week1, holdout = split_weeks(df)
    log(f"Baseline week 1   {summary_line(backtest(rule, week1))}")
    log(f"Baseline holdout  {summary_line(backtest(rule, holdout))}")

    alerts = evaluate(rule, week1)
    fp_alerts = alerts[~alerts["is_malicious"]]
    messages = [{"role": "user", "content": (
        f"Rule under review:\n{json.dumps(rule, indent=2)}\n\n"
        f"Available fields: {usable_fields(df)}\n"
        f"Supported operators: {list(OPS)}\n\n"
        f"{profile_false_positives(fp_alerts, week1)}\n"
        "Explain the root cause and propose exclusions."
    )}]

    attempts, accepted = [], None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        injected = attempt == 1 and first_proposal is not None
        if injected:
            log("Attempt 1: DEMO - injecting a risky proposal instead of asking Claude")
            proposal = first_proposal
            raw_content = [{"type": "text", "text": json.dumps(first_proposal)}]
            usage = None
        else:
            log(f"Attempt {attempt}: asking {MODEL} for a diagnosis and exclusions...")
            proposal, raw_content, usage = ask_claude(messages)
        candidate = copy.deepcopy(rule)
        candidate["exclusions"] = rule.get("exclusions", []) + proposal["exclusions"]
        record = {"attempt": attempt, "proposal": proposal, "week1": None, "holdout": None,
                  "status": "rejected", "reason": "", "injected": injected, "usage": usage}

        if not proposal["exclusions"]:
            # Claude concluded no exclusion is safe: stop, the rule stays unchanged.
            record["reason"] = "Agent proposed no exclusions (no safe tuning found)"
            attempts.append(record)
            log(f"Attempt {attempt}: NO CHANGE - {record['reason']}")
            break

        try:
            check_fields(proposal["exclusions"], df)
            w1 = compare(rule, candidate, week1)
        except (ValueError, TypeError) as e:      # unknown field/op or bad value type
            record["reason"] = f"Invalid proposal: {e}"
            feedback = f"Your exclusions could not be evaluated: {e}. Fix them."
        else:
            record["week1"] = slim(w1)
            if w1["missed"]:
                # Safety check 1 failed: week 1 is training data, so show the events.
                record["reason"] = f"Week 1 backtest: would hide {w1['missed']} real attack(s)"
                feedback = (f"Backtest failed: your exclusions suppress {w1['missed']} confirmed "
                            "malicious events, which must still alert:\n"
                            f"{w1['missed_events'][usable_fields(df)].to_csv(index=False)}\n"
                            "Propose narrower exclusions that keep these alerting. "
                            "Return the complete exclusion list, not just the changes.")
            else:
                ho = compare(rule, candidate, holdout)
                record["holdout"] = slim(ho)
                if ho["missed"] and validate_holdout:
                    # Safety check 2 failed: say which exclusion was too broad, but do not
                    # reveal the holdout events, so the holdout stays unseen.
                    culprits = exclusions_hiding(candidate, ho["missed_events"])
                    record["reason"] = (f"Holdout (week 2): would hide {ho['missed']} real "
                                        "attack(s) the agent never saw")
                    feedback = (
                        f"Your exclusions passed the training backtest, but on unseen holdout "
                        f"data they suppressed {ho['missed']} confirmed attack(s). "
                        "These exclusions were responsible:\n"
                        + "\n".join(f"- #{c['index']} ({c['reason']}): "
                                     f"{json.dumps(c['conditions'])} hid {c['attacks_hidden']}"
                                     for c in culprits)
                        + "\nThey are too broad: an attacker can share these field values. "
                        "Make them narrower (combine more specific identifying fields) or drop "
                        "them. Return the complete exclusion list.")
                else:
                    record["status"] = "accepted"
                    record["reason"] = ("Passed both checks: 0 attacks hidden in week 1 "
                                        "and in the holdout" if validate_holdout else
                                        "Passed week 1 backtest (holdout validation disabled)")
                    accepted = (candidate, w1, ho)

        attempts.append(record)
        log(f"Attempt {attempt}: {record['status'].upper()} - {record['reason']}")
        if accepted:
            break
        messages += [{"role": "assistant", "content": raw_content},
                     {"role": "user", "content": feedback}]

    return {
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "success": accepted is not None,
        "explanation": attempts[-1]["proposal"]["root_cause"],
        "original_rule": rule,
        "proposed_rule": accepted[0] if accepted else None,
        "week1": slim(accepted[1]) if accepted else None,
        "holdout": slim(accepted[2]) if accepted else None,
        "attempts": attempts,
        "usage": {
            "input_tokens": sum(a["usage"]["input_tokens"] for a in attempts if a["usage"]),
            "output_tokens": sum(a["usage"]["output_tokens"] for a in attempts if a["usage"]),
            "models": sorted({a["usage"]["model"] for a in attempts if a["usage"]}),
        },
        "seconds": round(time.monotonic() - started, 1),
    }


def print_view(label: str, v: dict) -> None:
    print(f"  {label:<8} TP kept {v['tp_kept']}/{v['tp_before']}, "
          f"FP removed {v['fp_removed']}/{v['fp_before']}, "
          f"FP rate {v['before']['fp_rate']:.0%} -> {v['after']['fp_rate']:.0%}, "
          f"missed attacks {v['missed']}")


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
    print("\nSafety check log:")
    for a in result["attempts"]:
        print(f"  attempt {a['attempt']}: {a['status']:<8} {a['reason']}")
    if result["success"]:
        print("\nAccepted exclusions:")
        print(json.dumps(result["proposed_rule"]["exclusions"], indent=2))
        print("\nImpact:")
        print_view("week 1", result["week1"])
        print_view("holdout", result["holdout"])
    else:
        print(f"\nNo safe proposal after {MAX_ATTEMPTS} attempts; rule left unchanged.")
