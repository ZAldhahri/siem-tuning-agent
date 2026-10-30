"""Rule engine: evaluates a detection rule over the events DataFrame.

Rule format (rules/rules.json):
    {
      "id": "R1", "name": "...",
      "conditions": [{"field": ..., "op": ..., "value": ...}, ...],   # all must match (AND)
      "exclusions": [                                                  # any match suppresses (OR)
          {"reason": "why this is benign",
           "conditions": [{"field": ..., "op": ..., "value": ...}, ...]}  # AND within one exclusion
      ]
    }
"""
import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
EVENTS_PATH = ROOT / "data" / "events.csv"
RULES_PATH = ROOT / "rules" / "rules.json"

# Supported comparison operators. Each maps (column Series, value) -> boolean mask.
OPS = {
    "==": lambda s, v: s == v,
    "!=": lambda s, v: s != v,
    ">": lambda s, v: s > v,
    ">=": lambda s, v: s >= v,
    "<": lambda s, v: s < v,
    "<=": lambda s, v: s <= v,
    "in": lambda s, v: s.isin(v),
    "not_in": lambda s, v: ~s.isin(v),
    "startswith": lambda s, v: s.astype(str).str.startswith(v),
    "contains": lambda s, v: s.astype(str).str.contains(v, regex=False),
}


def load_events(path=EVENTS_PATH) -> pd.DataFrame:
    """Load events; blank text fields become "" so string comparisons work."""
    df = pd.read_csv(path)
    text_cols = df.select_dtypes(include=["object", "str"]).columns
    df[text_cols] = df[text_cols].fillna("")
    return df


def load_rules(path=RULES_PATH) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def save_rules(rules: list[dict], path=RULES_PATH) -> None:
    with open(path, "w") as f:
        json.dump(rules, f, indent=2)


def condition_mask(df: pd.DataFrame, cond: dict) -> pd.Series:
    """Boolean mask for a single {"field", "op", "value"} condition."""
    field, op, value = cond["field"], cond["op"], cond["value"]
    if field not in df.columns:
        raise ValueError(f"Unknown field: {field!r}")
    if op not in OPS:
        raise ValueError(f"Unknown operator: {op!r} (supported: {list(OPS)})")
    return OPS[op](df[field], value)


def all_of(df: pd.DataFrame, conditions: list[dict]) -> pd.Series:
    """AND together a list of conditions (an empty list matches everything)."""
    mask = pd.Series(True, index=df.index)
    for cond in conditions:
        mask &= condition_mask(df, cond)
    return mask


def exclusion_mask(df: pd.DataFrame, rule: dict) -> pd.Series:
    """True where ANY of the rule's exclusions applies."""
    mask = pd.Series(False, index=df.index)
    for exc in rule.get("exclusions", []):
        mask |= all_of(df, exc["conditions"])
    return mask


def evaluate(rule: dict, df: pd.DataFrame) -> pd.DataFrame:
    """Return the events that fire this rule: conditions match and no exclusion applies."""
    return df[all_of(df, rule["conditions"]) & ~exclusion_mask(df, rule)]


if __name__ == "__main__":
    events = load_events()
    for r in load_rules():
        alerts = evaluate(r, events)
        print(f"{r['id']} {r['name']:<28} {len(alerts):>4} alerts")
