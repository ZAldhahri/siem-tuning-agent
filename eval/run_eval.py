"""Evaluation harness: held-out performance, robustness, ablations, regression checks.

One command:  python -m eval.run_eval
  1. regenerates the 3 unseen datasets (data/generate_unseen.py, fixed seeds)
  2. for each dataset, tunes the bare rules on week 1 with four variants:
       A  no agent (bare rules)
       B  heuristic: exclude the most frequent false-positive value, no LLM
       C  agent without holdout validation (week 1 backtest only)
       D  full agent (week 1 backtest + week 2 holdout gate)
     LLM variants run --runs times to show nondeterminism
  3. scores every result on week 3 (test, never touched by any variant) and week 2
  4. checks that previously accepted rules (eval/accepted_rules.json) still hide 0 attacks
  5. runs the pytest suite
  6. writes eval/results.json and eval/REPORT.md

Options: --runs N  --workers N  --datasets same shifted adversarial  --report-only
"""
import argparse
import json
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import anthropic

from agent import tuner
from agent.autonomous import decide
from agent.backtest import backtest, compare
from agent.engine import ROOT, evaluate, load_events, load_rules

EVAL_DIR = ROOT / "eval"
RESULTS_PATH = EVAL_DIR / "results.json"
REPORT_PATH = EVAL_DIR / "REPORT.md"
ACCEPTED_PATH = EVAL_DIR / "accepted_rules.json"
UNSEEN_DIR = ROOT / "data" / "unseen"
DATASETS = ["same", "shifted", "adversarial"]
VARIANTS = {"A": "No agent (bare rules)", "B": "Heuristic: top FP value, no LLM",
            "C": "Agent, no holdout validation", "D": "Full agent"}
PRICE_PER_MTOK = {"claude-sonnet-5-5": (2.00, 10.00)}   # (input, output) USD


# ---------------------------------------------------------------- helpers
def bare_rules() -> list[dict]:
    return [{**r, "exclusions": []} for r in load_rules()]


def load_dataset(name: str):
    return load_events(UNSEEN_DIR / f"{name}.csv")


def score(bare: dict, final: dict, df, week: int) -> dict:
    """Numbers for one rule on one week: before = bare rule, after = tuned rule."""
    v = compare(bare, final, df[df["week"] == week])
    return {"alerts_before": v["before"]["alerts"], "alerts_after": v["after"]["alerts"],
            "fp_before": v["fp_before"], "fp_removed": v["fp_removed"],
            "tp_before": v["tp_before"], "tp_kept": v["tp_kept"], "missed": v["missed"]}


def cost_usd(usage: dict) -> float | None:
    if not usage["models"]:
        return 0.0
    if any(m not in PRICE_PER_MTOK for m in usage["models"]):
        return None                                   # a fallback model ran: price unknown
    pin, pout = PRICE_PER_MTOK[usage["models"][0]]
    return round(usage["input_tokens"] / 1e6 * pin + usage["output_tokens"] / 1e6 * pout, 4)


def heuristic_rule(rule: dict, week1, max_exclusions=3, min_share=0.05, disable_share=0.95):
    """Variant B: greedily exclude the most frequent false-positive field value (one
    condition each, up to 3). Skips the rule's own fields, blank values, and any value
    that would bring the total excluded share of the rule's alerts to >= 95% (that would
    just switch the rule off). Uses analyst FP dispositions, no LLM, no attack labels."""
    alerts = evaluate(rule, week1)
    fps = alerts[~alerts["is_malicious"]]
    own = {c["field"] for c in rule["conditions"]}
    fields = [f for f in tuner.usable_fields(week1) if f not in own]
    exclusions, remaining_fp, remaining_alerts = [], fps, alerts
    floor = (1 - disable_share) * len(alerts)
    for _ in range(max_exclusions):
        best = None
        for f in fields:
            for v, n in remaining_fp[f].value_counts().items():
                if v == "" or (remaining_alerts[f] != v).sum() < floor:
                    continue
                if best is None or n > best[2]:
                    best = (f, v, int(n))
                break                                 # value_counts is sorted: top eligible
        if best is None or best[2] < min_share * len(fps):
            break
        f, v, _ = best
        v = v.item() if hasattr(v, "item") else v     # numpy scalar -> JSON-safe
        exclusions.append({"reason": f"most frequent FP value {f}={v}",
                           "conditions": [{"field": f, "op": "==", "value": v}]})
        remaining_fp = remaining_fp[remaining_fp[f] != v]
        remaining_alerts = remaining_alerts[remaining_alerts[f] != v]
    return {**rule, "exclusions": exclusions}


# ---------------------------------------------------------------- jobs
def deterministic_jobs(datasets) -> list[dict]:
    out = []
    for ds in datasets:
        df = load_dataset(ds)
        for rule in bare_rules():
            for variant in ("A", "B"):
                final = rule if variant == "A" else heuristic_rule(rule, df[df["week"] == 1])
                out.append({"dataset": ds, "variant": variant, "run": 1, "rule_id": rule["id"],
                            "exclusions": final["exclusions"], "success": True,
                            "attempts": 0, "rejected": 0, "decision": None,
                            "cost_usd": 0.0, "seconds": 0.0, "error": None,
                            "week2": score(rule, final, df, 2), "week3": score(rule, final, df, 3)})
    return out


def llm_job(ds: str, df, variant: str, run: int, rule: dict) -> dict:
    rec = {"dataset": ds, "variant": variant, "run": run, "rule_id": rule["id"], "error": None}
    try:
        res = tuner.tune_rule(rule, df, log=lambda *a: None, validate_holdout=variant == "D")
    except Exception as e:                            # API failure: rule stays unchanged
        rec.update(exclusions=[], success=False, attempts=0, rejected=0, decision="error",
                   cost_usd=0.0, seconds=0.0, error=f"{type(e).__name__}: {e}",
                   week2=score(rule, rule, df, 2), week3=score(rule, rule, df, 3))
        return rec
    final = res["proposed_rule"] or rule
    rec.update(
        exclusions=final["exclusions"], success=res["success"],
        attempts=len(res["attempts"]),
        rejected=sum(a["status"] == "rejected" for a in res["attempts"]),
        rejected_reasons=[a["reason"] for a in res["attempts"] if a["status"] == "rejected"],
        decision=decide(res)[0], usage=res["usage"], cost_usd=cost_usd(res["usage"]),
        seconds=res["seconds"],
        week2=score(rule, final, df, 2), week3=score(rule, final, df, 3))
    return rec


def run_llm_jobs(datasets, runs, workers) -> list[dict]:
    tuner._client = anthropic.Anthropic(max_retries=6)   # sturdier under parallel load
    frames = {ds: load_dataset(ds) for ds in datasets}
    specs = [(ds, v, run, rule) for ds in datasets for v in ("C", "D")
             for run in range(1, runs + 1) for rule in bare_rules()]
    out = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(llm_job, ds, frames[ds], v, run, rule)
                   for ds, v, run, rule in specs]
        for i, fut in enumerate(as_completed(futures), 1):
            r = fut.result()
            out.append(r)
            print(f"[{i}/{len(specs)}] {r['dataset']:<11} {r['variant']} run{r['run']} "
                  f"{r['rule_id']}: attempts={r['attempts']} rejected={r['rejected']} "
                  f"test missed={r['week3']['missed']} "
                  f"FP removed={r['week3']['fp_removed']}/{r['week3']['fp_before']}"
                  + (f"  ERROR {r['error']}" if r["error"] else ""), flush=True)
    return out


# ---------------------------------------------------------------- aggregation
def per_run(jobs) -> list[dict]:
    """Sum the three rules for each (dataset, variant, run)."""
    groups = {}
    for j in jobs:
        groups.setdefault((j["dataset"], j["variant"], j["run"]), []).append(j)
    rows = []
    for (ds, v, run), js in sorted(groups.items()):
        row = {"dataset": ds, "variant": v, "run": run}
        for wk in ("week2", "week3"):
            t = {k: sum(j[wk][k] for j in js) for k in js[0][wk]}
            t["noise_reduction_pct"] = round(100 * t["fp_removed"] / t["fp_before"], 1)
            row[wk] = t
        costs = [j["cost_usd"] for j in js]
        row.update(attempts=sum(j["attempts"] for j in js),
                   rejected=sum(j["rejected"] for j in js),
                   auto_applied=sum(j["decision"] == "auto-applied" for j in js),
                   rules_unchanged=sum(not j["exclusions"] for j in js),
                   errors=sum(bool(j["error"]) for j in js),
                   cost_usd=None if None in costs else round(sum(costs), 4),
                   seconds=round(sum(j["seconds"] for j in js), 1))
        rows.append(row)
    return rows


def summarize(runs) -> list[dict]:
    """Mean / std / min / max across runs for each (dataset, variant)."""
    groups = {}
    for r in runs:
        groups.setdefault((r["dataset"], r["variant"]), []).append(r)
    out = []
    for (ds, v), rs in sorted(groups.items()):
        def stat(get):
            vals = [get(r) for r in rs]
            if any(x is None for x in vals):
                return None
            return {"mean": round(statistics.mean(vals), 2),
                    "std": round(statistics.stdev(vals), 2) if len(vals) > 1 else 0.0,
                    "min": min(vals), "max": max(vals), "values": vals}
        out.append({
            "dataset": ds, "variant": v, "runs": len(rs),
            "test_noise_reduction_pct": stat(lambda r: r["week3"]["noise_reduction_pct"]),
            "test_fp_removed": stat(lambda r: r["week3"]["fp_removed"]),
            "test_fp_before": rs[0]["week3"]["fp_before"],
            "test_attacks_kept": stat(lambda r: r["week3"]["tp_kept"]),
            "test_attacks_total": rs[0]["week3"]["tp_before"],
            "test_missed": stat(lambda r: r["week3"]["missed"]),
            "val_noise_reduction_pct": stat(lambda r: r["week2"]["noise_reduction_pct"]),
            "val_missed": stat(lambda r: r["week2"]["missed"]),
            "attempts": stat(lambda r: r["attempts"]),
            "rejected": stat(lambda r: r["rejected"]),
            "auto_applied": stat(lambda r: r["auto_applied"]),
            "rules_unchanged": stat(lambda r: r["rules_unchanged"]),
            "errors": stat(lambda r: r["errors"]),
            "cost_usd": stat(lambda r: r["cost_usd"]),
            "seconds": stat(lambda r: r["seconds"]),
        })
    return out


# ---------------------------------------------------------------- regression
def regression_check(datasets) -> list[dict]:
    """Do previously accepted rules still hide 0 attacks on every dataset (all weeks)?"""
    accepted = json.loads(ACCEPTED_PATH.read_text())
    frames = {"original (dev)": load_events()} | {ds: load_dataset(ds) for ds in datasets}
    rows = []
    for name, df in frames.items():
        for rule in accepted:
            m, b = backtest(rule, df), backtest({**rule, "exclusions": []}, df)
            rows.append({"dataset": name, "rule_id": rule["id"],
                         "missed": len(m["missed_true_positives"]),
                         "attacks": b["true_positives"],
                         "fp_removed": b["false_positives"] - m["false_positives"],
                         "fp_before": b["false_positives"],
                         "passed": len(m["missed_true_positives"]) == 0})
    return rows


def run_pytest() -> dict:
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-rxX"], cwd=ROOT,
                       capture_output=True, text=True)
    lines = [ln for ln in p.stdout.strip().splitlines() if ln.strip()]
    return {"exit_code": p.returncode, "summary": lines[-1] if lines else "",
            "xfail": [ln for ln in lines if ln.startswith("XFAIL")]}


# ---------------------------------------------------------------- report
def fmt(s, pct=False, money=False):
    if s is None:
        return "n/a"
    unit = "%" if pct else ""
    if money:
        return f"${s['mean']:.3f}"
    if s["std"] == 0:
        return f"{s['mean']:g}{unit}"
    return f"{s['mean']:g}{unit} ± {s['std']:g}"


def runs_list(s):
    return "n/a" if s is None else ", ".join(f"{x:g}" for x in s["values"])


def write_report(results: dict) -> None:
    S = {(s["dataset"], s["variant"]): s for s in results["summary"]}
    ds_list = results["datasets"]
    L = [f"# Evaluation report", "",
         f"Generated {results['generated_at']} by `python -m eval.run_eval` "
         f"({results['runs']} runs per LLM variant, model `{tuner.MODEL}`). "
         "All numbers below are produced by the script from `eval/results.json`.", "",
         "## Method", "",
         "- **Datasets** (`data/generate_unseen.py`, fixed seeds, never used during development):",
         "  - `same`: same generating process as the dev data, new seed.",
         "  - `shifted`: new benign sources (service accounts, a pen-test vendor, Intune, "
         "a second VPN pool, a cloud proxy) and different volumes.",
         "  - `adversarial`: many more trap attacks that resemble benign noise, all arriving "
         "after the training week. Some differ from the noise only by `failed_count`; some "
         "are indistinguishable from it (a compromised service or admin account doing what "
         "it normally does).",
         "- **Weeks:** week 1 = training (the only data shown to the agent), week 2 = "
         "validation (the full agent's holdout gate), week 3 = **test** (touched by no "
         "variant). Week 2 is not an unbiased score for variant D because D selects on it, "
         "so the headline numbers are week 3.",
         "- **Every variant starts from bare rules** (no exclusions). Metrics are summed over "
         "the three rules. LLM variants are run several times; ± is the standard deviation "
         "across runs. A and B are deterministic and run once.",
         "- **Missed attacks** = malicious events that match a rule's conditions but are "
         "hidden by an exclusion. **Noise reduction** = share of false positives removed.",
         "- For C and D, a proposal that never passes its checks leaves the rule unchanged. "
         "D's accepted proposals are scored whether they would be auto-applied or queued "
         "for a human (the auto-applied count is reported separately). C's accepted proposals "
         "are scored as if applied; in the real autonomous mode the holdout check would have "
         "queued them for a human instead.",
         "- D's validation gate also rejects proposals that remove no validation-week false "
         "positives (overfitting gate). C has no access to the validation week, so it has neither gate.", ""]

    L += ["## Evaluation scope", "",
          "- Data is synthetic with perfect labels, which makes safety measurable. Real analyst "
          "dispositions are the next step.",
          "- The holdout gate catches attack patterns that appear in the validation week. Entirely "
          "new patterns need continuous re-validation, which is on the roadmap.", ""]

    L += ["## Headline: full agent (D) on the unseen test week", "",
          "| Dataset | Noise reduction | FP removed | Attacks kept | Missed attacks per run | "
          "Rejected proposals | Attempts | Auto-applied rules | Cost per run | Agent time per run |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for ds in ds_list:
        s = S[(ds, "D")]
        L.append(f"| {ds} | {fmt(s['test_noise_reduction_pct'], pct=True)} | "
                 f"{fmt(s['test_fp_removed'])} / {s['test_fp_before']} | "
                 f"{fmt(s['test_attacks_kept'])} / {s['test_attacks_total']} | "
                 f"{runs_list(s['test_missed'])} | {fmt(s['rejected'])} | {fmt(s['attempts'])} | "
                 f"{fmt(s['auto_applied'])} / 3 | {fmt(s['cost_usd'], money=True)} | "
                 f"{fmt(s['seconds'])} s |")

    L += ["", "## Ablations (test week)", "",
          "| Dataset | Variant | Noise reduction | Attacks kept | Missed attacks per run | "
          "Missed on validation week | Rules left unchanged |",
          "|---|---|---|---|---|---|---|"]
    for ds in ds_list:
        for v, label in VARIANTS.items():
            s = S[(ds, v)]
            L.append(f"| {ds} | {v}. {label} | {fmt(s['test_noise_reduction_pct'], pct=True)} | "
                     f"{fmt(s['test_attacks_kept'])} / {s['test_attacks_total']} | "
                     f"{runs_list(s['test_missed'])} | {runs_list(s['val_missed'])} | "
                     f"{fmt(s['rules_unchanged'])} / 3 |")

    # Computed comparisons, no hand-written claims.
    L += ["", "### Key comparisons (computed)", ""]
    for ds in ds_list:
        c, d, b = S[(ds, "C")], S[(ds, "D")], S[(ds, "B")]
        L.append(f"- **{ds}:** total missed test attacks across runs: "
                 f"B {sum(b['test_missed']['values'])}, "
                 f"C {sum(c['test_missed']['values'])}, D {sum(d['test_missed']['values'])}. "
                 f"Mean noise reduction: B {b['test_noise_reduction_pct']['mean']:g}%, "
                 f"C {c['test_noise_reduction_pct']['mean']:g}%, "
                 f"D {d['test_noise_reduction_pct']['mean']:g}%.")

    L += ["", "## Per-run detail (LLM variants)", "",
          "| Dataset | Variant | Run | Test noise reduction | Test missed | Validation missed | "
          "Attempts | Rejected | Cost | Agent time | Errors |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in results["runs_detail"]:
        if r["variant"] in ("C", "D"):
            cost = "n/a" if r["cost_usd"] is None else f"${r['cost_usd']:.3f}"
            L.append(f"| {r['dataset']} | {r['variant']} | {r['run']} | "
                     f"{r['week3']['noise_reduction_pct']:g}% | {r['week3']['missed']} | "
                     f"{r['week2']['missed']} | {r['attempts']} | {r['rejected']} | {cost} | "
                     f"{r['seconds']:g} s | {r['errors']} |")

    tot_cost = [r["cost_usd"] for r in results["runs_detail"] if r["variant"] in ("C", "D")]
    L += ["", f"Total LLM cost of this evaluation: "
          + ("n/a (a fallback model ran)" if None in tot_cost else f"${sum(tot_cost):.2f}")
          + f". Wall-clock time: {results['wall_seconds']:g} s with {results['workers']} "
          "parallel workers (agent time above is per run, summed over rules, and includes "
          "waiting under parallel load).", ""]

    L += ["## Regression check: previously accepted rules", "",
          "`eval/accepted_rules.json` holds the exclusions the agent proposed and passed on "
          "the development data. A dataset passes if they hide 0 attacks across all its weeks.",
          "", "| Dataset | Rule | Missed attacks | FP removed | Result |", "|---|---|---|---|---|"]
    for r in results["regression"]:
        L.append(f"| {r['dataset']} | {r['rule_id']} | {r['missed']} / {r['attacks']} | "
                 f"{r['fp_removed']} / {r['fp_before']} | {'pass' if r['passed'] else '**FAIL**'} |")
    pt = results["pytest"]
    L += ["", f"**pytest:** `{pt['summary']}` (exit code {pt['exit_code']})."]
    if pt["xfail"]:
        L += ["Expected failures (documented, strict):"] + [f"- `{x}`" for x in pt["xfail"]]
    errors = [j for j in results["jobs"] if j.get("error")]
    L += ["", "## Errors", ""]
    L += [f"- {j['dataset']} {j['variant']} run {j['run']} {j['rule_id']}: {j['error']}"
          for j in errors] or ["None."]
    REPORT_PATH.write_text("\n".join(L) + "\n")


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Run the SIEM tuning agent evaluation.")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--datasets", nargs="+", default=DATASETS, choices=DATASETS)
    ap.add_argument("--report-only", action="store_true",
                    help="rebuild REPORT.md from the existing results.json")
    args = ap.parse_args()

    if args.report_only:
        write_report(json.loads(RESULTS_PATH.read_text()))
        print(f"Wrote {REPORT_PATH}")
        return

    subprocess.run([sys.executable, str(ROOT / "data" / "generate_unseen.py")], check=True)
    t0 = time.monotonic()
    jobs = deterministic_jobs(args.datasets) + run_llm_jobs(args.datasets, args.runs, args.workers)
    runs = per_run(jobs)
    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model": tuner.MODEL, "runs": args.runs, "workers": args.workers,
        "datasets": args.datasets, "wall_seconds": round(time.monotonic() - t0, 1),
        "summary": summarize(runs), "runs_detail": runs,
        "regression": regression_check(args.datasets), "pytest": run_pytest(),
        "jobs": jobs,
    }
    RESULTS_PATH.write_text(json.dumps(results, indent=2, default=str))
    write_report(results)
    print(f"\nWrote {RESULTS_PATH} and {REPORT_PATH}")
    print("pytest:", results["pytest"]["summary"])


if __name__ == "__main__":
    main()
