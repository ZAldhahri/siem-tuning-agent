# Evaluation report

Generated 2026-10-30T15:31:04+00:00 by `python -m eval.run_eval` (3 runs per LLM variant, model `claude-sonnet-5-5`). All numbers below are produced by the script from `eval/results.json`.

## Method

- **Datasets** (`data/generate_unseen.py`, fixed seeds, never used during development):
  - `same`: same generating process as the dev data, new seed.
  - `shifted`: new benign sources (service accounts, a pen-test vendor, Intune, a second VPN pool, a cloud proxy) and different volumes.
  - `adversarial`: many more trap attacks that resemble benign noise, all arriving after the training week. Some differ from the noise only by `failed_count`; some are indistinguishable from it (a compromised service or admin account doing what it normally does).
- **Weeks:** week 1 = training (the only data shown to the agent), week 2 = validation (the full agent's holdout gate), week 3 = **test** (touched by no variant). Week 2 is not an unbiased score for variant D because D selects on it, so the headline numbers are week 3.
- **Every variant starts from bare rules** (no exclusions). Metrics are summed over the three rules. LLM variants are run several times; ± is the standard deviation across runs. A and B are deterministic and run once.
- **Missed attacks** = malicious events that match a rule's conditions but are hidden by an exclusion. **Noise reduction** = share of false positives removed.
- For C and D, a proposal that never passes its checks leaves the rule unchanged. D's accepted proposals are scored whether they would be auto-applied or queued for a human (the auto-applied count is reported separately). C's accepted proposals are scored as if applied; in the real autonomous mode the holdout check would have queued them for a human instead.
- D's validation gate also rejects proposals that remove no validation-week false positives (overfitting gate). C has no access to the validation week, so it has neither gate.

## Evaluation scope

- Data is synthetic with perfect labels, which makes safety measurable. Real analyst dispositions are the next step.
- The holdout gate catches attack patterns that appear in the validation week. Entirely new patterns need continuous re-validation, which is on the roadmap.

## Headline: full agent (D) on the unseen test week

| Dataset | Noise reduction | FP removed | Attacks kept | Missed attacks per run | Rejected proposals | Attempts | Auto-applied rules | Cost per run | Agent time per run |
|---|---|---|---|---|---|---|---|---|---|
| same | 96.5% | 307 / 318 | 17 / 17 | 0, 0, 0 | 0 | 3 | 3 / 3 | $0.030 | 11.2 ± 0.1 s |
| shifted | 91.6% | 395 / 431 | 16 / 16 | 0, 0, 0 | 0 | 3 | 3 / 3 | $0.030 | 13.43 ± 0.64 s |
| adversarial | 25.67% ± 1.42 | 89.33 ± 4.93 / 348 | 29 / 29 | 0, 0, 0 | 6 ± 1 | 7.67 ± 0.58 | 1.67 ± 0.58 / 3 | $0.080 | 32.27 ± 3.78 s |

## Ablations (test week)

| Dataset | Variant | Noise reduction | Attacks kept | Missed attacks per run | Missed on validation week | Rules left unchanged |
|---|---|---|---|---|---|---|
| same | A. No agent (bare rules) | 0% | 17 / 17 | 0 | 0 | 3 / 3 |
| same | B. Heuristic: top FP value, no LLM | 96.5% | 16 / 17 | 1 | 2 | 0 / 3 |
| same | C. Agent, no holdout validation | 96.5% | 17 / 17 | 0, 0, 0 | 0, 0, 0 | 0 / 3 |
| same | D. Full agent | 96.5% | 17 / 17 | 0, 0, 0 | 0, 0, 0 | 0 / 3 |
| shifted | A. No agent (bare rules) | 0% | 16 / 16 | 0 | 0 | 3 / 3 |
| shifted | B. Heuristic: top FP value, no LLM | 83.3% | 16 / 16 | 0 | 2 | 0 / 3 |
| shifted | C. Agent, no holdout validation | 91.6% | 16 / 16 | 0, 0, 0 | 0, 0, 0 | 0 / 3 |
| shifted | D. Full agent | 91.6% | 16 / 16 | 0, 0, 0 | 0, 0, 0 | 0 / 3 |
| adversarial | A. No agent (bare rules) | 0% | 29 / 29 | 0 | 0 | 3 / 3 |
| adversarial | B. Heuristic: top FP value, no LLM | 96% | 18 / 29 | 11 | 10 | 0 / 3 |
| adversarial | C. Agent, no holdout validation | 96% | 22 / 29 | 7, 7, 7 | 8, 8, 8 | 0 / 3 |
| adversarial | D. Full agent | 25.67% ± 1.42 | 29 / 29 | 0, 0, 0 | 0, 0, 0 | 1.33 ± 0.58 / 3 |

### Key comparisons (computed)

- **same:** total missed test attacks across runs: B 1, C 0, D 0. Mean noise reduction: B 96.5%, C 96.5%, D 96.5%.
- **shifted:** total missed test attacks across runs: B 0, C 0, D 0. Mean noise reduction: B 83.3%, C 91.6%, D 91.6%.
- **adversarial:** total missed test attacks across runs: B 11, C 21, D 0. Mean noise reduction: B 96%, C 96%, D 25.67%.

## Per-run detail (LLM variants)

| Dataset | Variant | Run | Test noise reduction | Test missed | Validation missed | Attempts | Rejected | Cost | Agent time | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| adversarial | C | 1 | 96% | 7 | 8 | 3 | 0 | $0.026 | 17.9 s | 0 |
| adversarial | C | 2 | 96% | 7 | 8 | 3 | 0 | $0.026 | 12.6 s | 0 |
| adversarial | C | 3 | 96% | 7 | 8 | 3 | 0 | $0.027 | 11.5 s | 0 |
| adversarial | D | 1 | 27.3% | 0 | 0 | 8 | 6 | $0.086 | 35.2 s | 0 |
| adversarial | D | 2 | 25% | 0 | 0 | 7 | 5 | $0.068 | 28 s | 0 |
| adversarial | D | 3 | 24.7% | 0 | 0 | 8 | 7 | $0.083 | 33.6 s | 0 |
| same | C | 1 | 96.5% | 0 | 0 | 3 | 0 | $0.026 | 13.3 s | 0 |
| same | C | 2 | 96.5% | 0 | 0 | 3 | 0 | $0.025 | 14.1 s | 0 |
| same | C | 3 | 96.5% | 0 | 0 | 3 | 0 | $0.026 | 13.2 s | 0 |
| same | D | 1 | 96.5% | 0 | 0 | 3 | 0 | $0.026 | 11.2 s | 0 |
| same | D | 2 | 96.5% | 0 | 0 | 3 | 0 | $0.026 | 11.1 s | 0 |
| same | D | 3 | 96.5% | 0 | 0 | 3 | 0 | $0.025 | 11.3 s | 0 |
| shifted | C | 1 | 91.6% | 0 | 0 | 3 | 0 | $0.030 | 13.1 s | 0 |
| shifted | C | 2 | 91.6% | 0 | 0 | 3 | 0 | $0.029 | 12.7 s | 0 |
| shifted | C | 3 | 91.6% | 0 | 0 | 3 | 0 | $0.031 | 13.9 s | 0 |
| shifted | D | 1 | 91.6% | 0 | 0 | 3 | 0 | $0.030 | 12.7 s | 0 |
| shifted | D | 2 | 91.6% | 0 | 0 | 3 | 0 | $0.030 | 13.8 s | 0 |
| shifted | D | 3 | 91.6% | 0 | 0 | 3 | 0 | $0.029 | 13.8 s | 0 |

Total LLM cost of this evaluation: $0.65. Wall-clock time: 42.3 s with 8 parallel workers (agent time above is per run, summed over rules, and includes waiting under parallel load).

## Regression check: previously accepted rules

`eval/accepted_rules.json` holds the exclusions the agent proposed and passed on the development data. A dataset passes if they hide 0 attacks across all its weeks.

| Dataset | Rule | Missed attacks | FP removed | Result |
|---|---|---|---|---|
| original (dev) | R1 | 0 / 16 | 280 / 288 | pass |
| original (dev) | R2 | 0 / 10 | 230 / 238 | pass |
| original (dev) | R3 | 0 / 8 | 140 / 148 | pass |
| same | R1 | 0 / 25 | 420 / 432 | pass |
| same | R2 | 0 / 16 | 345 / 357 | pass |
| same | R3 | 0 / 13 | 210 / 222 | pass |
| shifted | R1 | 0 / 25 | 380 / 620 | pass |
| shifted | R2 | 0 / 16 | 130 / 360 | pass |
| shifted | R3 | 0 / 13 | 120 / 340 | pass |
| adversarial | R1 | 6 / 33 | 420 / 432 | **FAIL** |
| adversarial | R2 | 6 / 24 | 345 / 357 | **FAIL** |
| adversarial | R3 | 3 / 17 | 210 / 222 | **FAIL** |

**pytest:** `40 passed, 1 xfailed in 7.53s` (exit code 0).
Expected failures (documented, strict):
- `XFAIL tests/test_regression.py::test_accepted_rules_hide_no_attacks[adversarial] - by design: contains compromised svc_deploy / it_admin / VPN-pool / scanner accounts that look exactly like the benign sources these exclusions allow`

## Errors

None.
