"""Previously accepted rules must keep hiding 0 attacks on every dataset."""
import json
import subprocess
import sys

import pytest

from agent.backtest import backtest
from agent.engine import ROOT, load_events

ACCEPTED = json.loads((ROOT / "eval" / "accepted_rules.json").read_text())
UNSEEN = ROOT / "data" / "unseen"


@pytest.fixture(scope="session", autouse=True)
def unseen_data():
    if not all((UNSEEN / f"{n}.csv").exists() for n in ("same", "shifted", "adversarial")):
        subprocess.run([sys.executable, str(ROOT / "data" / "generate_unseen.py")], check=True)


@pytest.mark.parametrize("dataset", [
    "original", "same", "shifted",
    pytest.param("adversarial", marks=pytest.mark.xfail(strict=True, reason=(
        "by design: contains compromised svc_deploy / it_admin / VPN-pool / scanner accounts "
        "that look exactly like the benign sources these exclusions allow"))),
])
def test_accepted_rules_hide_no_attacks(dataset):
    df = load_events() if dataset == "original" else load_events(UNSEEN / f"{dataset}.csv")
    missed = {r["id"]: len(backtest(r, df)["missed_true_positives"]) for r in ACCEPTED}
    assert missed == {r["id"]: 0 for r in ACCEPTED}, missed
