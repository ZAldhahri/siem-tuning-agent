"""Generate 3 UNSEEN evaluation datasets (never used while developing the agent).

Each has 3 weeks: week 1 = training (the agent tunes on it), week 2 = validation (the
agent's holdout gate), week 3 = test (never touched by the agent; reported in eval).

  same         same generating process as data/generate_events.py, new seed
  shifted      new benign sources and different volumes (new service accounts, a pen-test
               vendor, Intune, a second VPN pool, a cloud proxy)
  adversarial  same benign sources, but many more trap attacks that look like benign noise,
               all arriving AFTER the training week (weeks 2-3). Some are separable from
               the noise by a third field (failed_count); some are indistinguishable from
               it (a compromised service/admin account doing exactly what it normally does).

Usage: python data/generate_unseen.py   -> data/unseen/{same,shifted,adversarial}.csv
"""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent / "unseen"
START = datetime(2026, 11, 1)
WEEKS = 3
PROFILES = {"same": 101, "shifted": 202, "adversarial": 303}


def generate(profile: str, seed: int) -> list[dict]:
    rng = random.Random(seed)
    users = [f"user{i}" for i in range(1, 41)]
    events = []

    def pub_ip():
        return ".".join(str(rng.randint(11, 250)) for _ in range(4))

    def internal_ip():
        return f"10.0.{rng.randint(1, 9)}.{rng.randint(2, 250)}"

    def ev(week=None, **kw):
        week = week or rng.randint(1, WEEKS)
        minute = (week - 1) * 7 * 24 * 60 + rng.randint(0, 7 * 24 * 60 - 1)
        e = dict(timestamp=(START + timedelta(minutes=minute)).isoformat(), week=week,
                 event_type="", user=rng.choice(users), src_ip=internal_ip(),
                 host=f"PC-{rng.randint(1, 60)}", process="", parent_process="",
                 encoded=False, failed_count=0, impossible_travel=False, via_vpn=False,
                 is_malicious=False)
        e.update(kw)
        events.append(e)

    def many(n, **kw):                       # n benign events, random weeks
        for _ in range(n):
            ev(**{k: (v() if callable(v) else v) for k, v in kw.items()})

    def attacks(n, weeks=(1, 2, 3), **kw):   # n malicious events spread over the given weeks
        start = rng.randrange(len(weeks))
        for i in range(n):
            ev(week=weeks[(start + i) % len(weeks)], is_malicious=True,
               **{k: (v() if callable(v) else v) for k, v in kw.items()})

    shifted, adversarial = profile == "shifted", profile == "adversarial"
    trap_weeks = (2, 3) if adversarial else (1, 2, 3)
    trap_n = 3 if adversarial else 2

    many(3000, event_type=lambda: rng.choice(["login_success", "process_exec"]),
         process=lambda: rng.choice(["chrome.exe", "excel.exe", "teams.exe"]))

    # ---- R1 brute force
    burst = dict(event_type="login_failure_burst")
    many(80 if shifted else 255, **burst, user="vuln_scanner", src_ip="10.0.5.20",
         failed_count=lambda: rng.randint(6, 40))
    many(300 if shifted else 165, **burst, user="svc_backup",
         failed_count=lambda: rng.randint(6, 30))
    many(30 if shifted else 12, **burst, failed_count=lambda: rng.randint(6, 12))
    if shifted:
        many(150, **burst, user="svc_sql", src_ip="10.0.7.15",
             failed_count=lambda: rng.randint(6, 20))
        many(60, **burst, user="pentest_vendor",
             src_ip=lambda: f"203.0.113.{rng.randint(2, 250)}",
             failed_count=lambda: rng.randint(10, 60))
    attacks(21, **burst, src_ip=pub_ip, failed_count=lambda: rng.randint(8, 200))
    attacks(trap_n, trap_weeks, **burst, user="svc_backup", src_ip=pub_ip, failed_count=25)
    attacks(trap_n, trap_weeks, **burst, src_ip="10.0.5.77", failed_count=9)
    if adversarial:   # separable from the noise only by failed_count
        attacks(3, trap_weeks, **burst, user="vuln_scanner", src_ip="10.0.5.20",
                failed_count=lambda: rng.randint(150, 300))
        attacks(3, trap_weeks, **burst, user="svc_backup",
                failed_count=lambda: rng.randint(100, 200))

    # ---- R2 encoded PowerShell
    ps = dict(event_type="process_exec", process="powershell.exe", encoded=True)
    many(90 if shifted else 270, **ps, parent_process="ccmexec.exe", user="svc_deploy")
    many(40 if shifted else 75, **ps, user=lambda: f"it_admin{rng.randint(1, 4)}",
         parent_process=lambda: rng.choice(["cmd.exe", "explorer.exe"]))
    many(30 if shifted else 12, **ps, parent_process="wmiprvse.exe")
    if shifted:
        many(200, **ps, parent_process="IntuneManagementExtension.exe", user="SYSTEM")
    attacks(12, **ps, parent_process=lambda: rng.choice(["winword.exe", "outlook.exe"]))
    attacks(trap_n, trap_weeks, **ps, parent_process="ccmexec.exe", user="user12")
    attacks(trap_n, trap_weeks, **ps, parent_process="wmiprvse.exe", user="user27")
    if adversarial:   # indistinguishable from the benign source
        attacks(3, trap_weeks, **ps, parent_process="ccmexec.exe", user="svc_deploy")
        attacks(3, trap_weeks, **ps, parent_process="explorer.exe", user="it_admin2")

    # ---- R3 impossible travel
    travel = dict(event_type="login_success", impossible_travel=True)
    many(120 if shifted else 210, **travel, via_vpn=True,
         src_ip=lambda: f"10.8.{rng.randint(0, 3)}.{rng.randint(2, 250)}")
    many(30 if shifted else 12, **travel, src_ip=pub_ip)
    if shifted:
        many(100, **travel, via_vpn=True,
             src_ip=lambda: f"10.9.{rng.randint(0, 3)}.{rng.randint(2, 250)}")
        many(90, **travel, src_ip=lambda: f"198.51.100.{rng.randint(2, 250)}")
    attacks(11, **travel, src_ip=pub_ip)
    attacks(trap_n, trap_weeks, **travel, via_vpn=True, src_ip=pub_ip)
    if adversarial:   # indistinguishable: compromised account inside the VPN pool
        attacks(3, trap_weeks, **travel, via_vpn=True,
                src_ip=lambda: f"10.8.{rng.randint(0, 3)}.{rng.randint(2, 250)}")

    events.sort(key=lambda e: e["timestamp"])
    return events


def main():
    OUT_DIR.mkdir(exist_ok=True)
    for name, seed in PROFILES.items():
        events = generate(name, seed)
        with open(OUT_DIR / f"{name}.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=events[0].keys())
            w.writeheader()
            w.writerows(events)
        n_mal = sum(e["is_malicious"] for e in events)
        print(f"{name:<12} seed={seed}  {len(events)} events, {n_mal} malicious")


if __name__ == "__main__":
    main()
