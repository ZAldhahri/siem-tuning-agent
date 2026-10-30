"""Generate synthetic SIEM events with ground-truth labels.

Two weeks of data: week 1 is the training window the agent tunes on, week 2 is the
holdout used to validate a proposed tuning before it is applied.

Each rule's noise has an easy-to-exclude bulk source, a messy residue that cannot be
excluded safely, and "trap" attacks that share field values with the benign noise so
that a sloppy exclusion (whole user, whole subnet, whole parent process) hides a real
attack. Some traps only appear in week 2, so only the holdout catches them.
"""
import csv
import random
from datetime import datetime, timedelta

random.seed(42)
START = datetime(2026, 10, 1)
users = [f"user{i}" for i in range(1, 41)]
events = []


def ts(week):
    """Random timestamp inside week 1 (days 0-6) or week 2 (days 7-13)."""
    offset = (week - 1) * 7 * 24 * 60 + random.randint(0, 7 * 24 * 60 - 1)
    return (START + timedelta(minutes=offset)).isoformat()


def pub_ip():
    return ".".join(str(random.randint(11, 250)) for _ in range(4))


def internal_ip():
    return f"10.0.{random.randint(1, 9)}.{random.randint(2, 250)}"


def ev(week=None, **kw):
    """Add one event; week is random unless given."""
    week = week or random.choice([1, 2])
    e = dict(timestamp=ts(week), week=week, event_type="", user=random.choice(users),
             src_ip=internal_ip(), host=f"PC-{random.randint(1, 60)}", process="",
             parent_process="", encoded=False, failed_count=0, impossible_travel=False,
             via_vpn=False, is_malicious=False)
    e.update(kw)
    events.append(e)


# Normal background activity
for _ in range(2000):
    ev(event_type=random.choice(["login_success", "process_exec"]),
       process=random.choice(["chrome.exe", "excel.exe", "teams.exe"]))

# ---------------------------------------------------------------- R1 brute force
burst = dict(event_type="login_failure_burst")
for _ in range(170):  # vulnerability scanner, fixed IP (safe to exclude: user AND ip)
    ev(**burst, user="vuln_scanner", src_ip="10.0.5.20", failed_count=random.randint(6, 40))
for _ in range(110):  # backup account retries from internal hosts (safe: user AND internal)
    ev(**burst, user="svc_backup", failed_count=random.randint(6, 30))
for _ in range(8):    # messy: ordinary users locking themselves out (not safely excludable)
    ev(**burst, failed_count=random.randint(6, 12))
for i in range(14):   # real attacks from the internet, split evenly across weeks
    ev(week=1 + i % 2, **burst, src_ip=pub_ip(), failed_count=random.randint(8, 200), is_malicious=True)
# Traps
ev(week=1, **burst, user="svc_backup", src_ip=pub_ip(), failed_count=25,
   is_malicious=True)  # excluding the whole svc_backup user hides this
ev(week=2, **burst, src_ip="10.0.5.77", failed_count=9,
   is_malicious=True)  # compromised host in the scanner's subnet

# ---------------------------------------------------------------- R2 encoded PowerShell
ps = dict(event_type="process_exec", process="powershell.exe", encoded=True)
for _ in range(180):  # SCCM deployments (safe: parent ccmexec AND user svc_deploy)
    ev(**ps, parent_process="ccmexec.exe", user="svc_deploy")
for _ in range(50):   # IT admins running scripts (safe: admin user AND parent)
    ev(**ps, parent_process=random.choice(["cmd.exe", "explorer.exe"]),
       user=f"it_admin{random.randint(1, 4)}")
for _ in range(8):    # messy: per-user WMI inventory script (not safely excludable)
    ev(**ps, parent_process="wmiprvse.exe")
for i in range(8):    # real phishing payloads
    ev(week=1 + i % 2, **ps, parent_process=random.choice(["winword.exe", "outlook.exe"]), is_malicious=True)
# Traps
ev(week=1, **ps, parent_process="ccmexec.exe", user="user12",
   is_malicious=True)  # attacker abusing SCCM: excluding all ccmexec hides this
ev(week=2, **ps, parent_process="wmiprvse.exe", user="user27",
   is_malicious=True)  # WMI lateral movement

# ---------------------------------------------------------------- R3 impossible travel
travel = dict(event_type="login_success", impossible_travel=True)
for _ in range(140):  # VPN users, VPN address pool (safe: via_vpn AND 10.8. pool)
    ev(**travel, via_vpn=True, src_ip=f"10.8.{random.randint(0, 3)}.{random.randint(2, 250)}")
for _ in range(8):    # messy: genuine travellers on mobile data (not safely excludable)
    ev(**travel, src_ip=pub_ip())
for i in range(7):    # real account compromises
    ev(week=1 + i % 2, **travel, src_ip=pub_ip(), is_malicious=True)
# Trap
ev(week=2, **travel, via_vpn=True, src_ip=pub_ip(),
   is_malicious=True)  # stolen VPN credentials: excluding all VPN traffic hides this

random.shuffle(events)
events.sort(key=lambda e: e["timestamp"])
with open("data/events.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=events[0].keys())
    w.writeheader()
    w.writerows(events)
print(f"Wrote {len(events)} events")
