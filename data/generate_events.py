import random, csv
from datetime import datetime, timedelta

random.seed(42)
start = datetime(2026, 10, 1)
users = [f"user{i}" for i in range(1, 41)]
events = []

def ts():
    return (start + timedelta(minutes=random.randint(0, 60*24*14))).isoformat()

def pub_ip():
    return ".".join(str(random.randint(11, 250)) for _ in range(4))

def ev(**kw):
    e = dict(timestamp=ts(), event_type="", user=random.choice(users),
             src_ip=f"10.0.{random.randint(1,9)}.{random.randint(2,250)}",
             host=f"PC-{random.randint(1,60)}", process="", parent_process="",
             encoded=False, failed_count=0, impossible_travel=False,
             via_vpn=False, is_malicious=False)
    e.update(kw)
    events.append(e)

# Normal background noise
for _ in range(2000):
    ev(event_type=random.choice(["login_success", "process_exec"]),
       process=random.choice(["chrome.exe", "excel.exe", "teams.exe"]))

# R1: brute force (noise from scanner + backup account, a few real attacks)
for _ in range(300):
    extra = random.choice([dict(src_ip="10.0.5.20", user="vuln_scanner"), dict(user="svc_backup")])
    ev(event_type="login_failure_burst", failed_count=random.randint(6, 40), **extra)
for _ in range(15):
    ev(event_type="login_failure_burst", failed_count=random.randint(8, 200),
       src_ip=pub_ip(), is_malicious=True)

# R2: encoded PowerShell (noise from SCCM, a few real phishing payloads)
for _ in range(250):
    ev(event_type="process_exec", process="powershell.exe", encoded=True,
       parent_process="ccmexec.exe", user="svc_deploy")
for _ in range(10):
    ev(event_type="process_exec", process="powershell.exe", encoded=True,
       parent_process=random.choice(["winword.exe", "outlook.exe"]), is_malicious=True)

# R3: impossible travel (noise from VPN users, a few real compromises)
for _ in range(150):
    ev(event_type="login_success", impossible_travel=True, via_vpn=True)
for _ in range(8):
    ev(event_type="login_success", impossible_travel=True, via_vpn=False,
       src_ip=pub_ip(), is_malicious=True)

random.shuffle(events)
with open("data/events.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=events[0].keys())
    w.writeheader()
    w.writerows(events)
print(f"Wrote {len(events)} events")