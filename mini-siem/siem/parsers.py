"""
parsers.py - Turn raw log lines from five different sources into ECS events.

Design note: every parser returns the SAME shape. A Windows 4625 and a Linux
"Failed password" both become:
    event.category = authentication, event.outcome = failure,
    source.ip = x, user.name = y
That is the whole point. One detection rule then covers every platform,
instead of one rule per log format.

Supported sources:
  sshd      Linux /var/log/auth.log (syslog)
  sudo      Linux sudo events (syslog)
  nginx     Nginx/Apache combined access log
  winlog    Windows Security events as JSON (evtx -> JSON via evtx_dump/Winlogbeat)
  suricata  Suricata EVE JSON alerts
  cowrie    Cowrie SSH honeypot JSON
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Callable, Iterator
from urllib.parse import unquote

from .models import Event

# ==========================================================================
# Linux sshd (syslog)
# ==========================================================================
SSHD_AUTH_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: "
    r"(?P<result>Failed|Accepted) (?P<method>\w+) for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
)
SSHD_KEY_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[\d+\]: "
    r"Accepted publickey for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)
SUDO_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) sudo:\s+(?P<user>\S+) : "
    r"(?P<status>TTY=\S+ ; PWD=\S+ ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)"
    r"|user NOT in sudoers.*)"
)


def _syslog_time(raw: str, year: int) -> datetime:
    """Syslog carries no year, so the caller supplies one."""
    clean = " ".join(raw.split())
    return datetime.strptime(f"{year} {clean}", "%Y %b %d %H:%M:%S")


def parse_sshd(line: str, year: int) -> Event | None:
    m = SSHD_AUTH_RE.match(line)
    if m:
        success = m["result"] == "Accepted"
        return Event({
            "@timestamp": _syslog_time(m["ts"], year),
            "event.kind": "event",
            "event.category": "authentication",
            "event.action": "ssh_login",
            "event.outcome": "success" if success else "failure",
            "event.provider": "sshd",
            "event.dataset": "linux.auth",
            "host.name": m["host"],
            "source.ip": m["ip"],
            "source.port": int(m["port"]),
            "user.name": m["user"],
            "user.invalid": bool(m["invalid"]),
            "process.pid": int(m["pid"]),
            "auth.method": m["method"].lower(),
            "message": line.strip(),
        })
    m = SSHD_KEY_RE.match(line)
    if m:
        return Event({
            "@timestamp": _syslog_time(m["ts"], year),
            "event.kind": "event",
            "event.category": "authentication",
            "event.action": "ssh_login",
            "event.outcome": "success",
            "event.provider": "sshd",
            "event.dataset": "linux.auth",
            "host.name": m["host"],
            "source.ip": m["ip"],
            "user.name": m["user"],
            "user.invalid": False,
            "auth.method": "publickey",
            "message": line.strip(),
        })
    return None


def parse_sudo(line: str, year: int) -> Event | None:
    m = SUDO_RE.match(line)
    if not m:
        return None
    denied = "NOT in sudoers" in m["status"]
    return Event({
        "@timestamp": _syslog_time(m["ts"], year),
        "event.kind": "event",
        "event.category": "process",
        "event.action": "sudo",
        "event.outcome": "failure" if denied else "success",
        "event.provider": "sudo",
        "event.dataset": "linux.auth",
        "host.name": m["host"],
        "user.name": m["user"],
        "user.target": m["target"] or "root",
        "process.command_line": (m["cmd"] or "").strip(),
        "message": line.strip(),
    })


# ==========================================================================
# Nginx / Apache combined access log
# ==========================================================================
NGINX_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<agent>[^"]*)")?'
)


def parse_nginx(line: str, year: int | None = None) -> Event | None:
    m = NGINX_RE.match(line)
    if not m:
        return None
    ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    status = int(m["status"])
    path = m["path"]
    return Event({
        "@timestamp": ts,
        "event.kind": "event",
        "event.category": "web",
        "event.action": "http_request",
        "event.outcome": "success" if status < 400 else "failure",
        "event.provider": "nginx",
        "event.dataset": "nginx.access",
        "source.ip": m["ip"],
        "user.name": None if m["user"] == "-" else m["user"],
        "http.request.method": m["method"],
        "http.response.status_code": status,
        "http.response.body.bytes": 0 if m["size"] == "-" else int(m["size"]),
        "url.original": path,
        # Decoded copy: attackers URL-encode payloads precisely to dodge naive
        # string matching, so rules must run against the decoded form.
        "url.path": unquote(path),
        "user_agent.original": m["agent"] or "",
        "http.request.referrer": m["ref"] or "",
        "message": line.strip(),
    })


# ==========================================================================
# Windows Security log (JSON)
# ==========================================================================
WIN_EVENT_MAP = {
    4624: ("authentication", "logon", "success"),
    4625: ("authentication", "logon", "failure"),
    4634: ("authentication", "logoff", "success"),
    4648: ("authentication", "explicit_credential_logon", "success"),
    4672: ("iam", "special_privileges_assigned", "success"),
    4720: ("iam", "user_created", "success"),
    4726: ("iam", "user_deleted", "success"),
    4732: ("iam", "added_to_privileged_group", "success"),
    4688: ("process", "process_creation", "success"),
    1102: ("configuration", "audit_log_cleared", "success"),
    7045: ("configuration", "service_installed", "success"),
}
# Logon type 3 = network, 10 = RDP. Useful context for lateral movement rules.
LOGON_TYPES = {2: "interactive", 3: "network", 4: "batch", 5: "service",
               7: "unlock", 8: "network_cleartext", 9: "new_credentials",
               10: "remote_interactive", 11: "cached_interactive"}


def parse_winlog(line: str, year: int | None = None) -> Event | None:
    try:
        raw = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    eid = raw.get("EventID") or raw.get("event_id")
    if eid is None:
        return None
    eid = int(eid)
    category, action, outcome = WIN_EVENT_MAP.get(eid, ("configuration", f"event_{eid}", "unknown"))
    data = raw.get("EventData", raw)
    ts_raw = raw.get("TimeCreated") or raw.get("@timestamp")
    ts = datetime.fromisoformat(str(ts_raw).replace("Z", "")) if ts_raw else datetime.utcnow()
    logon_type = data.get("LogonType")
    ev = Event({
        "@timestamp": ts,
        "event.kind": "event",
        "event.category": category,
        "event.action": action,
        "event.outcome": outcome,
        "event.code": eid,
        "event.provider": "windows_security",
        "event.dataset": "windows.security",
        "host.name": raw.get("Computer", "unknown"),
        "source.ip": data.get("IpAddress") if data.get("IpAddress") not in ("-", "::1", None) else None,
        "user.name": data.get("TargetUserName") or data.get("SubjectUserName"),
        "user.domain": data.get("TargetDomainName"),
        "winlog.logon_type": LOGON_TYPES.get(int(logon_type), str(logon_type)) if logon_type else None,
        "winlog.status": data.get("Status"),
        "process.name": data.get("NewProcessName") or data.get("ProcessName"),
        "process.command_line": data.get("CommandLine"),
        "process.parent.name": data.get("ParentProcessName"),
        "service.name": data.get("ServiceName"),
        "group.name": data.get("TargetGroupName") or data.get("GroupName"),
        "message": raw.get("Message", f"Windows event {eid}"),
    })
    return Event({k: v for k, v in ev.items() if v is not None})


# ==========================================================================
# Suricata EVE JSON
# ==========================================================================
def parse_suricata(line: str, year: int | None = None) -> Event | None:
    try:
        raw = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if raw.get("event_type") != "alert":
        return None
    alert = raw.get("alert", {})
    ts = datetime.fromisoformat(raw["timestamp"].split("+")[0].split("Z")[0])
    return Event({
        "@timestamp": ts,
        "event.kind": "alert",
        "event.category": "network",
        "event.action": "ids_alert",
        "event.outcome": "unknown",
        "event.provider": "suricata",
        "event.dataset": "suricata.eve",
        "source.ip": raw.get("src_ip"),
        "source.port": raw.get("src_port"),
        "destination.ip": raw.get("dest_ip"),
        "destination.port": raw.get("dest_port"),
        "network.protocol": raw.get("proto", "").lower(),
        "rule.name": alert.get("signature"),
        "rule.category": alert.get("category"),
        "rule.signature_id": alert.get("signature_id"),
        "event.severity": alert.get("severity", 3),
        "message": alert.get("signature", "suricata alert"),
    })


# ==========================================================================
# Cowrie SSH honeypot JSON
# ==========================================================================
COWRIE_MAP = {
    "cowrie.login.failed": ("authentication", "ssh_login", "failure"),
    "cowrie.login.success": ("authentication", "ssh_login", "success"),
    "cowrie.command.input": ("process", "command_executed", "success"),
    "cowrie.session.file_download": ("file", "file_download", "success"),
    "cowrie.session.connect": ("network", "connection", "unknown"),
}


def parse_cowrie(line: str, year: int | None = None) -> Event | None:
    try:
        raw = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    eventid = raw.get("eventid")
    if eventid not in COWRIE_MAP:
        return None
    category, action, outcome = COWRIE_MAP[eventid]
    ts = datetime.fromisoformat(raw["timestamp"].replace("Z", "").split("+")[0])
    return Event({k: v for k, v in {
        "@timestamp": ts,
        "event.kind": "event",
        "event.category": category,
        "event.action": action,
        "event.outcome": outcome,
        "event.provider": "cowrie",
        "event.dataset": "honeypot.cowrie",
        "host.name": raw.get("sensor", "honeypot"),
        "source.ip": raw.get("src_ip"),
        "user.name": raw.get("username"),
        "user.password_attempted": raw.get("password"),
        "process.command_line": raw.get("input"),
        "url.original": raw.get("url"),
        "file.hash.sha256": raw.get("shasum"),
        "honeypot": True,
        "message": raw.get("message", eventid),
    }.items() if v is not None})


# ==========================================================================
# Registry and dispatch
# ==========================================================================
PARSERS: dict[str, Callable[..., Event | None]] = {
    "sshd": parse_sshd,
    "sudo": parse_sudo,
    "nginx": parse_nginx,
    "winlog": parse_winlog,
    "suricata": parse_suricata,
    "cowrie": parse_cowrie,
}
# syslog files interleave sshd and sudo lines, so try both per line
SOURCE_CHAINS = {
    "auth": ["sshd", "sudo"],
    "sshd": ["sshd", "sudo"],
    "nginx": ["nginx"],
    "winlog": ["winlog"],
    "suricata": ["suricata"],
    "cowrie": ["cowrie"],
}


def detect_source(sample_lines: list[str]) -> str:
    """Guess the log type so --source is optional."""
    blob = "\n".join(sample_lines)
    if "sshd[" in blob or "sudo:" in blob:
        return "auth"
    if '"event_type"' in blob and "suricata" not in blob.lower() or '"alert"' in blob:
        if '"eventid"' in blob:
            return "cowrie"
        return "suricata"
    if '"eventid"' in blob and "cowrie" in blob:
        return "cowrie"
    if '"EventID"' in blob or '"event_id"' in blob:
        return "winlog"
    if re.search(r'"(GET|POST|HEAD|PUT) ', blob):
        return "nginx"
    return "auth"


def parse_file(path: str, source: str | None = None, year: int = 2026) -> tuple[list[Event], int]:
    """Parse one log file into ECS events. Returns (events, skipped_line_count)."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    if source is None:
        source = detect_source(lines[:40])
    chain = SOURCE_CHAINS.get(source, [source])
    events, skipped = [], 0
    for line in lines:
        if not line.strip():
            continue
        for name in chain:
            parser = PARSERS.get(name)
            if not parser:
                continue
            ev = parser(line, year)
            if ev:
                ev["log.file.path"] = path
                events.append(ev)
                break
        else:
            # No parser matched. Real logs are full of lines we do not care
            # about; counting them is how you spot a broken regex early.
            skipped += 1
    return events, skipped


def parse_many(paths: dict[str, str | None], year: int = 2026) -> tuple[list[Event], dict]:
    """
    paths: {file_path: source_name_or_None}
    Returns all events sorted by time, plus per-file stats.
    """
    all_events: list[Event] = []
    stats: dict = {}
    for path, source in paths.items():
        evs, skipped = parse_file(path, source, year)
        stats[path] = {"parsed": len(evs), "skipped": skipped,
                       "source": source or detect_source(open(path, encoding="utf-8", errors="replace").readlines()[:40])}
        all_events.extend(evs)
    all_events.sort(key=lambda e: e["@timestamp"])
    return all_events, stats
