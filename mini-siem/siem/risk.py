"""
risk.py - Entity risk scoring and automated response playbooks.

WHY RISK SCORING EXISTS
Alert-per-rule drowns analysts. Twelve medium alerts about one IP is twelve
tickets, and the signal is spread across all of them. Instead, alerts
accumulate onto ENTITIES (an IP, a user, a host). When an entity's score
crosses a threshold, one case opens containing the whole story.

This is the model Elastic and Microsoft Sentinel moved to, and it is the
difference between a rule engine and a SIEM.

DECAY
Risk is not permanent. An IP that brute-forced you last Tuesday and has been
quiet since is less interesting than one active in the last hour. Score decays
on a half-life so stale risk fades instead of accumulating forever.

MULTIPLIERS
Context changes severity. The same brute force against a crown-jewel database
server matters more than against a lab VM, and an attack from a known-malicious
address matters more than one from a residential ISP.

PLAYBOOKS
Response actions are plain Python functions, version-controlled and unit
tested alongside the detections. No separate automation platform to run,
no workflow JSON that cannot be reviewed in a pull request.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from .models import Alert, Case, Entity

# --------------------------------------------------------------------------
# Tunables. These live here, not scattered through the code, because tuning
# is an operational activity performed constantly.
# --------------------------------------------------------------------------
HALF_LIFE_HOURS = 24.0        # risk halves every day of inactivity
CASE_THRESHOLD = 100          # entity score that opens a case
CRITICAL_CASE_THRESHOLD = 180

CRITICALITY_MULTIPLIER = {"crown_jewel": 2.0, "high": 1.5, "medium": 1.0, "low": 0.7}
CONTEXT_MULTIPLIERS = {
    "threat_intel_match": 1.6,   # source is on a blocklist
    "privileged_user": 1.5,      # target account is privileged
    "external_source": 1.2,      # not from internal address space
    "off_hours": 1.2,            # outside business hours
    "honeypot": 2.0,             # nothing legitimate ever touches a honeypot
}


class RiskEngine:
    def __init__(self, half_life_hours: float = HALF_LIFE_HOURS,
                 case_threshold: int = CASE_THRESHOLD):
        self.half_life = half_life_hours
        self.case_threshold = case_threshold
        self.entities: dict[str, Entity] = {}

    # ---------------- scoring ----------------
    def _multiplier(self, alert: Alert) -> float:
        mult = 1.0
        ctx = alert.context or {}
        if ctx.get("threat.indicator.source"):
            mult *= CONTEXT_MULTIPLIERS["threat_intel_match"]
        if ctx.get("user.privileged"):
            mult *= CONTEXT_MULTIPLIERS["privileged_user"]
        if ctx.get("source.internal") is False:
            mult *= CONTEXT_MULTIPLIERS["external_source"]
        crit = ctx.get("host.criticality")
        if crit:
            mult *= CRITICALITY_MULTIPLIER.get(crit, 1.0)
        for ev in alert.raw_events[:1]:
            if ev.get("honeypot"):
                mult *= CONTEXT_MULTIPLIERS["honeypot"]
            if ev.get("event.business_hours") is False:
                mult *= CONTEXT_MULTIPLIERS["off_hours"]
        return mult

    def _decay(self, score: float, elapsed: timedelta) -> float:
        hours = max(elapsed.total_seconds() / 3600, 0)
        return score * math.pow(0.5, hours / self.half_life)

    def ingest(self, alerts: list[Alert]) -> dict[str, Entity]:
        """Accumulate alerts onto entities, applying decay between events."""
        for alert in sorted(alerts, key=lambda a: a.timestamp):
            key = f"{alert.entity_type}:{alert.entity}"
            ent = self.entities.get(key)
            if ent is None:
                ent = Entity(id=alert.entity, type=alert.entity_type,
                             first_seen=alert.timestamp, last_seen=alert.timestamp)
                self.entities[key] = ent
            else:
                ent.score = self._decay(ent.score, alert.timestamp - ent.last_seen)

            contribution = alert.risk_score * self._multiplier(alert)
            alert.risk_score = round(contribution)
            ent.score += contribution
            ent.last_seen = alert.timestamp
            ent.alerts.append(alert)
        return self.entities

    def ranked(self) -> list[Entity]:
        return sorted(self.entities.values(), key=lambda e: -e.score)

    # ---------------- case creation ----------------
    def open_cases(self) -> list[Case]:
        cases: list[Case] = []
        for ent in self.ranked():
            if ent.score < self.case_threshold:
                continue
            severity = ("critical" if ent.score >= CRITICAL_CASE_THRESHOLD
                        else "high" if ent.score >= self.case_threshold * 1.3 else "medium")
            worst = max(ent.alerts, key=lambda a: a.risk_score)
            actions: list[str] = []
            for a in sorted(ent.alerts, key=lambda a: -a.risk_score)[:3]:
                actions.extend(RESPONSE_LIBRARY.get(a.rule_id, []))
            # dedupe while preserving order
            seen, ordered_actions = set(), []
            for act in actions:
                if act not in seen:
                    seen.add(act)
                    ordered_actions.append(act)

            summary = (
                f"Entity {ent.id} ({ent.type}) accumulated a risk score of {ent.score:.0f} "
                f"from {len(ent.alerts)} alerts spanning "
                f"{_span(ent.first_seen, ent.last_seen)}, covering "
                f"{len(ent.techniques)} ATT&CK techniques "
                f"({', '.join(ent.techniques[:6]) or 'none mapped'}). "
                f"Highest-severity finding: {worst.rule_name}."
            )
            # Deterministic case id: the same entity on the same day always
            # produces the same case, so re-running the pipeline updates a case
            # instead of spawning duplicates. Real SOCs dedupe this way too.
            stamp = hashlib.sha256(f"{ent.type}:{ent.id}".encode()).hexdigest()[:6].upper()
            cases.append(Case(
                id=f"CASE-{ent.last_seen:%Y%m%d}-{stamp}",
                entity=ent,
                severity=severity,
                opened_at=ent.last_seen,
                title=f"{severity.upper()}: {ent.type} {ent.id} - {worst.rule_name}",
                summary=summary,
                recommended_actions=ordered_actions[:8],
                sla_hours=1 if severity == "critical" else 4 if severity == "high" else 24,
            ))
        return cases


def _span(a: datetime | None, b: datetime | None) -> str:
    if not a or not b:
        return "unknown"
    mins = int((b - a).total_seconds() // 60)
    if mins < 60:
        return f"{mins} minutes"
    if mins < 1440:
        return f"{mins // 60}h {mins % 60}m"
    return f"{mins // 1440}d {(mins % 1440) // 60}h"


# ==========================================================================
# Response playbooks - plain Python, tested like any other code
# ==========================================================================
RESPONSE_LIBRARY: dict[str, list[str]] = {
    "ssh_brute_force": [
        "Block source IP at the perimeter firewall",
        "Verify whether any authentication from this source succeeded",
        "Enable fail2ban or equivalent rate limiting on the target host",
    ],
    "ssh_password_spray": [
        "Identify which sprayed accounts exist and are enabled",
        "Force password reset on any account that authenticated",
        "Review password policy and enable MFA on exposed services",
    ],
    "auth_success_after_failures": [
        "ISOLATE the target host from the network",
        "Rotate credentials for the compromised account immediately",
        "Revoke active sessions and authorised SSH keys",
        "Capture volatile memory before reboot for forensics",
        "Hunt for persistence: cron, systemd units, authorized_keys, new accounts",
    ],
    "win_audit_log_cleared": [
        "Preserve the host; treat as active intrusion cleanup",
        "Reconstruct activity from SIEM-forwarded logs prior to the clear",
        "Identify the account that cleared the log and its logon source",
    ],
    "win_privileged_group_add": [
        "Verify an approved change ticket exists for this membership",
        "Remove the membership if unapproved and investigate the granting account",
    ],
    "web_sql_injection": [
        "Review response codes for successful injection (200 on injected parameter)",
        "Check database audit logs for unauthorised queries at matching timestamps",
        "Deploy a WAF rule for the affected endpoint",
    ],
    "web_sensitive_paths": [
        "Confirm the probed files are not actually served",
        "Rotate any secret that was exposed via a 200 response",
    ],
    "chain_recon_to_compromise": [
        "PAGE the on-call analyst - confirmed intrusion pattern",
        "Activate the incident response plan and assign an incident commander",
        "Isolate affected hosts and begin evidence preservation",
    ],
    "honeypot_command": [
        "Extract downloaded payload hashes and submit to threat intel",
        "Record the command sequence as adversary tradecraft",
        "Block the source permanently; honeypot contact is definitionally hostile",
    ],
}


class PlaybookRunner:
    """
    Executes response playbooks. Runs in dry-run mode by default: it records
    what it WOULD do rather than doing it.

    Automated blocking is genuinely dangerous. An attacker who knows you
    auto-block can spoof traffic from your payment processor's address range
    and take your business offline for you. Containment stays behind a human
    decision unless the confidence is absolute.
    """

    def __init__(self, dry_run: bool = True, blocklist_path: str = "out/blocklist.txt"):
        self.dry_run = dry_run
        self.blocklist_path = Path(blocklist_path)
        self.actions_taken: list[dict] = []

    def _record(self, action: str, target: str, detail: str, executed: bool):
        self.actions_taken.append({
            "action": action, "target": target, "detail": detail,
            "executed": executed, "mode": "dry-run" if self.dry_run else "live",
            "at": datetime.now().isoformat(timespec="seconds"),
        })

    def block_ip(self, ip: str, reason: str) -> None:
        if self.dry_run:
            self._record("block_ip", ip, f"would block: {reason}", False)
            return
        self.blocklist_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.blocklist_path, "a", encoding="utf-8") as fh:
            fh.write(f"{ip}  # {reason} ({datetime.now():%Y-%m-%d %H:%M})\n")
        self._record("block_ip", ip, reason, True)

    def notify(self, case: Case) -> None:
        detail = f"[{case.severity.upper()}] {case.title} | SLA {case.sla_hours}h"
        self._record("notify", case.entity.id, detail, not self.dry_run)

    def write_case_file(self, case: Case, out_dir: str = "out/cases") -> Path:
        path = Path(out_dir)
        path.mkdir(parents=True, exist_ok=True)
        target = path / f"{case.id}.json"
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(case.to_dict(), fh, indent=2)
        self._record("create_case", case.entity.id, str(target), True)
        return target

    def run(self, cases: list[Case]) -> list[dict]:
        """
        Auto-containment policy: only for honeypot contact, where false
        positives are impossible by construction. Everything else notifies
        and waits for a human.
        """
        for case in cases:
            self.write_case_file(case)
            self.notify(case)
            honeypot_confirmed = any(a.rule_id.startswith("honeypot") for a in case.entity.alerts)
            if case.entity.type == "ip" and honeypot_confirmed:
                self.block_ip(case.entity.id, f"honeypot interaction - {case.id}")
            elif case.severity == "critical" and case.entity.type == "ip":
                self._record("block_ip", case.entity.id,
                             "HELD FOR ANALYST APPROVAL - critical but not honeypot-confirmed", False)
        return self.actions_taken
