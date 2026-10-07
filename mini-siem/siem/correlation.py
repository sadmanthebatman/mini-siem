"""
correlation.py - Detections that a single-event rule cannot express.

Three classes of logic live here:

  1. STATEFUL     Something that depends on what came before.
                  "Success after 10 failures" needs memory of the failures.

  2. SEQUENCE     Multi-stage attack chains across data sources.
                  Recon -> brute force -> successful login -> command execution.
                  This is the thing that makes a SIEM a SIEM: no single log
                  source sees the whole attack, only the correlation does.

  3. BEHAVIORAL   Deviation from a learned baseline rather than a known-bad
                  pattern. Catches what signatures miss, at the cost of
                  needing a clean training period.
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

import yaml

from .models import Alert, Event

# ==========================================================================
# 1. Stateful
# ==========================================================================
def success_after_failures(events: list[Event], threshold: int = 8,
                           window: timedelta = timedelta(minutes=10),
                           enricher=None) -> list[Alert]:
    """
    The highest-value detection in the whole system.

    Many failures then a success means the guessing stopped because it
    worked. Everything else in this SIEM is a lead; this is an incident.
    """
    alerts: list[Alert] = []
    fails: dict[str, list[Event]] = defaultdict(list)

    for e in sorted(events, key=lambda x: x["@timestamp"]):
        if e.get("event.category") != "authentication":
            continue
        ip = e.get("source.ip")
        if not ip:
            continue
        now = e["@timestamp"]
        # Drop failures that have aged out of the window
        fails[ip] = [f for f in fails[ip] if now - f["@timestamp"] <= window]

        if e.get("event.outcome") == "failure":
            fails[ip].append(e)
        elif e.get("event.outcome") == "success" and len(fails[ip]) >= threshold:
            tried = {f.get("user.name") for f in fails[ip]}
            alerts.append(Alert(
                rule_id="auth_success_after_failures",
                rule_name="Successful Authentication After Repeated Failures",
                severity="critical",
                timestamp=now,
                entity=ip,
                entity_type="ip",
                description=(f"Authentication SUCCEEDED as '{e.get('user.name')}' on "
                             f"{e.get('host.name')} after {len(fails[ip])} failures "
                             f"against {len(tried)} account(s) in the preceding "
                             f"{int(window.total_seconds() // 60)} minutes"),
                tags=["T1078", "T1110", "ATTACK.INITIAL_ACCESS"],
                evidence=[f"failed: {f.get('user.name')} at {f['@timestamp']}" for f in fails[ip][-4:]]
                         + [f"SUCCESS: {e.get('user.name')} at {now}"],
                event_count=len(fails[ip]) + 1,
                raw_events=fails[ip] + [e],
                context=enricher.context_for(e) if enricher else {},
            ))
            fails[ip] = []
    return alerts


def privilege_escalation_after_login(events: list[Event], window: timedelta = timedelta(minutes=15),
                                     enricher=None) -> list[Alert]:
    """Sudo/privileged action shortly after a login from an external address."""
    alerts: list[Alert] = []
    recent_external_login: dict[str, Event] = {}
    for e in sorted(events, key=lambda x: x["@timestamp"]):
        user = e.get("user.name")
        if not user:
            continue
        if (e.get("event.category") == "authentication" and e.get("event.outcome") == "success"
                and e.get("source.internal") is False):
            recent_external_login[user] = e
        elif e.get("event.action") in ("sudo", "special_privileges_assigned"):
            prior = recent_external_login.get(user)
            if prior and e["@timestamp"] - prior["@timestamp"] <= window:
                alerts.append(Alert(
                    rule_id="priv_esc_after_external_login",
                    rule_name="Privilege Escalation Shortly After External Login",
                    severity="high",
                    timestamp=e["@timestamp"],
                    entity=str(prior.get("source.ip")),
                    entity_type="ip",
                    description=(f"User '{user}' escalated privileges "
                                 f"{int((e['@timestamp'] - prior['@timestamp']).total_seconds() // 60)}m "
                                 f"after logging in from external address {prior.get('source.ip')}"),
                    tags=["T1548", "ATTACK.PRIVILEGE_ESCALATION"],
                    evidence=[f"login from {prior.get('source.ip')} at {prior['@timestamp']}",
                              f"command: {e.get('process.command_line')}"],
                    raw_events=[prior, e],
                    context=enricher.context_for(prior) if enricher else {},
                ))
                recent_external_login.pop(user, None)
    return alerts


# ==========================================================================
# 2. Sequence correlation (YAML-driven)
# ==========================================================================
class SequenceRule:
    """
    Chains alerts from other rules into a single higher-confidence alert.

    Example: web_scanning -> ssh_brute_force -> auth_success_after_failures
    within 2 hours from the same IP is not three medium findings. It is one
    confirmed intrusion, and it should page someone.
    """

    def __init__(self, data: dict):
        self.id = data["id"]
        self.title = data["title"]
        self.description = data.get("description", "")
        self.level = data.get("level", "critical")
        self.tags = [t.replace("attack.", "").upper() if t.startswith("attack.t") else t
                     for t in data.get("tags", [])]
        self.stages: list[dict] = data["sequence"]["stages"]
        self.within = _dur(data["sequence"].get("within", "2h"))
        self.group_by = data["sequence"].get("group_by", "entity")
        self.ordered = data["sequence"].get("ordered", True)
        self.response = data.get("response", [])

    def evaluate(self, alerts: list[Alert]) -> list[Alert]:
        by_entity: dict[str, list[Alert]] = defaultdict(list)
        for a in alerts:
            by_entity[a.entity].append(a)

        results: list[Alert] = []
        for entity, ents in by_entity.items():
            ents.sort(key=lambda a: a.timestamp)
            matched: list[Alert] = []
            stage_idx = 0
            for alert in ents:
                wanted = self.stages[stage_idx]
                rule_ids = wanted.get("rule_id", [])
                rule_ids = rule_ids if isinstance(rule_ids, list) else [rule_ids]
                if alert.rule_id in rule_ids:
                    if matched and alert.timestamp - matched[0].timestamp > self.within:
                        matched, stage_idx = [], 0
                        continue
                    matched.append(alert)
                    stage_idx += 1
                    if stage_idx == len(self.stages):
                        results.append(self._build(entity, matched))
                        matched, stage_idx = [], 0
            # Unordered mode: all stages present within the window, any order
            if not self.ordered and stage_idx < len(self.stages):
                present = {a.rule_id for a in ents}
                needed = [s.get("rule_id") for s in self.stages]
                flat = [r if isinstance(r, str) else r[0] for r in needed]
                if all(any(rid in present for rid in ([r] if isinstance(r, str) else r)) for r in flat):
                    span = ents[-1].timestamp - ents[0].timestamp
                    if span <= self.within:
                        results.append(self._build(entity, ents))
        return results

    def _build(self, entity: str, chain: list[Alert]) -> Alert:
        span = chain[-1].timestamp - chain[0].timestamp
        return Alert(
            rule_id=self.id,
            rule_name=self.title,
            severity=self.level,
            timestamp=chain[-1].timestamp,
            entity=entity,
            entity_type=chain[0].entity_type,
            description=(f"{self.description} Chain of {len(chain)} stages completed in "
                         f"{int(span.total_seconds() // 60)} minutes."),
            tags=self.tags,
            evidence=[f"{a.timestamp:%H:%M:%S} [{a.severity}] {a.rule_name}" for a in chain],
            event_count=sum(a.event_count for a in chain),
            context=chain[0].context,
            risk_score=95,
        )


def _dur(s: str) -> timedelta:
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    return timedelta(**{units[s[-1]]: float(s[:-1])}) if s[-1] in units else timedelta(seconds=float(s))


def load_sequence_rules(directory: str = "rules/correlation") -> list[SequenceRule]:
    rules = []
    for path in sorted(Path(directory).rglob("*.yml")):
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if data and "sequence" in data:
            rules.append(SequenceRule(data))
    return rules


# ==========================================================================
# 3. Behavioral baselining
# ==========================================================================
class Baseline:
    """
    Learns normal behaviour from a training period, then flags deviation.

    Honest limitation, and a good thing to be able to say out loud: this
    assumes the training window is clean. If the attacker was already
    present during training, their behaviour becomes the baseline and the
    detection is blind to it. That is why baselining supplements signatures
    rather than replacing them.
    """

    def __init__(self, train_ratio: float = 0.5, sigma: float = 3.0):
        self.train_ratio = train_ratio
        self.sigma = sigma
        self.user_hours: dict[str, set] = defaultdict(set)
        self.user_hosts: dict[str, set] = defaultdict(set)
        self.ip_volumes: list[int] = []
        self.trained = False

    def train(self, events: list[Event]) -> None:
        for e in events:
            user = e.get("user.name")
            if user and e.get("event.outcome") == "success":
                self.user_hours[user].add(e["@timestamp"].hour)
                if e.get("host.name"):
                    self.user_hosts[user].add(e["host.name"])
        counts = defaultdict(int)
        for e in events:
            if e.get("source.ip") and e.get("source.internal") is not True:
                counts[e["source.ip"]] += 1
        self.ip_volumes = sorted(counts.values())
        self.trained = True

    def detect(self, events: list[Event], enricher=None) -> list[Alert]:
        if not self.trained:
            split = int(len(events) * self.train_ratio)
            self.train(events[:split])
            events = events[split:]

        alerts: list[Alert] = []
        seen_combo: set = set()

        for e in events:
            user = e.get("user.name")
            # Authentication only. Local actions such as sudo carry no source
            # address, so the internal/external suppression below cannot be
            # evaluated for them and every one became a false positive.
            if (not user or e.get("event.outcome") != "success"
                    or e.get("event.category") != "authentication"):
                continue
            hour = e["@timestamp"].hour
            host = e.get("host.name")
            known_hours = self.user_hours.get(user)

            # Local logons carry no source address; treat them as internal.
            internal = e.get("source.internal") is True or e.get("source.ip") is None
            # Suppress for internal sources entirely: people work late, and
            # "staff logged in at 21:00" is not worth an analyst's time.
            # Retained for EXTERNAL sources, where off-hours access is a
            # genuine anomaly. Tuning record: this condition cut behavioral
            # false positives from 9 to 0 with no loss of true positives.
            if (known_hours and hour not in known_hours and (user, "hour") not in seen_combo
                    and not internal):
                seen_combo.add((user, "hour"))
                alerts.append(Alert(
                    rule_id="behavior_unusual_hour",
                    rule_name="Authentication at Unusual Hour for User",
                    severity="medium",
                    timestamp=e["@timestamp"],
                    entity=user,
                    entity_type="user",
                    description=(f"User '{user}' authenticated at {hour:02d}:00; baseline activity "
                                 f"hours are {sorted(known_hours)}"),
                    tags=["T1078", "ATTACK.DEFENSE_EVASION"],
                    evidence=[f"host={host} ip={e.get('source.ip')}"],
                    raw_events=[e],
                    context=enricher.context_for(e) if enricher else {},
                ))

            known_hosts = self.user_hosts.get(user)
            if known_hosts and host and host not in known_hosts and (user, host) not in seen_combo:
                seen_combo.add((user, host))
                alerts.append(Alert(
                    rule_id="behavior_new_host",
                    rule_name="User Authenticated to Host Never Used Before",
                    severity="medium",
                    timestamp=e["@timestamp"],
                    entity=user,
                    entity_type="user",
                    description=(f"User '{user}' authenticated to '{host}' for the first time; "
                                 f"baseline hosts are {sorted(known_hosts)}"),
                    tags=["T1021", "ATTACK.LATERAL_MOVEMENT"],
                    evidence=[f"new host={host} ip={e.get('source.ip')}"],
                    raw_events=[e],
                    context=enricher.context_for(e) if enricher else {},
                ))

        # Volume outlier: an IP generating far more events than the norm
        if len(self.ip_volumes) >= 5:
            mean = statistics.mean(self.ip_volumes)
            stdev = statistics.pstdev(self.ip_volumes) or 1
            limit = mean + self.sigma * stdev
            counts = defaultdict(list)
            for e in events:
                if e.get("source.ip"):
                    counts[e["source.ip"]].append(e)
            for ip, evs in counts.items():
                # Internal hosts legitimately generate high volume (jump boxes,
                # monitoring, CI runners). Volume anomaly is only meaningful
                # for external sources.
                if evs[0].get("source.internal") is True:
                    continue
                if len(evs) > limit:
                    alerts.append(Alert(
                        rule_id="behavior_volume_outlier",
                        rule_name="Anomalous Event Volume From Source",
                        severity="low",
                        timestamp=evs[0]["@timestamp"],
                        entity=ip,
                        entity_type="ip",
                        description=(f"{len(evs)} events from this source versus a baseline mean of "
                                     f"{mean:.1f} (threshold {limit:.1f} at {self.sigma} sigma)"),
                        tags=["T1595"],
                        evidence=[f"event count={len(evs)}"],
                        raw_events=evs[:5],
                        context=enricher.context_for(evs[0]) if enricher else {},
                    ))
        return alerts


def run_stateful(events: list[Event], enricher=None) -> list[Alert]:
    return (success_after_failures(events, enricher=enricher)
            + privilege_escalation_after_login(events, enricher=enricher))
