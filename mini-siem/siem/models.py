"""
models.py - Core data structures.

Everything in this SIEM speaks Elastic Common Schema (ECS). A Windows 4625
and a Linux "Failed password" both become the same shape, so one detection
rule covers both. That single decision is what makes this a SIEM rather than
a pile of per-logtype scripts.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any

# --------------------------------------------------------------------------
# ECS event
# --------------------------------------------------------------------------
class Event(dict):
    """
    A dict of dotted ECS field paths -> values.

    We deliberately keep flat dotted keys ("source.ip") rather than nested
    dicts: rules reference fields by dotted path, and flat lookup keeps the
    matcher simple and fast.
    """

    @property
    def timestamp(self) -> datetime:
        return self["@timestamp"]

    @property
    def source_ip(self) -> str | None:
        return self.get("source.ip")

    def get_path(self, path: str) -> Any:
        """Lookup supporting both flat dotted keys and nested dicts."""
        if path in self:
            return self[path]
        node: Any = self
        for part in path.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node

    def to_nested(self) -> dict:
        """Expand dotted keys into nested JSON for OpenSearch/Elastic."""
        out: dict = {}
        # Longest paths first so a leaf never blocks a deeper branch, and any
        # genuine collision degrades to a flat key instead of raising.
        for key, value in sorted(self.items(), key=lambda kv: -kv[0].count(".")):
            value = value.isoformat() if isinstance(value, datetime) else value
            parts = key.split(".")
            node = out
            ok = True
            for part in parts[:-1]:
                nxt = node.setdefault(part, {})
                if not isinstance(nxt, dict):
                    ok = False
                    break
                node = nxt
            if ok and not isinstance(node.get(parts[-1]), dict):
                node[parts[-1]] = value
            else:
                out[key] = value
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_nested(), default=str, separators=(",", ":"))


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------
SEVERITY_SCORE = {"critical": 90, "high": 60, "medium": 35, "low": 15, "informational": 5}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    severity: str                 # critical | high | medium | low | informational
    timestamp: datetime
    entity: str                   # the thing we are scoring (usually source.ip or user)
    entity_type: str              # ip | user | host
    description: str
    tags: list[str] = field(default_factory=list)       # ATT&CK technique ids
    evidence: list[str] = field(default_factory=list)   # human-readable samples
    event_count: int = 1
    raw_events: list[Event] = field(default_factory=list, repr=False)
    context: dict = field(default_factory=dict)         # enrichment snapshot
    risk_score: int = 0

    def __post_init__(self):
        if not self.risk_score:
            self.risk_score = SEVERITY_SCORE.get(self.severity, 10)

    @property
    def fingerprint(self) -> str:
        """Stable id used for deduplication across runs."""
        basis = f"{self.rule_id}|{self.entity}|{self.timestamp.strftime('%Y-%m-%dT%H')}"
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw_events", None)
        d["timestamp"] = self.timestamp.isoformat()
        d["fingerprint"] = self.fingerprint
        return d

    def to_ecs(self) -> dict:
        """Alert shaped as an ECS signal document, ready for OpenSearch."""
        return {
            "@timestamp": self.timestamp.isoformat(),
            "event": {"kind": "signal", "category": ["intrusion_detection"],
                      "severity": SEVERITY_SCORE.get(self.severity, 10)},
            "rule": {"id": self.rule_id, "name": self.rule_name},
            "signal": {"severity": self.severity, "risk_score": self.risk_score,
                       "fingerprint": self.fingerprint, "count": self.event_count},
            "entity": {"id": self.entity, "type": self.entity_type},
            "threat": {"technique": {"id": [t for t in self.tags if t.lower().startswith("t")]}},
            "message": self.description,
            "evidence": self.evidence[:10],
            "context": self.context,
        }


# --------------------------------------------------------------------------
# Entities and cases
# --------------------------------------------------------------------------
@dataclass
class Entity:
    """An IP, user or host that accumulates risk over time."""
    id: str
    type: str
    score: float = 0.0
    alerts: list[Alert] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def techniques(self) -> list[str]:
        seen: list[str] = []
        for a in self.alerts:
            for t in a.tags:
                if t.lower().startswith("t") and t not in seen:
                    seen.append(t)
        return sorted(seen)

    @property
    def timeline(self) -> list[Alert]:
        return sorted(self.alerts, key=lambda a: a.timestamp)


@dataclass
class Case:
    """What an analyst actually works. Opened when an entity crosses threshold."""
    id: str
    entity: Entity
    severity: str
    opened_at: datetime
    title: str
    summary: str
    recommended_actions: list[str] = field(default_factory=list)
    sla_hours: int = 24

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "opened_at": self.opened_at.isoformat(),
            "entity": {"id": self.entity.id, "type": self.entity.type,
                       "risk_score": round(self.entity.score, 1)},
            "techniques": self.entity.techniques,
            "alert_count": len(self.entity.alerts),
            "summary": self.summary,
            "recommended_actions": self.recommended_actions,
            "sla_hours": self.sla_hours,
            "timeline": [
                {"time": a.timestamp.isoformat(), "rule": a.rule_name,
                 "severity": a.severity, "description": a.description}
                for a in self.entity.timeline
            ],
        }
