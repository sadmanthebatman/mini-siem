"""
rules_engine.py - Sigma-compatible detection engine.

Rules are YAML, not Python. That matters for three reasons:
  1. A detection engineer can add coverage without touching code.
  2. Rules are reviewable in a pull request as data.
  3. The syntax is a subset of Sigma, so rules convert to Splunk SPL,
     Elastic KQL or OpenSearch queries with sigma-cli.

Supported Sigma features:
  - selection / filter blocks, AND across keys, OR across list values
  - field modifiers: contains, startswith, endswith, re, gt, gte, lt, lte, all
  - condition: "selection and not filter", "selection"
  - threshold aggregation: count/distinct over a sliding time window
  - null matching and boolean matching
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from .models import Alert, Event

# --------------------------------------------------------------------------
# Field matching
# --------------------------------------------------------------------------
def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


def _cmp(value: Any, expected: Any, modifier: str | None) -> bool:
    """Compare one event field against one expected value with a Sigma modifier."""
    if value is None:
        return expected is None
    if modifier is None:
        if isinstance(expected, bool) or isinstance(value, bool):
            return bool(value) is bool(expected)
        if isinstance(expected, (int, float)) and not isinstance(expected, bool):
            try:
                return float(value) == float(expected)
            except (TypeError, ValueError):
                return False
        return str(value).lower() == str(expected).lower()

    sval = str(value).lower()
    if modifier == "contains":
        return str(expected).lower() in sval
    if modifier == "startswith":
        return sval.startswith(str(expected).lower())
    if modifier == "endswith":
        return sval.endswith(str(expected).lower())
    if modifier == "re":
        return re.search(str(expected), str(value), re.IGNORECASE) is not None
    try:
        num = float(value)
        exp = float(expected)
    except (TypeError, ValueError):
        return False
    return {"gt": num > exp, "gte": num >= exp, "lt": num < exp, "lte": num <= exp}.get(modifier, False)


def match_block(event: Event, block: dict) -> bool:
    """
    All keys in a block are ANDed. Values within a key are ORed
    (unless the |all modifier is present). This mirrors Sigma semantics.
    """
    for key, expected in block.items():
        parts = key.split("|")
        field = parts[0]
        modifiers = parts[1:]
        require_all = "all" in modifiers
        modifier = next((m for m in modifiers if m != "all"), None)
        value = event.get_path(field)
        results = [_cmp(value, exp, modifier) for exp in _as_list(expected)]
        if not (all(results) if require_all else any(results)):
            return False
    return True


# --------------------------------------------------------------------------
# Rule
# --------------------------------------------------------------------------
class Rule:
    def __init__(self, data: dict, path: Path | None = None):
        self.path = path
        self.id: str = data["id"]
        self.title: str = data["title"]
        self.description: str = data.get("description", "")
        self.level: str = data.get("level", "medium")
        self.status: str = data.get("status", "experimental")
        self.tags: list[str] = [t.replace("attack.", "").upper() if t.startswith("attack.t") else t
                                for t in data.get("tags", [])]
        self.author: str = data.get("author", "")
        self.references: list[str] = data.get("references", [])
        self.false_positives: list[str] = data.get("falsepositives", [])
        self.response: list[str] = data.get("response", [])
        self.detection: dict = data["detection"]
        self.condition: str = str(self.detection.get("condition", "selection"))
        self.threshold: dict | None = self.detection.get("threshold")
        self.entity_field: str = data.get("entity", "source.ip")
        self.enabled: bool = data.get("enabled", True)
        self.evidence_fields: list[str] = data.get("evidence_fields", ["message"])

    # ---------- per-event matching ----------
    def matches(self, event: Event) -> bool:
        """Evaluate the condition string against this event."""
        blocks = {k: v for k, v in self.detection.items()
                  if k not in ("condition", "threshold")}
        cond = self.condition.replace("|", " ").strip()
        # Supported forms: "selection", "selection and not filter",
        # "selection1 or selection2", "all of selection*"
        if cond.startswith("all of "):
            prefix = cond[7:].rstrip("*")
            return all(match_block(event, b) for name, b in blocks.items() if name.startswith(prefix))
        if cond.startswith("1 of ") or cond.startswith("any of "):
            prefix = cond.split("of ", 1)[1].rstrip("*")
            return any(match_block(event, b) for name, b in blocks.items() if name.startswith(prefix))

        tokens = cond.split()
        result: bool | None = None
        op = "and"
        negate = False
        for tok in tokens:
            if tok in ("and", "or"):
                op = tok
            elif tok == "not":
                negate = True
            else:
                block = blocks.get(tok)
                val = match_block(event, block) if block else False
                if negate:
                    val = not val
                    negate = False
                if result is None:
                    result = val
                else:
                    result = (result and val) if op == "and" else (result or val)
        return bool(result)

    # ---------- evaluation over an event stream ----------
    def evaluate(self, events: list[Event], enricher=None) -> list[Alert]:
        hits = [e for e in events if self.matches(e)]
        if not hits:
            return []
        if self.threshold:
            return self._evaluate_threshold(hits, enricher)
        return [self._alert(e, [e], 1, enricher) for e in hits]

    def _evaluate_threshold(self, hits: list[Event], enricher) -> list[Alert]:
        """
        Sliding-window aggregation.

        count:    N matching events from the same group within the window
        distinct: N distinct values of a field from the same group

        The sliding window is the important bit: a fixed bucket would miss an
        attack that straddles a boundary (5 failures at 11:59, 5 at 12:01).
        """
        th = self.threshold
        group_by: list[str] = th.get("group_by", ["source.ip"])
        window = _parse_duration(th.get("window", "60s"))
        need = int(th.get("count", 5))
        distinct_field: str | None = th.get("distinct")

        groups: dict[tuple, list[Event]] = defaultdict(list)
        for e in hits:
            key = tuple(str(e.get_path(f)) for f in group_by)
            groups[key].append(e)

        alerts: list[Alert] = []
        for key, evs in groups.items():
            evs.sort(key=lambda e: e["@timestamp"])
            left = 0
            for right in range(len(evs)):
                while evs[right]["@timestamp"] - evs[left]["@timestamp"] > window:
                    left += 1
                window_events = evs[left:right + 1]
                if distinct_field:
                    uniq = {str(e.get_path(distinct_field)) for e in window_events}
                    reached = len(uniq) >= need
                    measure = f"{len(uniq)} distinct {distinct_field}"
                else:
                    reached = len(window_events) >= need
                    measure = f"{len(window_events)} events"
                if reached:
                    # Report the full group, not just the window, so the
                    # analyst sees the true scale of the activity.
                    alerts.append(self._alert(evs[0], evs, len(evs), enricher,
                                              measure=measure, window=window))
                    break
        return alerts

    def _alert(self, first: Event, evs: list[Event], count: int, enricher,
               measure: str = "", window: timedelta | None = None) -> Alert:
        # Entity resolution with fallback. Windows events frequently carry no
        # source address (local logons), and bucketing all of those under
        # "unknown" merges unrelated activity into one meaningless entity.
        entity = first.get_path(self.entity_field)
        field_used = self.entity_field
        if entity in (None, "", "-"):
            for fallback in ("host.name", "user.name"):
                entity = first.get_path(fallback)
                if entity:
                    field_used = fallback
                    break
        entity = str(entity or "unattributed")
        entity_type = ("ip" if "ip" in field_used
                       else "user" if "user" in field_used else "host")
        desc = self.description or self.title
        if measure:
            desc = f"{desc} ({measure} within {_fmt_duration(window)})"
        evidence = []
        for e in evs[:5]:
            parts = [f"{f}={e.get_path(f)}" for f in self.evidence_fields if e.get_path(f) is not None]
            evidence.append(" ".join(parts) if parts else str(e.get("message", ""))[:160])
        return Alert(
            rule_id=self.id,
            rule_name=self.title,
            severity=self.level,
            timestamp=first["@timestamp"],
            entity=entity,
            entity_type=entity_type,
            description=desc,
            tags=self.tags,
            evidence=evidence,
            event_count=count,
            raw_events=evs,
            context=enricher.context_for(first) if enricher else {},
        )


# --------------------------------------------------------------------------
# Helpers and loading
# --------------------------------------------------------------------------
def _parse_duration(s: str | int) -> timedelta:
    if isinstance(s, (int, float)):
        return timedelta(seconds=float(s))
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    unit = s[-1].lower()
    if unit not in units:
        return timedelta(seconds=float(s))
    return timedelta(**{units[unit]: float(s[:-1])})


def _fmt_duration(td: timedelta | None) -> str:
    if not td:
        return "window"
    secs = int(td.total_seconds())
    if secs % 86400 == 0:
        return f"{secs // 86400}d"
    if secs % 3600 == 0:
        return f"{secs // 3600}h"
    if secs % 60 == 0:
        return f"{secs // 60}m"
    return f"{secs}s"


class RuleSet:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    @classmethod
    def load(cls, directory: str = "rules") -> "RuleSet":
        rules: list[Rule] = []
        for path in sorted(Path(directory).rglob("*.yml")):
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if not data or "detection" not in data:
                continue  # correlation/behavioral rules are loaded elsewhere
            rule = Rule(data, path)
            if rule.enabled:
                rules.append(rule)
        return cls(rules)

    def run(self, events: list[Event], enricher=None) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            alerts.extend(rule.evaluate(events, enricher))
        return alerts

    def coverage(self) -> dict[str, list[str]]:
        """ATT&CK technique -> rules covering it. Drives the coverage report."""
        cov: dict[str, list[str]] = defaultdict(list)
        for rule in self.rules:
            for tag in rule.tags:
                if tag.upper().startswith("T"):
                    cov[tag.upper()].append(rule.title)
        return dict(sorted(cov.items()))

    def __len__(self):
        return len(self.rules)
