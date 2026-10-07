"""
pipeline.py - The orchestrator.

    ingest -> normalize (ECS) -> enrich -> detect -> correlate -> score -> respond

Each stage is independently testable, which is why the CI metrics harness can
feed labelled events straight into the detect stage without touching parsers.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .correlation import Baseline, load_sequence_rules, run_stateful
from .enrich import Enricher
from .models import Alert, Case, Event
from .risk import PlaybookRunner, RiskEngine
from .rules_engine import RuleSet
from .parsers import parse_many


@dataclass
class PipelineResult:
    events: list[Event] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    cases: list[Case] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)
    risk_engine: RiskEngine | None = None

    def summary(self) -> dict:
        by_sev: dict[str, int] = {}
        for a in self.alerts:
            by_sev[a.severity] = by_sev.get(a.severity, 0) + 1
        return {
            "events_parsed": len(self.events),
            "alerts": len(self.alerts),
            "alerts_by_severity": by_sev,
            "entities_scored": len(self.risk_engine.entities) if self.risk_engine else 0,
            "cases_opened": len(self.cases),
            "techniques_covered": len(self.coverage),
            "actions_recorded": len(self.actions),
        }


class Pipeline:
    def __init__(self, rules_dir: str = "rules", config_dir: str = "config",
                 behavioral: bool = True, dry_run: bool = True,
                 case_threshold: int = 100):
        self.ruleset = RuleSet.load(rules_dir)
        self.sequences = load_sequence_rules(f"{rules_dir}/correlation")
        self.enricher = Enricher(config_dir)
        self.behavioral = behavioral
        self.risk = RiskEngine(case_threshold=case_threshold)
        self.playbooks = PlaybookRunner(dry_run=dry_run)

    def run(self, inputs: dict[str, str | None], year: int = 2026) -> PipelineResult:
        result = PipelineResult()

        # 1. Ingest and normalize
        events, parse_stats = parse_many(inputs, year=year)
        result.stats["parsing"] = parse_stats

        # 2. Enrich (must run in time order for first-seen logic)
        events = self.enricher.enrich_all(events)
        result.events = events

        # 3. Atomic detections (YAML/Sigma rules)
        atomic = self.ruleset.run(events, self.enricher)

        # 4. Stateful + behavioral detections
        stateful = run_stateful(events, self.enricher)
        behavioral: list[Alert] = []
        if self.behavioral and len(events) > 40:
            behavioral = Baseline().detect(events, self.enricher)

        alerts = atomic + stateful + behavioral

        # 5. Sequence correlation runs over the alerts produced above
        chains: list[Alert] = []
        for seq in self.sequences:
            chains.extend(seq.evaluate(alerts))
        alerts += chains

        # Deduplicate by fingerprint; identical findings in the same hour
        # are one alert, not many. Analysts drown without this.
        unique: dict[str, Alert] = {}
        for a in alerts:
            if a.fingerprint not in unique:
                unique[a.fingerprint] = a
        alerts = sorted(unique.values(), key=lambda a: a.timestamp)
        result.alerts = alerts
        result.stats["detections"] = {
            "atomic": len(atomic), "stateful": len(stateful),
            "behavioral": len(behavioral), "correlation": len(chains),
            "after_dedup": len(alerts),
        }

        # 6. Risk scoring and case creation
        self.risk.ingest(alerts)
        result.risk_engine = self.risk
        result.cases = self.risk.open_cases()

        # 7. Response playbooks
        result.actions = self.playbooks.run(result.cases)

        result.coverage = self.ruleset.coverage()
        result.stats["rules_loaded"] = {
            "atomic": len(self.ruleset), "sequence": len(self.sequences),
        }
        return result

    # ---------------- outputs ----------------
    @staticmethod
    def export(result: PipelineResult, out_dir: str = "out") -> dict[str, str]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        written: dict[str, str] = {}

        # ECS signals as NDJSON (one doc per line, ready for _bulk)
        signals = out / "alerts.ndjson"
        with open(signals, "w", encoding="utf-8") as fh:
            for a in result.alerts:
                fh.write(json.dumps(a.to_ecs(), default=str) + "\n")
        written["alerts"] = str(signals)

        # OpenSearch bulk file: action line + document line
        bulk = out / "opensearch_bulk.ndjson"
        with open(bulk, "w", encoding="utf-8") as fh:
            for a in result.alerts:
                fh.write(json.dumps({"index": {"_index": "siem-signals",
                                               "_id": a.fingerprint}}) + "\n")
                fh.write(json.dumps(a.to_ecs(), default=str) + "\n")
            for e in result.events:
                fh.write(json.dumps({"index": {"_index": "siem-events"}}) + "\n")
                fh.write(e.to_json() + "\n")
        written["bulk"] = str(bulk)

        # Cases
        cases = out / "cases.json"
        with open(cases, "w", encoding="utf-8") as fh:
            json.dump([c.to_dict() for c in result.cases], fh, indent=2)
        written["cases"] = str(cases)

        # Run summary for CI and the README metrics table
        summary = out / "summary.json"
        with open(summary, "w", encoding="utf-8") as fh:
            json.dump({"generated_at": datetime.now().isoformat(timespec="seconds"),
                       **result.summary(), "stats": result.stats,
                       "attack_coverage": result.coverage}, fh, indent=2, default=str)
        written["summary"] = str(summary)
        return written
