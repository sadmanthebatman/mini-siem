"""
stream.py - Real-time detection on a live log tail.

Batch analysis tells you what happened yesterday. Streaming tells you it is
happening now, which is the difference between incident response and archaeology.

HOW IT WORKS

Each source file is tailed like `tail -f`. New lines are parsed, enriched and
pushed into a sliding event window held in memory. Only the window matters:
events older than the longest rule window are evicted, so memory stays flat no
matter how long the process runs.

When an event arrives, only the rules that could possibly match it are
re-evaluated, and only against the events sharing its group key (usually the
source IP). That is what makes this incremental rather than "re-run everything
every second".

Alert fingerprints are remembered so each finding is emitted exactly once, no
matter how many times its window is re-evaluated.

WHAT IT HANDLES

  - Log rotation (inode change and truncation both detected)
  - Resume after restart: byte offsets are checkpointed to disk
  - Partial lines: a line still being written is held until its newline arrives
  - Backpressure: a batch cap per poll so a 100k-line burst cannot stall the loop

HONEST LIMITS

  This is single-process and in-memory. A production deployment puts Kafka
  between collection and processing so events survive a restart and multiple
  consumers can scale out. The stage boundaries here are drawn where that
  queue would go, which is the point of structuring it this way.
"""
from __future__ import annotations

import json
import os
import signal
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterator

from .correlation import SequenceRule, load_sequence_rules
from .enrich import Enricher
from .models import Alert, Event
from .parsers import PARSERS, SOURCE_CHAINS
from .risk import PlaybookRunner, RiskEngine
from .rules_engine import RuleSet, _parse_duration

DEFAULT_WINDOW = timedelta(minutes=30)
CHECKPOINT = ".siem_stream_state.json"


# ==========================================================================
# File tailing
# ==========================================================================
@dataclass
class TailedFile:
    """
    One followed log file.

    Rotation is detected two ways: the inode changes (logrotate moved the file
    and created a new one), or the file shrank below our offset (it was
    truncated in place). Both reset us to the start of the new file.
    """
    path: Path
    source: str
    offset: int = 0
    inode: int | None = None
    _buffer: str = ""
    missing_logged: bool = False

    def read_new_lines(self, max_lines: int = 5000) -> list[str]:
        if not self.path.exists():
            if not self.missing_logged:
                self.missing_logged = True
            return []
        self.missing_logged = False
        stat = self.path.stat()

        if self.inode is None:
            self.inode = stat.st_ino
        elif stat.st_ino != self.inode:
            self.inode, self.offset, self._buffer = stat.st_ino, 0, ""
        elif stat.st_size < self.offset:
            self.offset, self._buffer = 0, ""

        if stat.st_size == self.offset:
            return []

        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self.offset)
            chunk = fh.read(max_lines * 2048)
            self.offset = fh.tell()

        data = self._buffer + chunk
        lines = data.split("\n")
        # The last element is either empty (clean break) or a partial line
        # still being written. Hold it until its newline arrives.
        self._buffer = lines.pop()
        return [ln for ln in lines if ln.strip()]


class Checkpoint:
    """Persist byte offsets so a restart resumes instead of re-alerting."""

    def __init__(self, path: str = CHECKPOINT):
        self.path = Path(path)

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def save(self, files: list[TailedFile]) -> None:
        state = {str(f.path): {"offset": f.offset, "inode": f.inode} for f in files}
        try:
            self.path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        except OSError:
            pass


# ==========================================================================
# Incremental detection
# ==========================================================================
class StreamEngine:
    """
    Holds a sliding window of events and evaluates rules incrementally.

    State kept per run:
      window        deque of recent events, trimmed by time
      by_group      index of events per (rule, group key) for fast re-eval
      seen          alert fingerprints already emitted
      auth_state    prior-failure tracking for success-after-failures
    """

    def __init__(self, rules_dir: str = "rules", config_dir: str = "config",
                 window: timedelta | None = None, case_threshold: int = 100):
        self.ruleset = RuleSet.load(rules_dir)
        self.sequences: list[SequenceRule] = load_sequence_rules(f"{rules_dir}/correlation")
        self.enricher = Enricher(config_dir)
        self.risk = RiskEngine(case_threshold=case_threshold)
        self.playbooks = PlaybookRunner(dry_run=True)

        # Window must cover the longest rule window, or threshold rules would
        # evaluate against events we already evicted.
        longest = DEFAULT_WINDOW
        for rule in self.ruleset.rules:
            if rule.threshold:
                w = _parse_duration(rule.threshold.get("window", "60s"))
                longest = max(longest, w)
        self.window = window or (longest + timedelta(minutes=5))

        self.events: deque[Event] = deque()
        self.seen_fingerprints: set[str] = set()
        self.alerts: list[Alert] = []
        self.auth_failures: dict[str, list[Event]] = defaultdict(list)
        self.stats = {"events": 0, "alerts": 0, "cases": 0, "skipped": 0}
        self.open_case_ids: set[str] = set()

    # ------------------------------------------------------------------
    def _trim(self, now: datetime) -> None:
        cutoff = now - self.window
        while self.events and self.events[0]["@timestamp"] < cutoff:
            self.events.popleft()

    def _new_alerts(self, alerts: list[Alert]) -> list[Alert]:
        fresh = []
        for a in alerts:
            if a.fingerprint not in self.seen_fingerprints:
                self.seen_fingerprints.add(a.fingerprint)
                fresh.append(a)
        return fresh

    # ------------------------------------------------------------------
    def _stateful_auth(self, event: Event) -> list[Alert]:
        """Streaming version of success-after-failures. Naturally incremental."""
        if event.get("event.category") != "authentication":
            return []
        ip = event.get("source.ip")
        if not ip:
            return []
        now = event["@timestamp"]
        window = timedelta(minutes=10)
        self.auth_failures[ip] = [f for f in self.auth_failures[ip]
                                  if now - f["@timestamp"] <= window]
        if event.get("event.outcome") == "failure":
            self.auth_failures[ip].append(event)
            return []
        if event.get("event.outcome") == "success" and len(self.auth_failures[ip]) >= 8:
            fails = self.auth_failures[ip]
            tried = {f.get("user.name") for f in fails}
            alert = Alert(
                rule_id="auth_success_after_failures",
                rule_name="Successful Authentication After Repeated Failures",
                severity="critical", timestamp=now, entity=ip, entity_type="ip",
                description=(f"Authentication SUCCEEDED as '{event.get('user.name')}' on "
                             f"{event.get('host.name')} after {len(fails)} failures against "
                             f"{len(tried)} account(s)"),
                tags=["T1078", "T1110"],
                evidence=[f"failed: {f.get('user.name')} at {f['@timestamp']}" for f in fails[-3:]]
                         + [f"SUCCESS: {event.get('user.name')}"],
                event_count=len(fails) + 1, raw_events=fails + [event],
                context=self.enricher.context_for(event))
            self.auth_failures[ip] = []
            return [alert]
        return []

    # ------------------------------------------------------------------
    def feed(self, event: Event) -> list[Alert]:
        """Push one event through the engine and return any NEW alerts."""
        event = self.enricher.enrich(event)
        self.events.append(event)
        self.stats["events"] += 1
        self._trim(event["@timestamp"])

        produced: list[Alert] = []

        # 1. Atomic rules. Only rules whose selection matches THIS event can
        #    newly fire, so we skip the rest entirely - that is the
        #    optimisation that makes streaming viable.
        for rule in self.ruleset.rules:
            if not rule.matches(event):
                continue
            if rule.threshold:
                group_by = rule.threshold.get("group_by", ["source.ip"])
                key = tuple(str(event.get_path(f)) for f in group_by)
                scope = [e for e in self.events
                         if tuple(str(e.get_path(f)) for f in group_by) == key]
                produced.extend(rule.evaluate(scope, self.enricher))
            else:
                produced.extend(rule.evaluate([event], self.enricher))

        # 2. Stateful
        produced.extend(self._stateful_auth(event))

        fresh = self._new_alerts(produced)

        # 3. Sequence correlation over the alerts seen so far
        if fresh:
            self.alerts.extend(fresh)
            chains: list[Alert] = []
            for seq in self.sequences:
                chains.extend(seq.evaluate(self.alerts))
            chain_fresh = self._new_alerts(chains)
            self.alerts.extend(chain_fresh)
            fresh.extend(chain_fresh)

        # 4. Risk scoring and case creation
        if fresh:
            self.stats["alerts"] += len(fresh)
            self.risk.ingest(fresh)
            for case in self.risk.open_cases():
                if case.id not in self.open_case_ids:
                    self.open_case_ids.add(case.id)
                    self.stats["cases"] += 1
                    self.playbooks.write_case_file(case)
                    self.playbooks.notify(case)
                    fresh.append(_case_marker(case))
        return fresh


def _case_marker(case) -> Alert:
    """A pseudo-alert so the console can announce case creation inline."""
    return Alert(rule_id="__case__", rule_name=f"CASE OPENED {case.id}",
                 severity=case.severity, timestamp=case.opened_at,
                 entity=case.entity.id, entity_type=case.entity.type,
                 description=f"{case.title} | SLA {case.sla_hours}h | "
                             f"risk {case.entity.score:.0f}",
                 evidence=case.recommended_actions[:3])


# ==========================================================================
# Runner
# ==========================================================================
COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m",
          "low": "\033[1;36m", "informational": "\033[0;37m",
          "dim": "\033[2m", "bold": "\033[1m", "green": "\033[1;32m", "reset": "\033[0m"}


class StreamRunner:
    def __init__(self, inputs: dict[str, str], rules_dir="rules", config_dir="config",
                 interval: float = 1.0, year: int = 2026, color: bool = True,
                 from_start: bool = False, sink: str | None = None,
                 on_alert: Callable[[Alert], None] | None = None):
        self.engine = StreamEngine(rules_dir, config_dir)
        self.interval = interval
        self.year = year
        self.c = COLORS if color else {k: "" for k in COLORS}
        self.sink = Path(sink) if sink else None
        self.on_alert = on_alert
        self.running = True
        self.started = datetime.now()

        checkpoint = Checkpoint()
        saved = {} if from_start else checkpoint.load()
        self.checkpoint = checkpoint
        self.files: list[TailedFile] = []
        for path, source in inputs.items():
            p = Path(path)
            prior = saved.get(str(p), {})
            offset = prior.get("offset", 0)
            if from_start:
                offset = 0
            elif not prior and p.exists():
                # No checkpoint: start at EOF so we report live activity only,
                # not a replay of the entire historical file.
                offset = p.stat().st_size
            self.files.append(TailedFile(p, source, offset=offset,
                                         inode=prior.get("inode")))

    # ------------------------------------------------------------------
    def _parse(self, line: str, source: str) -> Event | None:
        for name in SOURCE_CHAINS.get(source, [source]):
            parser = PARSERS.get(name)
            if parser:
                ev = parser(line, self.year)
                if ev:
                    return ev
        return None

    def _emit(self, alert: Alert) -> None:
        c = self.c
        ts = alert.timestamp.strftime("%H:%M:%S")
        if alert.rule_id == "__case__":
            print(f"\n{c['bold']}{c[alert.severity]} ▶ {alert.rule_name} {c['reset']} "
                  f"{alert.description}")
            for act in alert.evidence:
                print(f"    {c['dim']}→ {act}{c['reset']}")
            print()
        else:
            tags = ",".join(t for t in alert.tags if t.upper().startswith("T"))
            print(f"{c['dim']}{ts}{c['reset']} {c[alert.severity]}{alert.severity.upper():<9}"
                  f"{c['reset']} {c['bold']}{alert.rule_name}{c['reset']} "
                  f"{c['dim']}←{c['reset']} {alert.entity}"
                  + (f"  {c['dim']}[{tags}]{c['reset']}" if tags else ""))
            if alert.description:
                print(f"           {c['dim']}{alert.description[:120]}{c['reset']}")
        sys.stdout.flush()

        if self.sink:
            with open(self.sink, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(alert.to_ecs(), default=str) + "\n")
        if self.on_alert:
            self.on_alert(alert)

    def _status(self) -> None:
        c = self.c
        up = int((datetime.now() - self.started).total_seconds())
        s = self.engine.stats
        print(f"\r{c['dim']}[{up//60:02d}:{up%60:02d}] events {s['events']}  "
              f"alerts {s['alerts']}  cases {s['cases']}  "
              f"window {len(self.engine.events)} events{c['reset']}   ", end="")
        sys.stdout.flush()

    # ------------------------------------------------------------------
    def stop(self, *_):
        self.running = False

    def run(self, max_seconds: float | None = None) -> dict:
        c = self.c
        signal.signal(signal.SIGINT, self.stop)
        try:
            signal.signal(signal.SIGTERM, self.stop)
        except (ValueError, AttributeError):
            pass

        print(f"{c['bold']}STREAMING{c['reset']}  "
              f"{len(self.files)} source(s), window {int(self.engine.window.total_seconds()//60)}m, "
              f"{len(self.engine.ruleset)} rules + {len(self.engine.sequences)} chains")
        for f in self.files:
            print(f"  {c['dim']}tail{c['reset']} {f.path}  "
                  f"{c['dim']}({f.source}, from byte {f.offset}){c['reset']}")
        print(f"{c['dim']}Ctrl-C to stop{c['reset']}\n")

        deadline = time.time() + max_seconds if max_seconds else None
        last_status = 0.0
        try:
            while self.running:
                batch: list[tuple[Event, str]] = []
                for f in self.files:
                    for line in f.read_new_lines():
                        ev = self._parse(line, f.source)
                        if ev:
                            ev["log.file.path"] = str(f.path)
                            batch.append((ev, f.source))
                        else:
                            self.engine.stats["skipped"] += 1

                # Order matters: windows and stateful logic assume time order.
                batch.sort(key=lambda pair: pair[0]["@timestamp"])
                for ev, _src in batch:
                    for alert in self.engine.feed(ev):
                        print("\r" + " " * 78 + "\r", end="")
                        self._emit(alert)

                if batch:
                    self.checkpoint.save(self.files)
                if time.time() - last_status > 1.0:
                    self._status()
                    last_status = time.time()
                if deadline and time.time() > deadline:
                    break
                time.sleep(self.interval)
        except KeyboardInterrupt:
            pass

        self.checkpoint.save(self.files)
        s = self.engine.stats
        print(f"\n\n{c['bold']}STOPPED{c['reset']}  events {s['events']}  "
              f"alerts {s['alerts']}  cases {s['cases']}  unparsed {s['skipped']}")
        if self.engine.risk.entities:
            print(f"\n{c['bold']}TOP RISK ENTITIES{c['reset']}")
            for ent in self.engine.risk.ranked()[:5]:
                col = c["critical"] if ent.score >= 180 else c["high"] if ent.score >= 100 else c["low"]
                print(f"  {ent.id:<22}{col}{ent.score:>7.0f}{c['reset']}  "
                      f"{len(ent.alerts)} alerts  {c['dim']}{', '.join(ent.techniques[:5])}{c['reset']}")
        return s


# ==========================================================================
# Replay: feed a historical file through the streaming engine at speed
# ==========================================================================
def replay(inputs: dict[str, str], speed: float = 0.0, rules_dir="rules",
           config_dir="config", year: int = 2026, color: bool = True,
           limit: int | None = None) -> dict:
    """
    Push existing log files through the STREAMING engine in timestamp order,
    so you can watch an attack unfold without waiting for live traffic.

    speed=0 runs as fast as possible; speed=1.0 replays in real time; 60 means
    one simulated minute per real second.
    """
    from .parsers import parse_many

    engine = StreamEngine(rules_dir, config_dir)
    c = COLORS if color else {k: "" for k in COLORS}
    events, _stats = parse_many(inputs, year=year)
    if limit:
        events = events[:limit]

    print(f"{c['bold']}REPLAY{c['reset']}  {len(events)} events through the streaming engine"
          + (f" at {speed}x" if speed else " at full speed") + "\n")

    runner = StreamRunner.__new__(StreamRunner)   # reuse the emitter only
    runner.c, runner.sink, runner.on_alert, runner.engine = c, None, None, engine

    previous: datetime | None = None
    for ev in events:
        if speed and previous:
            delay = (ev["@timestamp"] - previous).total_seconds() / speed
            if 0 < delay < 5:
                time.sleep(delay)
        previous = ev["@timestamp"]
        for alert in engine.feed(ev):
            runner._emit(alert)

    s = engine.stats
    print(f"\n{c['bold']}REPLAY COMPLETE{c['reset']}  events {s['events']}  "
          f"alerts {s['alerts']}  cases {s['cases']}")
    if engine.risk.entities:
        print(f"\n{c['bold']}TOP RISK ENTITIES{c['reset']}")
        for ent in engine.risk.ranked()[:8]:
            col = c["critical"] if ent.score >= 180 else c["high"] if ent.score >= 100 else c["low"]
            print(f"  {ent.id:<22}{col}{ent.score:>7.0f}{c['reset']}  {len(ent.alerts)} alerts  "
                  f"{c['dim']}{', '.join(ent.techniques[:5])}{c['reset']}")
    return s
