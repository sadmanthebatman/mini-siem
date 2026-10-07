"""
cli.py - Command line interface.

    python -m siem.cli analyze --input-dir sample_logs
    python -m siem.cli analyze --auth /var/log/auth.log --nginx /var/log/nginx/access.log
    python -m siem.cli rules --coverage
    python -m siem.cli metrics --input-dir sample_logs
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .models import SEVERITY_ORDER
from .pipeline import Pipeline, PipelineResult

C = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m",
     "low": "\033[1;36m", "informational": "\033[0;37m",
     "bold": "\033[1m", "dim": "\033[2m", "green": "\033[1;32m", "reset": "\033[0m"}
NO_COLOR = {k: "" for k in C}


def hr(ch="─", n=78):
    return ch * n


def print_report(result: PipelineResult, color=True, max_alerts=25):
    c = C if color else NO_COLOR
    s = result.summary()

    print(f"\n{c['bold']}{hr('━')}")
    print("  SIEM ANALYSIS REPORT")
    print(f"{hr('━')}{c['reset']}\n")

    # Ingestion
    print(f"{c['bold']}INGESTION{c['reset']}")
    for path, st in result.stats.get("parsing", {}).items():
        name = Path(path).name
        print(f"  {name:<26} {st['source']:<10} {st['parsed']:>6} parsed  "
              f"{c['dim']}{st['skipped']:>5} skipped{c['reset']}")
    print(f"  {'TOTAL':<26} {'':<10} {s['events_parsed']:>6} events\n")

    # Detections
    d = result.stats.get("detections", {})
    r = result.stats.get("rules_loaded", {})
    print(f"{c['bold']}DETECTION{c['reset']}")
    print(f"  Rules loaded: {r.get('atomic', 0)} atomic + {r.get('sequence', 0)} correlation")
    print(f"  Atomic {d.get('atomic',0)}  |  Stateful {d.get('stateful',0)}  |  "
          f"Behavioral {d.get('behavioral',0)}  |  Correlation {d.get('correlation',0)}")
    sev = s["alerts_by_severity"]
    parts = [f"{c[k]}{k.upper()} {sev.get(k,0)}{c['reset']}"
             for k in ("critical", "high", "medium", "low") if sev.get(k)]
    print(f"  Alerts after dedup: {s['alerts']}   " + "  ".join(parts) + "\n")

    # Top risk entities
    print(f"{c['bold']}TOP RISK ENTITIES{c['reset']}")
    print(f"  {'ENTITY':<22}{'TYPE':<7}{'SCORE':>7}  {'ALERTS':>6}  TECHNIQUES")
    print(f"  {c['dim']}{hr('·', 74)}{c['reset']}")
    for ent in result.risk_engine.ranked()[:10]:
        col = (c["critical"] if ent.score >= 180 else c["high"] if ent.score >= 100
               else c["medium"] if ent.score >= 50 else c["low"])
        techs = ", ".join(ent.techniques[:4]) or "-"
        print(f"  {ent.id:<22}{ent.type:<7}{col}{ent.score:>7.0f}{c['reset']}  "
              f"{len(ent.alerts):>6}  {c['dim']}{techs}{c['reset']}")

    # Cases
    print(f"\n{c['bold']}CASES OPENED ({len(result.cases)}){c['reset']}")
    for case in result.cases:
        col = c[case.severity]
        print(f"\n  {col} {case.severity.upper()} {c['reset']} {c['bold']}{case.id}{c['reset']}"
              f"   SLA {case.sla_hours}h")
        print(f"  {case.title}")
        print(f"  {c['dim']}{case.summary}{c['reset']}")
        print(f"  {c['bold']}Timeline:{c['reset']}")
        for a in case.entity.timeline[:8]:
            print(f"    {a.timestamp:%H:%M:%S}  {c[a.severity]}{a.severity[:4].upper():<5}{c['reset']} "
                  f"{a.rule_name}")
        if len(case.entity.timeline) > 8:
            print(f"    {c['dim']}... {len(case.entity.timeline)-8} more{c['reset']}")
        print(f"  {c['bold']}Recommended actions:{c['reset']}")
        for act in case.recommended_actions[:5]:
            print(f"    → {act}")

    # Alerts
    print(f"\n{c['bold']}ALERT DETAIL{c['reset']}")
    shown = sorted(result.alerts, key=lambda a: (SEVERITY_ORDER[a.severity], a.timestamp))
    for a in shown[:max_alerts]:
        print(f"\n  {c[a.severity]} {a.severity.upper():<9}{c['reset']} {c['bold']}{a.rule_name}{c['reset']}")
        print(f"  {a.timestamp}  entity={a.entity} ({a.entity_type})  risk={a.risk_score}"
              f"  events={a.event_count}")
        print(f"  {a.description}")
        if a.tags:
            print(f"  {c['dim']}ATT&CK: {', '.join(t for t in a.tags if t.startswith('T'))}{c['reset']}")
        if a.context:
            ctx = "  ".join(f"{k.split('.')[-1]}={v}" for k, v in list(a.context.items())[:5])
            print(f"  {c['dim']}context: {ctx}{c['reset']}")
        for ev in a.evidence[:3]:
            print(f"  {c['dim']}  · {ev}{c['reset']}")
    if len(shown) > max_alerts:
        print(f"\n  {c['dim']}... {len(shown)-max_alerts} more alerts (see out/alerts.ndjson){c['reset']}")

    # Response actions
    print(f"\n{c['bold']}RESPONSE ACTIONS{c['reset']}")
    for act in result.actions:
        mark = f"{c['green']}✓{c['reset']}" if act["executed"] else f"{c['dim']}○{c['reset']}"
        print(f"  {mark} {act['action']:<14} {act['target']:<20} {c['dim']}{act['detail']}{c['reset']}")

    # Coverage
    print(f"\n{c['bold']}ATT&CK COVERAGE{c['reset']}  ({len(result.coverage)} techniques)")
    line = "  "
    for tech in result.coverage:
        if len(line) > 70:
            print(line)
            line = "  "
        line += f"{tech}  "
    print(line)
    print(f"\n{c['bold']}{hr('━')}{c['reset']}\n")


def cmd_analyze(args):
    inputs: dict[str, str | None] = {}
    if args.input_dir:
        d = Path(args.input_dir)
        mapping = {"auth.log": "auth", "access.log": "nginx",
                   "windows_security.json": "winlog", "suricata_eve.json": "suricata",
                   "cowrie.json": "cowrie"}
        for name, source in mapping.items():
            if (d / name).exists():
                inputs[str(d / name)] = source
    for flag, source in (("auth", "auth"), ("nginx", "nginx"), ("winlog", "winlog"),
                         ("suricata", "suricata"), ("cowrie", "cowrie")):
        val = getattr(args, flag, None)
        if val:
            inputs[val] = source
    if not inputs:
        print("No input files found. Use --input-dir or a source flag.", file=sys.stderr)
        return 1

    pipe = Pipeline(rules_dir=args.rules, config_dir=args.config,
                    behavioral=not args.no_behavioral, dry_run=not args.live,
                    case_threshold=args.case_threshold)
    result = pipe.run(inputs, year=args.year)
    print_report(result, color=not args.no_color, max_alerts=args.max_alerts)
    written = Pipeline.export(result, args.out)
    print("Exports:")
    for k, v in written.items():
        print(f"  {k:<10} {v}")
    if args.html:
        from .dashboard import render_dashboard
        path = render_dashboard(result, args.html)
        print(f"  {'dashboard':<10} {path}")
    return 0


def cmd_rules(args):
    from .rules_engine import RuleSet
    from .correlation import load_sequence_rules
    rs = RuleSet.load(args.rules)
    seqs = load_sequence_rules(f"{args.rules}/correlation")
    print(f"\n{len(rs)} atomic rules, {len(seqs)} correlation rules\n")
    print(f"{'ID':<34}{'LEVEL':<10}{'STATUS':<14}TITLE")
    print(hr())
    for r in sorted(rs.rules, key=lambda r: (SEVERITY_ORDER.get(r.level, 9), r.id)):
        print(f"{r.id:<34}{r.level:<10}{r.status:<14}{r.title}")
    for s in seqs:
        print(f"{s.id:<34}{s.level:<10}{'correlation':<14}{s.title}")
    if args.coverage:
        print(f"\nATT&CK COVERAGE\n{hr()}")
        for tech, rules in rs.coverage().items():
            print(f"{tech:<14}{', '.join(rules)}")
    return 0


def cmd_metrics(args):
    from .metrics import evaluate
    return evaluate(args.input_dir, args.rules, args.config, args.year, args.threshold_sweep)



def _collect_inputs(args) -> dict:
    inputs: dict = {}
    if getattr(args, "input_dir", None):
        d = Path(args.input_dir)
        mapping = {"auth.log": "auth", "access.log": "nginx",
                   "windows_security.json": "winlog", "suricata_eve.json": "suricata",
                   "cowrie.json": "cowrie"}
        for name, source in mapping.items():
            if (d / name).exists():
                inputs[str(d / name)] = source
    for flag, source in (("auth", "auth"), ("nginx", "nginx"), ("winlog", "winlog"),
                         ("suricata", "suricata"), ("cowrie", "cowrie")):
        val = getattr(args, flag, None)
        if val:
            inputs[val] = source
    return inputs


def _load_events(args):
    """Parse and enrich without running detections - the search corpus."""
    from .enrich import Enricher
    from .parsers import parse_many
    inputs = _collect_inputs(args)
    if not inputs:
        print("No input files found. Use --input-dir or a source flag.", file=sys.stderr)
        return None
    events, _stats = parse_many(inputs, year=args.year)
    return Enricher(args.config).enrich_all(events)


def cmd_search(args):
    from .query import QueryError, render_table, search as run_search, EXAMPLES
    if args.examples:
        print("\n  EXAMPLE QUERIES\n")
        for q, why in EXAMPLES:
            print(f"  {C['dim']}# {why}{C['reset']}\n  {q}\n")
        return 0
    events = _load_events(args)
    if events is None:
        return 1
    try:
        rows = run_search(events, args.query)
    except QueryError as exc:
        print(f"query error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(rows, indent=2, default=str))
    else:
        print()
        print(render_table(rows, max_rows=args.limit))
        print()
    return 0


def cmd_shell(args):
    """Interactive search REPL."""
    from .query import QueryError, render_table, search as run_search, EXAMPLES
    c = C if not args.no_color else NO_COLOR
    events = _load_events(args)
    if events is None:
        return 1
    print(f"\n{c['bold']}SIEMQL{c['reset']} — {len(events)} events loaded")
    print(f"{c['dim']}Commands: .help  .fields  .examples  .quit{c['reset']}\n")
    history: list[str] = []
    while True:
        try:
            line = input(f"{c['bold']}siem>{c['reset']} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line in (".quit", ".exit", "exit", "quit"):
            break
        if line == ".help":
            print(__import__("siem.query", fromlist=["x"]).__doc__)
            continue
        if line == ".examples":
            for q, why in EXAMPLES:
                print(f"  {c['dim']}# {why}{c['reset']}\n  {q}\n")
            continue
        if line == ".fields":
            fields: dict = {}
            for e in events[:2000]:
                for k in e:
                    fields[k] = fields.get(k, 0) + 1
            for name, count in sorted(fields.items(), key=lambda kv: -kv[1]):
                print(f"  {name:<34}{c['dim']}{count} events{c['reset']}")
            continue
        if line == ".history":
            for h in history:
                print(f"  {h}")
            continue
        history.append(line)
        try:
            rows = run_search(events, line)
            print()
            print(render_table(rows, max_rows=args.limit))
            print()
        except QueryError as exc:
            print(f"  {c['high']}query error:{c['reset']} {exc}\n")
        except Exception as exc:  # noqa: BLE001
            print(f"  {c['high']}error:{c['reset']} {type(exc).__name__}: {exc}\n")
    return 0


def cmd_stream(args):
    from .stream import StreamRunner, replay
    inputs = _collect_inputs(args)
    if not inputs:
        print("No input files found. Use --input-dir or a source flag.", file=sys.stderr)
        return 1
    if args.replay:
        replay(inputs, speed=args.speed, rules_dir=args.rules, config_dir=args.config,
               year=args.year, color=not args.no_color, limit=args.limit)
        return 0
    runner = StreamRunner(inputs, rules_dir=args.rules, config_dir=args.config,
                          interval=args.interval, year=args.year,
                          color=not args.no_color, from_start=args.from_start,
                          sink=args.sink)
    runner.run(max_seconds=args.max_seconds)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="siem", description="Open-source SIEM: detect, correlate, score, respond")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="run the full pipeline over log files")
    a.add_argument("--input-dir", help="directory containing standard-named log files")
    a.add_argument("--auth"); a.add_argument("--nginx"); a.add_argument("--winlog")
    a.add_argument("--suricata"); a.add_argument("--cowrie")
    a.add_argument("--rules", default="rules"); a.add_argument("--config", default="config")
    a.add_argument("--out", default="out"); a.add_argument("--year", type=int, default=2026)
    a.add_argument("--case-threshold", type=int, default=100)
    a.add_argument("--max-alerts", type=int, default=25)
    a.add_argument("--html", help="also write an HTML dashboard to this path")
    a.add_argument("--no-behavioral", action="store_true")
    a.add_argument("--no-color", action="store_true")
    a.add_argument("--live", action="store_true", help="execute response actions instead of dry-run")
    a.set_defaults(func=cmd_analyze)

    r = sub.add_parser("rules", help="list loaded detection rules")
    r.add_argument("--rules", default="rules")
    r.add_argument("--coverage", action="store_true")
    r.set_defaults(func=cmd_rules)

    m = sub.add_parser("metrics", help="measure precision/recall against ground truth")
    m.add_argument("--input-dir", default="sample_logs")
    m.add_argument("--rules", default="rules"); m.add_argument("--config", default="config")
    m.add_argument("--year", type=int, default=2026)
    m.add_argument("--threshold-sweep", action="store_true", help="sweep brute-force thresholds")
    m.set_defaults(func=cmd_metrics)

    sr = sub.add_parser("search", help="run one SIEMQL query over the logs")
    sr.add_argument("query", nargs="?", default="", help="SIEMQL query string")
    sr.add_argument("--input-dir", default="sample_logs")
    sr.add_argument("--auth"); sr.add_argument("--nginx"); sr.add_argument("--winlog")
    sr.add_argument("--suricata"); sr.add_argument("--cowrie")
    sr.add_argument("--config", default="config"); sr.add_argument("--year", type=int, default=2026)
    sr.add_argument("--limit", type=int, default=50)
    sr.add_argument("--json", action="store_true")
    sr.add_argument("--examples", action="store_true", help="show example queries and exit")
    sr.add_argument("--no-color", action="store_true")
    sr.set_defaults(func=cmd_search)

    sh = sub.add_parser("shell", help="interactive SIEMQL search prompt")
    sh.add_argument("--input-dir", default="sample_logs")
    sh.add_argument("--auth"); sh.add_argument("--nginx"); sh.add_argument("--winlog")
    sh.add_argument("--suricata"); sh.add_argument("--cowrie")
    sh.add_argument("--config", default="config"); sh.add_argument("--year", type=int, default=2026)
    sh.add_argument("--limit", type=int, default=30)
    sh.add_argument("--no-color", action="store_true")
    sh.set_defaults(func=cmd_shell)

    st = sub.add_parser("stream", help="real-time detection on a live log tail")
    st.add_argument("--input-dir")
    st.add_argument("--auth"); st.add_argument("--nginx"); st.add_argument("--winlog")
    st.add_argument("--suricata"); st.add_argument("--cowrie")
    st.add_argument("--rules", default="rules"); st.add_argument("--config", default="config")
    st.add_argument("--year", type=int, default=2026)
    st.add_argument("--interval", type=float, default=1.0, help="poll seconds")
    st.add_argument("--from-start", action="store_true", help="read existing content too")
    st.add_argument("--sink", help="append alerts as ECS JSON to this file")
    st.add_argument("--max-seconds", type=float, help="stop after N seconds")
    st.add_argument("--replay", action="store_true",
                    help="push existing files through the streaming engine")
    st.add_argument("--speed", type=float, default=0.0,
                    help="replay speed multiplier (0 = instant, 60 = 1 sim-minute/sec)")
    st.add_argument("--limit", type=int, help="replay only the first N events")
    st.add_argument("--no-color", action="store_true")
    st.set_defaults(func=cmd_stream)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
