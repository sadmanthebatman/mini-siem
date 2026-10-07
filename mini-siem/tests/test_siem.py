"""
Test suite.

Two things every detection test must prove:
  1. It FIRES on the attack  (no blind spot)
  2. It STAYS SILENT on benign lookalikes  (no alert fatigue)

The second half is the half people skip, and it is the half that decides
whether a SOC trusts the ruleset. Each detection test below has a negative
case built from traffic deliberately designed to look suspicious but be
innocent: an expired service account, a search engine crawler, a user who
mistypes a password.

Runs with pytest, or standalone: python tests/test_siem.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from siem.correlation import Baseline, SequenceRule, success_after_failures
from siem.enrich import Enricher, is_internal
from siem.metrics import score
from siem.models import Alert, Event
from siem.parsers import parse_file, parse_nginx, parse_sshd, parse_suricata, parse_winlog
from siem.pipeline import Pipeline
from siem.risk import PlaybookRunner, RiskEngine
from siem.query import Query, QueryError, render_table, search as qsearch
from siem.rules_engine import Rule, RuleSet, match_block
from siem.stream import StreamEngine, TailedFile, replay

ROOT = Path(__file__).resolve().parents[1]
LOGS = ROOT / "sample_logs"
Y = 2026


def ev(**kw) -> Event:
    base = {"@timestamp": datetime(2026, 9, 21, 12, 0, 0), "event.category": "authentication",
            "event.outcome": "failure", "event.provider": "sshd", "source.ip": "1.2.3.4",
            "user.name": "root", "message": "test"}
    base.update(kw)
    return Event(base)


# ======================================================================
# Parsers
# ======================================================================
class TestParsers:
    def test_sshd_failure(self):
        e = parse_sshd("Sep 21 11:00:02 web01 sshd[4821]: Failed password for root "
                       "from 203.0.113.45 port 51001 ssh2", Y)
        assert e["event.outcome"] == "failure"
        assert e["source.ip"] == "203.0.113.45"
        assert e["user.name"] == "root"
        assert e["@timestamp"] == datetime(2026, 9, 21, 11, 0, 2)

    def test_sshd_invalid_user_flag(self):
        e = parse_sshd("Sep 21 11:00:02 web01 sshd[1]: Failed password for invalid user "
                       "admin from 1.2.3.4 port 1 ssh2", Y)
        assert e["user.invalid"] is True
        assert e["user.name"] == "admin"

    def test_sshd_single_digit_day_padding(self):
        """Syslog pads days under 10 with an extra space. Classic parser break."""
        e = parse_sshd("Sep  5 08:00:00 web01 sshd[1]: Accepted password for alice "
                       "from 10.0.0.5 port 1 ssh2", Y)
        assert e["@timestamp"] == datetime(2026, 9, 5, 8, 0, 0)

    def test_sshd_rejects_noise(self):
        assert parse_sshd("Sep 21 14:22:10 web01 sshd[1]: Connection closed by 10.0.0.1", Y) is None
        assert parse_sshd("total garbage", Y) is None

    def test_nginx_url_decoding(self):
        """Encoded payloads must be decoded or rules miss them entirely."""
        e = parse_nginx('1.2.3.4 - - [21/Sep/2026:14:30:00 +0000] '
                        '"GET /p?id=1%20UNION%20SELECT%201 HTTP/1.1" 200 5 "-" "sqlmap/1.8"')
        assert "UNION SELECT" in e["url.path"]
        assert "%20" in e["url.original"]
        assert e["http.response.status_code"] == 200

    def test_winlog_4625(self):
        e = parse_winlog(json.dumps({"EventID": 4625, "TimeCreated": "2026-09-21T16:20:00",
                                     "Computer": "dc01",
                                     "EventData": {"TargetUserName": "Administrator",
                                                   "IpAddress": "141.98.80.12", "LogonType": 3}}))
        assert e["event.category"] == "authentication"
        assert e["event.outcome"] == "failure"
        assert e["winlog.logon_type"] == "network"

    def test_suricata_ignores_non_alerts(self):
        assert parse_suricata(json.dumps({"event_type": "flow", "timestamp": "2026-09-21T10:00:00"})) is None

    def test_all_sample_files_parse(self):
        """Every sample file must parse with zero skipped lines."""
        for name, src in (("auth.log", "auth"), ("access.log", "nginx"),
                          ("windows_security.json", "winlog"), ("cowrie.json", "cowrie")):
            events, skipped = parse_file(str(LOGS / name), src, Y)
            assert events, f"{name} produced no events"
            assert skipped == 0, f"{name} skipped {skipped} lines"


# ======================================================================
# Rule engine
# ======================================================================
class TestRuleEngine:
    def test_and_across_keys_or_within_values(self):
        e = ev(**{"event.provider": "sshd"})
        assert match_block(e, {"event.outcome": "failure", "event.provider": ["sshd", "cowrie"]})
        assert not match_block(e, {"event.outcome": "success", "event.provider": "sshd"})

    def test_contains_and_regex_modifiers(self):
        e = ev(**{"url.path": "/products?id=1 UNION SELECT pw FROM users"})
        assert match_block(e, {"url.path|contains": "UNION"})
        assert match_block(e, {"url.path|re": r"union\s+select"})
        assert not match_block(e, {"url.path|contains": "nonexistent"})

    def test_numeric_modifiers(self):
        e = ev(**{"http.response.status_code": 404})
        assert match_block(e, {"http.response.status_code|gte": 400})
        assert not match_block(e, {"http.response.status_code|lt": 400})

    def test_negation_condition(self):
        rule = Rule({"id": "t", "title": "t", "detection": {
            "selection": {"event.outcome": "failure"},
            "filter": {"user.name": "svc_backup"},
            "condition": "selection and not filter"}})
        assert rule.matches(ev())
        assert not rule.matches(ev(**{"user.name": "svc_backup"}))

    def test_sliding_window_not_fixed_bucket(self):
        """
        An attack straddling a bucket boundary must still fire. Fixed-bucket
        counting would miss 5 failures at 11:59:58 plus 5 at 12:00:02.
        """
        rule = Rule({"id": "bf", "title": "bf", "detection": {
            "selection": {"event.outcome": "failure"},
            "threshold": {"group_by": ["source.ip"], "count": 10, "window": "60s"},
            "condition": "selection"}})
        base = datetime(2026, 9, 21, 11, 59, 58)
        events = [ev(**{"@timestamp": base + timedelta(seconds=i)}) for i in range(10)]
        assert len(rule.evaluate(events)) == 1

    def test_threshold_respects_window(self):
        rule = Rule({"id": "bf", "title": "bf", "detection": {
            "selection": {"event.outcome": "failure"},
            "threshold": {"group_by": ["source.ip"], "count": 10, "window": "60s"},
            "condition": "selection"}})
        base = datetime(2026, 9, 21, 11, 0, 0)
        slow = [ev(**{"@timestamp": base + timedelta(minutes=i * 5)}) for i in range(10)]
        assert rule.evaluate(slow) == []

    def test_distinct_counting_for_spray(self):
        rule = Rule({"id": "sp", "title": "sp", "detection": {
            "selection": {"event.outcome": "failure"},
            "threshold": {"group_by": ["source.ip"], "distinct": "user.name",
                          "count": 5, "window": "10m"},
            "condition": "selection"}})
        base = datetime(2026, 9, 21, 11, 0, 0)
        # 20 attempts but only 2 usernames: must NOT fire
        few = [ev(**{"@timestamp": base + timedelta(seconds=i * 5),
                     "user.name": ["alice", "bob"][i % 2]}) for i in range(20)]
        assert rule.evaluate(few) == []
        # 6 distinct usernames: must fire
        many = [ev(**{"@timestamp": base + timedelta(seconds=i * 5), "user.name": f"u{i}"})
                for i in range(6)]
        assert len(rule.evaluate(many)) == 1

    def test_shipped_rules_all_load(self):
        rs = RuleSet.load(str(ROOT / "rules"))
        assert len(rs) >= 14
        for r in rs.rules:
            assert r.id and r.title and r.level in ("critical", "high", "medium", "low", "informational")
            assert r.false_positives, f"{r.id} documents no false positives"
            assert r.response, f"{r.id} documents no response guidance"

    def test_stateless_compromise_rule_is_disabled(self):
        """Regression guard: re-enabling this rule caused a 96% FP rate."""
        rs = RuleSet.load(str(ROOT / "rules"))
        assert "auth_success_after_failures" not in {r.id for r in rs.rules}


# ======================================================================
# Stateful and behavioral
# ======================================================================
class TestStateful:
    def test_fires_on_success_after_failures(self):
        base = datetime(2026, 9, 21, 11, 0, 0)
        events = [ev(**{"@timestamp": base + timedelta(seconds=i)}) for i in range(12)]
        events.append(ev(**{"@timestamp": base + timedelta(seconds=13), "event.outcome": "success"}))
        alerts = success_after_failures(events)
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"

    def test_silent_when_too_few_failures(self):
        base = datetime(2026, 9, 21, 11, 0, 0)
        events = [ev(**{"@timestamp": base + timedelta(seconds=i)}) for i in range(3)]
        events.append(ev(**{"@timestamp": base + timedelta(seconds=5), "event.outcome": "success"}))
        assert success_after_failures(events) == []

    def test_failures_age_out_of_window(self):
        """Failures an hour ago must not justify a critical on today's login."""
        base = datetime(2026, 9, 21, 11, 0, 0)
        events = [ev(**{"@timestamp": base + timedelta(seconds=i)}) for i in range(12)]
        events.append(ev(**{"@timestamp": base + timedelta(hours=3), "event.outcome": "success"}))
        assert success_after_failures(events) == []

    def test_baseline_ignores_internal_users(self):
        """Internal staff working late is not an incident."""
        b = Baseline()
        train = [ev(**{"@timestamp": datetime(2026, 9, 21, 9, 0), "user.name": "alice",
                       "event.outcome": "success", "host.name": "web01",
                       "source.internal": True})]
        b.train(train)
        late = [ev(**{"@timestamp": datetime(2026, 9, 21, 23, 0), "user.name": "alice",
                      "event.outcome": "success", "host.name": "web01",
                      "source.internal": True})]
        assert [a for a in b.detect(late) if a.rule_id == "behavior_unusual_hour"] == []

    def test_baseline_flags_external_off_hours(self):
        b = Baseline()
        b.train([ev(**{"@timestamp": datetime(2026, 9, 21, 9, 0), "user.name": "alice",
                       "event.outcome": "success", "host.name": "web01", "source.internal": True})])
        ext = [ev(**{"@timestamp": datetime(2026, 9, 21, 3, 0), "user.name": "alice",
                     "event.outcome": "success", "host.name": "web01", "source.internal": False})]
        assert [a for a in b.detect(ext) if a.rule_id == "behavior_unusual_hour"]


class TestSequence:
    def _chain(self):
        return SequenceRule({"id": "chain", "title": "chain", "level": "critical",
                             "sequence": {"within": "4h", "ordered": True, "stages": [
                                 {"rule_id": ["web_scanning"]},
                                 {"rule_id": ["ssh_brute_force"]},
                                 {"rule_id": ["auth_success_after_failures"]}]}})

    def _alert(self, rid, minute):
        return Alert(rule_id=rid, rule_name=rid, severity="high",
                     timestamp=datetime(2026, 9, 21, 11, minute), entity="1.2.3.4",
                     entity_type="ip", description="x")

    def test_complete_chain_fires(self):
        alerts = [self._alert("web_scanning", 0), self._alert("ssh_brute_force", 10),
                  self._alert("auth_success_after_failures", 20)]
        assert len(self._chain().evaluate(alerts)) == 1

    def test_partial_chain_silent(self):
        alerts = [self._alert("web_scanning", 0), self._alert("ssh_brute_force", 10)]
        assert self._chain().evaluate(alerts) == []

    def test_chain_expires_after_window(self):
        alerts = [self._alert("web_scanning", 0), self._alert("ssh_brute_force", 10)]
        late = Alert(rule_id="auth_success_after_failures", rule_name="x", severity="critical",
                     timestamp=datetime(2026, 9, 22, 20, 0), entity="1.2.3.4",
                     entity_type="ip", description="x")
        assert self._chain().evaluate(alerts + [late]) == []


# ======================================================================
# Enrichment and risk
# ======================================================================
class TestEnrichment:
    def test_internal_classification(self):
        assert is_internal("10.0.0.5") and is_internal("192.168.1.1")
        assert not is_internal("203.0.113.45")
        assert not is_internal("not-an-ip")

    def test_threat_intel_and_geo(self):
        e = Enricher(str(ROOT / "config"))
        out = e.enrich(ev(**{"source.ip": "203.0.113.45", "host.name": "dbserver01"}))
        assert out["threat.indicator.source"] == "AbuseIPDB"
        assert out["source.geo.country_name"] == "Russia"
        assert out["host.criticality"] == "crown_jewel"

    def test_first_seen_only_once(self):
        e = Enricher(str(ROOT / "config"))
        assert e.enrich(ev(**{"source.ip": "8.8.8.8"}))["source.first_seen"] is True
        assert e.enrich(ev(**{"source.ip": "8.8.8.8"}))["source.first_seen"] is False


class TestRisk:
    def _alert(self, sev="high", ctx=None, minute=0):
        return Alert(rule_id="r", rule_name="r", severity=sev,
                     timestamp=datetime(2026, 9, 21, 11, minute), entity="1.2.3.4",
                     entity_type="ip", description="d", context=ctx or {})

    def test_context_raises_score(self):
        plain = RiskEngine(); plain.ingest([self._alert()])
        ctx = RiskEngine(); ctx.ingest([self._alert(ctx={"threat.indicator.source": "AbuseIPDB",
                                                        "host.criticality": "crown_jewel",
                                                        "user.privileged": True})])
        assert ctx.ranked()[0].score > plain.ranked()[0].score * 2

    def test_decay_reduces_stale_risk(self):
        fast = RiskEngine(); fast.ingest([self._alert(minute=0), self._alert(minute=5)])
        slow = RiskEngine()
        slow.ingest([self._alert(minute=0),
                     Alert(rule_id="r", rule_name="r", severity="high",
                           timestamp=datetime(2026, 9, 25, 11, 0), entity="1.2.3.4",
                           entity_type="ip", description="d")])
        assert slow.ranked()[0].score < fast.ranked()[0].score

    def test_case_opens_only_above_threshold(self):
        low = RiskEngine(case_threshold=100); low.ingest([self._alert("low")])
        assert low.open_cases() == []
        high = RiskEngine(case_threshold=100)
        high.ingest([self._alert("critical", minute=i) for i in range(3)])
        assert high.open_cases()

    def test_playbook_dry_run_does_not_block(self):
        pb = PlaybookRunner(dry_run=True)
        pb.block_ip("1.2.3.4", "test")
        assert pb.actions_taken[0]["executed"] is False
        assert not Path("out/blocklist.txt").exists() or "1.2.3.4" not in \
            Path("out/blocklist.txt").read_text(encoding="utf-8")


# ======================================================================
# End to end
# ======================================================================
class TestEndToEnd:
    def _run(self):
        inputs = {str(LOGS / n): s for n, s in
                  (("auth.log", "auth"), ("access.log", "nginx"),
                   ("windows_security.json", "winlog"), ("suricata_eve.json", "suricata"),
                   ("cowrie.json", "cowrie"))}
        return Pipeline(str(ROOT / "rules"), str(ROOT / "config")).run(inputs, year=Y)

    def test_every_attacker_is_detected(self):
        result = self._run()
        found = {a.entity for a in result.alerts}
        for attacker in ("203.0.113.45", "198.51.100.77", "45.33.32.156",
                         "141.98.80.12", "80.94.92.60"):
            assert attacker in found, f"missed attacker {attacker}"

    def test_benign_sources_produce_no_alerts(self):
        result = self._run()
        noisy_but_innocent = {"10.0.0.41",      # expired service account
                              "66.249.66.1",    # Googlebot hitting 404s
                              "192.168.1.10", "192.168.1.22", "10.0.0.5", "10.0.0.17"}
        assert not (noisy_but_innocent & {a.entity for a in result.alerts})

    def test_intrusion_chain_correlates(self):
        result = self._run()
        assert any(a.rule_id.startswith("chain_") for a in result.alerts)

    def test_quality_gate(self):
        """The CI gate: recall and precision must both hold at 100%."""
        result = self._run()
        truth = json.loads((LOGS / "ground_truth.json").read_text(encoding="utf-8"))
        m = score(result, truth)
        assert m["recall"] == 1.0, f"missed: {m['missed']}"
        assert m["precision"] == 1.0, f"false positives: {m['false_positive_alerts']}"

    def test_exports_are_valid_json(self):
        result = self._run()
        written = Pipeline.export(result, "out")
        for line in open(written["alerts"], encoding="utf-8"):
            json.loads(line)
        json.load(open(written["cases"], encoding="utf-8"))

    def test_run_is_deterministic(self):
        a, b = self._run(), self._run()
        assert {x.fingerprint for x in a.alerts} == {x.fingerprint for x in b.alerts}



# ======================================================================
# Search language
# ======================================================================
class TestQueryLanguage:
    def _corpus(self):
        from siem.parsers import parse_many
        events, _ = parse_many({str(LOGS / "auth.log"): "auth",
                                str(LOGS / "access.log"): "nginx"}, year=Y)
        return Enricher(str(ROOT / "config")).enrich_all(events)

    def test_simple_equality_filter(self):
        rows = qsearch(self._corpus(), 'source.ip = "203.0.113.45"')
        assert rows and all(r["source.ip"] == "203.0.113.45" for r in rows)

    def test_boolean_and_or_not(self):
        c = self._corpus()
        both = qsearch(c, 'event.outcome = failure and event.provider = sshd')
        either = qsearch(c, 'event.outcome = failure or event.outcome = success')
        negated = qsearch(c, 'not event.outcome = failure')
        assert len(both) < len(either)
        assert all(r["event.outcome"] != "failure" for r in negated)

    def test_numeric_comparison(self):
        rows = qsearch(self._corpus(), "http.response.status_code >= 400")
        assert rows and all(int(r["http.response.status_code"]) >= 400 for r in rows)

    def test_regex_operator(self):
        rows = qsearch(self._corpus(), 'url.path =~ "union.*select"')
        assert len(rows) >= 1

    def test_in_operator(self):
        rows = qsearch(self._corpus(), 'user.name in [root, admin]')
        assert rows and all(str(r["user.name"]).lower() in ("root", "admin") for r in rows)

    def test_existence_wildcard(self):
        rows = qsearch(self._corpus(), "threat.indicator.source = *")
        assert rows and all(r.get("threat.indicator.source") for r in rows)

    def test_stats_with_group_by(self):
        rows = qsearch(self._corpus(),
                       'event.outcome = failure | stats count by source.ip')
        assert rows and "count" in rows[0] and "source.ip" in rows[0]

    def test_distinct_count_separates_spray_from_bruteforce(self):
        """
        The query a real analyst writes: many failures but ONE username is a
        broken service account; many failures across MANY usernames is a spray.
        """
        rows = qsearch(self._corpus(),
                       'event.outcome = failure | stats count, dc(user.name) as users '
                       'by source.ip | sort -count')
        by_ip = {r["source.ip"]: r for r in rows}
        assert by_ip["10.0.0.41"]["users"] == 1        # benign backup agent
        assert by_ip["198.51.100.77"]["users"] >= 10   # the spray

    def test_sort_descending(self):
        rows = qsearch(self._corpus(), "| stats count by source.ip | sort -count")
        counts = [r["count"] for r in rows]
        assert counts == sorted(counts, reverse=True)

    def test_head_limits_rows(self):
        assert len(qsearch(self._corpus(), "| stats count by source.ip | head 3")) == 3

    def test_top_returns_percentages(self):
        rows = qsearch(self._corpus(), "event.category = authentication | top user.name 5")
        assert len(rows) == 5 and "percent" in rows[0]

    def test_fields_projection(self):
        rows = qsearch(self._corpus(), 'source.ip = "203.0.113.45" | fields source.ip, user.name')
        assert set(rows[0]) == {"source.ip", "user.name"}

    def test_timechart_buckets(self):
        rows = qsearch(self._corpus(), "| timechart span=4h count")
        assert rows and "time" in rows[0] and rows[0]["count"] > 0

    def test_pipeline_chaining(self):
        rows = qsearch(self._corpus(),
                       'event.outcome = failure | where source.internal = false '
                       '| stats count by source.ip | sort -count | head 2')
        assert len(rows) == 2

    def test_bad_query_raises_clean_error(self):
        for bad in ("source.ip = = =", "| stats nonsense_agg by x", "| frobnicate"):
            try:
                qsearch(self._corpus()[:10], bad)
                raise AssertionError(f"expected QueryError for {bad!r}")
            except QueryError:
                pass

    def test_render_table_handles_empty(self):
        assert "no results" in render_table([])


# ======================================================================
# Streaming
# ======================================================================
class TestStreaming:
    def test_tailer_reads_only_new_lines(self, tmp_path=None):
        import tempfile
        d = Path(tempfile.mkdtemp())
        f = d / "auth.log"
        f.write_text("line one\nline two\n", encoding="utf-8")
        t = TailedFile(f, "auth")
        assert len(t.read_new_lines()) == 2
        assert t.read_new_lines() == []
        with open(f, "a", encoding="utf-8") as fh:
            fh.write("line three\n")
        assert t.read_new_lines() == ["line three"]

    def test_tailer_holds_partial_line(self):
        import tempfile
        d = Path(tempfile.mkdtemp())
        f = d / "a.log"
        f.write_text("complete\npartial-no-newline", encoding="utf-8")
        t = TailedFile(f, "auth")
        assert t.read_new_lines() == ["complete"]      # partial withheld
        with open(f, "a", encoding="utf-8") as fh:
            fh.write("-now-complete\n")
        assert t.read_new_lines() == ["partial-no-newline-now-complete"]

    def test_tailer_detects_rotation(self):
        import os, tempfile
        d = Path(tempfile.mkdtemp())
        f = d / "r.log"
        f.write_text("old one\nold two\n", encoding="utf-8")
        t = TailedFile(f, "auth")
        assert len(t.read_new_lines()) == 2
        os.rename(f, d / "r.log.1")
        f.write_text("fresh\n", encoding="utf-8")
        assert t.read_new_lines() == ["fresh"]

    def test_tailer_detects_truncation(self):
        import tempfile
        d = Path(tempfile.mkdtemp())
        f = d / "t.log"
        f.write_text("aaaa\nbbbb\ncccc\n", encoding="utf-8")
        t = TailedFile(f, "auth")
        t.read_new_lines()
        f.write_text("x\n", encoding="utf-8")        # truncated in place
        assert t.read_new_lines() == ["x"]

    def _engine(self):
        return StreamEngine(str(ROOT / "rules"), str(ROOT / "config"))

    def test_brute_force_fires_mid_stream(self):
        engine = self._engine()
        base = datetime(2026, 9, 21, 22, 0, 0)
        fired = []
        for i in range(14):
            fired += engine.feed(ev(**{"@timestamp": base + timedelta(seconds=i * 2),
                                       "source.ip": "203.0.113.45"}))
        assert any(a.rule_id == "ssh_brute_force" for a in fired)

    def test_each_alert_emitted_once(self):
        """Re-evaluating the window must not re-emit the same finding."""
        engine = self._engine()
        base = datetime(2026, 9, 21, 22, 0, 0)
        fired = []
        for i in range(30):
            fired += engine.feed(ev(**{"@timestamp": base + timedelta(seconds=i),
                                       "source.ip": "203.0.113.45"}))
        bf = [a for a in fired if a.rule_id == "ssh_brute_force"]
        assert len(bf) == 1, f"duplicate alerts emitted: {len(bf)}"

    def test_compromise_detected_incrementally(self):
        engine = self._engine()
        base = datetime(2026, 9, 21, 22, 0, 0)
        fired = []
        for i in range(12):
            fired += engine.feed(ev(**{"@timestamp": base + timedelta(seconds=i * 2),
                                       "source.ip": "203.0.113.45"}))
        fired += engine.feed(ev(**{"@timestamp": base + timedelta(seconds=30),
                                   "source.ip": "203.0.113.45", "event.outcome": "success"}))
        assert any(a.rule_id == "auth_success_after_failures" for a in fired)

    def test_window_evicts_old_events(self):
        """Memory must stay bounded no matter how long the process runs."""
        engine = self._engine()
        base = datetime(2026, 9, 21, 0, 0, 0)
        for i in range(400):
            engine.feed(ev(**{"@timestamp": base + timedelta(minutes=i),
                              "source.ip": f"10.0.0.{i % 50}"}))
        assert len(engine.events) < 400
        span = engine.events[-1]["@timestamp"] - engine.events[0]["@timestamp"]
        assert span <= engine.window

    def test_benign_traffic_stays_silent(self):
        engine = self._engine()
        base = datetime(2026, 9, 21, 9, 0, 0)
        fired = []
        for i in range(20):
            fired += engine.feed(ev(**{"@timestamp": base + timedelta(minutes=i * 3),
                                       "source.ip": "192.168.1.10", "user.name": "alice",
                                       "event.outcome": "success"}))
        assert fired == []

    def test_streaming_finds_same_attackers_as_batch(self):
        inputs = {str(LOGS / n): s for n, s in
                  (("auth.log", "auth"), ("access.log", "nginx"),
                   ("windows_security.json", "winlog"), ("cowrie.json", "cowrie"))}
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            engine = StreamEngine(str(ROOT / "rules"), str(ROOT / "config"))
            from siem.parsers import parse_many
            events, _ = parse_many(inputs, year=Y)
            for e in events:
                engine.feed(e)
        found = {a.entity for a in engine.alerts}
        for attacker in ("203.0.113.45", "198.51.100.77", "141.98.80.12", "80.94.92.60"):
            assert attacker in found, f"streaming missed {attacker}"


# ======================================================================
# Standalone runner (works without pytest installed)
# ======================================================================
def _run_standalone() -> int:
    classes = [TestParsers, TestRuleEngine, TestStateful, TestSequence,
               TestEnrichment, TestRisk, TestQueryLanguage, TestStreaming, TestEndToEnd]
    passed = failed = 0
    failures: list[str] = []
    for cls in classes:
        print(f"\n{cls.__name__}")
        inst = cls()
        for name in sorted(n for n in dir(inst) if n.startswith("test_")):
            try:
                getattr(inst, name)()
                print(f"  PASS  {name}")
                passed += 1
            except AssertionError as exc:
                print(f"  FAIL  {name}: {exc}")
                failures.append(f"{cls.__name__}.{name}: {exc}")
                failed += 1
            except Exception as exc:  # noqa: BLE001
                print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
                failures.append(f"{cls.__name__}.{name}: {type(exc).__name__}: {exc}")
                failed += 1
    print(f"\n{'─'*60}\n  {passed} passed, {failed} failed\n{'─'*60}")
    for f in failures:
        print(f"  {f}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(_run_standalone())
