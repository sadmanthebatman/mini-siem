# Architecture

## Data flow

```
 ingest ──▶ normalize ──▶ enrich ──▶ detect ──▶ correlate ──▶ score ──▶ respond
 parsers.py   models.py   enrich.py  rules_    correlation.py  risk.py  risk.py
                                     engine.py
```

Each stage is independently testable. The metrics harness feeds labelled events
straight into the detect stage without touching parsers, which is what makes CI
quality gating possible.

## 1. Ingestion and normalization

Five parsers, one output shape. Everything becomes Elastic Common Schema with flat
dotted keys (`source.ip`, not nested dicts) because rules reference fields by dotted
path and flat lookup keeps the matcher simple.

| Source | Format | Notes |
|---|---|---|
| sshd | syslog | No year in timestamp — supplied by the caller |
| sudo | syslog | No source IP; local action |
| nginx | combined | URL-decoded into `url.path`, raw kept in `url.original` |
| Windows Security | JSON | Event ID → ECS category/action/outcome map |
| Suricata | EVE JSON | Non-alert event types discarded |
| Cowrie | JSON | Tagged `honeypot: true`, which drives a 2.0× risk multiplier |

**The decision that matters:** a Windows 4625 and a Linux "Failed password" both
become `event.category=authentication, event.outcome=failure`. One brute-force rule
covers both platforms. Without this, every rule is written N times for N log formats
and the ruleset becomes unmaintainable at exactly the point it becomes useful.

Unparsed lines are counted, not silently dropped. A rising skip count is the first
sign of a broken regex or a changed log format.

## 2. Enrichment

Raw: `203.0.113.45 failed 25 logins`.
Enriched: `203.0.113.45 (Russia, AbuseIPDB-flagged, first seen today) failed 25
logins against a crown-jewel host targeting a privileged account`.

The second is triageable in ten seconds; the first needs four browser tabs.

| Enrichment | Source | Used by |
|---|---|---|
| Geo / ASN | `config/geoip.csv` | Analyst context |
| Threat intel | `config/threat_intel.json` | 1.6× risk multiplier |
| Asset criticality | `config/assets.yml` | Up to 2.0× multiplier |
| Identity | `config/identities.yml` | 1.5× for privileged accounts |
| First-seen | Runtime state | Novelty detection |
| Business hours | Timestamp | 1.2× off-hours multiplier |

All offline files so runs are reproducible and CI is deterministic. Swap the loaders
for MaxMind, MISP and AbuseIPDB in production; the interfaces don't change.

Enrichment runs in chronological order because first-seen is order-dependent.

## 3. Detection tiers

**Atomic** — Sigma YAML in `rules/atomic/`. Stateless matching plus sliding-window
thresholds. The window slides rather than bucketing: 5 failures at 11:59:58 and 5
at 12:00:02 is a real attack that fixed buckets miss. Tested explicitly.

**Stateful** — Python in `correlation.py`. Detections needing memory:
success-after-failures, privilege-escalation-after-external-login. These cannot be
expressed in stateless Sigma, which is why one rule file is deliberately disabled.

**Behavioral** — `Baseline` learns per-user activity hours and host sets from a
training window, then flags deviation. Honest limitation: assumes the training
window is clean. An attacker present during training becomes the baseline.
Supplements signatures, never replaces them.

**Correlation** — sequence rules in `rules/correlation/` chain alerts from the other
tiers. Recon → credential attack → compromise, from the same entity within 4 hours,
is one confirmed intrusion rather than three unrelated findings. This is the stage
that justifies the word SIEM: no single log source sees the whole attack.

## 4. Deduplication

Alert fingerprint = `rule_id | entity | hour`. Identical findings inside the same
hour collapse to one alert. Without this the honeypot rules alone produce dozens of
near-identical alerts and the case timeline becomes unreadable.

## 5. Risk scoring

Alerts accumulate onto entities rather than each becoming a ticket.

```
entity_score = Σ (severity_base × context_multipliers), decayed by elapsed time
```

- Severity base: critical 90, high 60, medium 35, low 15
- Multipliers: honeypot 2.0, crown-jewel asset 2.0, threat-intel match 1.6,
  privileged user 1.5, external source 1.2, off-hours 1.2
- Decay: 24-hour half-life, applied between consecutive alerts for that entity

Decay matters because an IP that attacked last Tuesday and went quiet is less
interesting than one active now. Without decay, risk accumulates monotonically and
every long-lived entity eventually looks critical.

A case opens at score 100, with severity and SLA derived from the final score
(critical ≥180 → 1h, high ≥130 → 4h, otherwise 24h). Case IDs are deterministic
(`CASE-{date}-{hash(entity)}`) so re-running updates a case instead of spawning
duplicates.

## 6. Response

Playbooks are plain Python functions in `risk.py`, version-controlled and unit
tested. Dry-run by default: actions are recorded, not executed.

Auto-containment is permitted for exactly one condition — honeypot interaction,
where false positives are impossible by construction. Everything else, including
critical cases, records `HELD FOR ANALYST APPROVAL`.

This is a deliberate safety decision. An attacker who knows you auto-block can spoof
traffic from your payment processor's address range and have your own automation
take your business offline. Containment stays behind a human unless confidence is
absolute.

## Outputs

| File | Purpose |
|---|---|
| `out/alerts.ndjson` | ECS signal documents |
| `out/opensearch_bulk.ndjson` | Ready for `_bulk` ingestion |
| `out/cases.json`, `out/cases/*.json` | Case files with timelines and actions |
| `out/metrics.json` | Precision, recall, F1, per-scenario recall |
| `out/summary.json` | Run statistics and ATT&CK coverage |
| `out/dashboard.html` | Self-contained dashboard, no dependencies |

## Scaling path

This is a batch pipeline. For production:

1. Beats or Fluent Bit agents replace file reading
2. Kafka between collection and processing for buffering and backpressure
3. Processing becomes a consumer loop; the stage functions are unchanged
4. Enrichment state (first-seen, baselines) moves from dicts to Redis or a database
5. OpenSearch with index lifecycle management: hot 7d, warm 30d, delete 90d
6. Rules continue to live in Git with the same CI gate

The stage boundaries are already drawn where the distributed version needs them,
which is the point of structuring it this way.
