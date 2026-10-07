# Mini-SIEM

A SIEM pipeline built from scratch to understand what tools like Splunk and Sentinel do internally: log normalization, detection, correlation, risk scoring, search and real-time alerting.

**Python 3.10+ and PyYAML.**

```bash
pip install -r requirements.txt
python tools/generate_logs.py
python -m siem.cli analyze --input-dir sample_logs --html out/dashboard.html
```

## Results

Tested on 1,136 labelled events containing 14 attacks, mixed with benign traffic built to cause false positives (a misconfigured backup agent, a search crawler, users mistyping passwords).

| Precision | Recall | Alerts | False positives | Tests |
|---|---|---|---|---|
| 100% | 100% | 28 | 0 | 64 passing |

CI fails the build if precision or recall drops below 80%.

> This is a corpus I wrote, so 100% shows the pipeline is consistent, not that it would score the same on real attacker traffic. See [docs/HONEYPOT.md](docs/HONEYPOT.md) for testing against live data.

## How it works

```
logs → normalize (ECS) → enrich → detect → correlate → score → case
```

1. **Normalize.** Six log sources (SSH, sudo, Nginx, Windows Security, Suricata, Cowrie honeypot) are converted to Elastic Common Schema. A Windows 4625 and a Linux failed login become the same event, so one rule covers both.
2. **Enrich.** Adds GeoIP, threat intel, asset criticality and account privilege to every event.
3. **Detect.** Three layers: 15 Sigma-compatible YAML rules, stateful logic (e.g. login success after repeated failures), and behavioral baselines.
4. **Correlate.** Chains alerts into attack stories. A web scan, then a password spray, then a successful login from one IP is one intrusion, not three alerts.
5. **Score.** Alerts add risk to the IP, user or host that caused them. Risk is weighted by context and halves every 24 hours. A case opens when the score crosses a threshold.

## Search and streaming

**SIEMQL**, a pipe-based query language similar to SPL:

```bash
python -m siem.cli shell --input-dir sample_logs
```
```
siem> event.outcome = failure | stats count, dc(user.name) as users by source.ip | sort -count

  SOURCE.IP      COUNT  USERS
  10.0.0.41      84     1      ← broken backup agent
  198.51.100.77  76     14     ← password spray
  203.0.113.45   60     3      ← brute force
```

**Real-time streaming** tails log files and alerts as events arrive. It handles log rotation, keeps memory bounded, and resumes from a checkpoint after restart.

```bash
python -m siem.cli stream --auth /var/log/auth.log
python -m siem.cli stream --input-dir sample_logs --replay --speed 60   # demo
```

## Commands

| Command | Does |
|---|---|
| `analyze` | Full pipeline, console report, optional HTML dashboard |
| `metrics --threshold-sweep` | Precision/recall, plus accuracy at different thresholds |
| `shell` / `search` | Interactive or one-off queries |
| `stream` | Live detection on a log tail |
| `rules --coverage` | List rules and MITRE ATT&CK coverage |

Run tests with `python tests/test_siem.py`.

## Key decisions

- **One rule is deliberately disabled.** A stateless version of "login success after failures" fired on every normal login: 56 critical alerts for 2 real attacks. It was rebuilt as stateful logic, and a test keeps the old version off. Full story in [docs/TUNING.md](docs/TUNING.md).
- **No auto-blocking** except honeypot hits, where a false positive can't happen. Everything else waits for an analyst.
- **Every rule must document** its false positives and response steps, or CI rejects it.

## Limitations

- Single process, in memory. Roughly 1M events before RAM becomes the limit.
- Search scans every event; there's no index, join or subsearch.
- Behavioral baselining runs in batch mode only.


---

Sadman Sakib Abir · MIT License
