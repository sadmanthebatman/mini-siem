# Real-Time Streaming

Batch analysis tells you what happened yesterday. Streaming tells you it is
happening now — the difference between incident response and archaeology.

```bash
# Watch live logs and alert as attacks occur
python -m siem.cli stream --auth /var/log/auth.log --nginx /var/log/nginx/access.log

# Replay existing logs through the streaming engine (best demo)
python -m siem.cli stream --input-dir sample_logs --replay

# Replay at 60x: one simulated minute per real second
python -m siem.cli stream --input-dir sample_logs --replay --speed 60

# Ship alerts to a file as they fire
python -m siem.cli stream --input-dir sample_logs --sink alerts.ndjson
```

## What you see

Alerts print the moment the engine has enough evidence, mid-stream:

```
22:00:12 HIGH      SSH Brute Force ← 203.0.113.45  [T1110.001]
           Repeated SSH authentication failures from a single source (10 events within 1m)

 ▶ CASE OPENED CASE-20260921-59A5A6  CRITICAL: ip 203.0.113.45 | SLA 1h | risk 207
    → Block source IP at the perimeter firewall
    → Verify whether any authentication from this source succeeded

22:00:40 CRITICAL  Successful Authentication After Repeated Failures ← 203.0.113.45  [T1078,T1110]
           Authentication SUCCEEDED as 'root' on web01 after 14 failures against 1 account(s)
```

A live status line shows throughput: `[02:14] events 1832  alerts 6  cases 2  window 420 events`.

## How it works

**Sliding window, not full history.** Events are held in a deque trimmed to the
longest rule window plus a margin. Memory stays flat no matter how long the
process runs — a test asserts this explicitly.

**Incremental evaluation.** When an event arrives, only rules whose selection
matches *that event* are re-evaluated, and only against events sharing its group
key. That is what makes streaming viable; re-running every rule over every event
each second would not keep up.

**Exactly-once alerting.** Each alert's fingerprint (`rule | entity | hour`) is
remembered, so re-evaluating an overlapping window never re-emits a finding.

**Stateful detections are naturally incremental.** Success-after-failures tracks
prior failures per source in a rolling 10-minute map — it needs no window scan at
all.

**Correlation and risk update live.** Sequence chains evaluate against alerts seen
so far, entity risk accumulates with decay, and cases open the moment a score
crosses threshold.

## Operational behaviour

| Condition | Handling |
|---|---|
| Log rotation (logrotate) | Inode change detected, reopens from byte 0 |
| Truncation in place (`> file`) | File smaller than offset, resets |
| Partial line being written | Held in buffer until its newline arrives |
| Restart | Byte offsets checkpointed to `.siem_stream_state.json` |
| First run, no checkpoint | Starts at EOF — live activity only, no replay of history |
| Burst of 100k lines | Capped per poll so the loop cannot stall |
| File does not exist yet | Waits for it, no crash |

Each of these has a test.

## Flags

| Flag | Meaning |
|---|---|
| `--interval N` | poll seconds (default 1.0) |
| `--from-start` | read existing file content instead of starting at EOF |
| `--sink FILE` | append alerts as ECS JSON lines |
| `--max-seconds N` | stop automatically after N seconds |
| `--replay` | push existing files through the streaming engine |
| `--speed N` | replay multiplier: 0 instant, 1 real-time, 60 fast |
| `--limit N` | replay only the first N events |

## Try it on your own machine

```bash
# Linux: watch your real auth log
sudo python -m siem.cli stream --auth /var/log/auth.log

# In another terminal, generate a failure
ssh wronguser@localhost
```

On an internet-facing host you will see genuine botnet attempts within minutes.

## Streaming versus batch

Replaying the sample corpus through the streaming engine produces slightly fewer
alerts than batch analysis. That is expected, not a bug:

- **Behavioral baselining is batch-only.** It needs a training window before it
  can judge deviation, so it does not run per-event.
- **Threshold rules fire once per entity per window** rather than being
  recomputed across the whole dataset.

Both engines find every attacker — `test_streaming_finds_same_attackers_as_batch`
asserts it. Use streaming for live detection, batch for investigation and
reporting.

## Honest limitations

Single process, in-memory state. A production deployment puts Kafka between
collection and processing so events survive a restart and multiple consumers scale
out horizontally. The stage boundaries here are drawn exactly where that queue
would go.

No distributed coordination, no exactly-once delivery guarantee across restarts
(checkpoints are best-effort), and the enrichment state is per-process.
