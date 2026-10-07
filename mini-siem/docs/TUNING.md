# Tuning Record

Alert fatigue is the defining failure mode of a SOC. A ruleset that nobody trusts
gets ignored, and an ignored ruleset is worse than none because it creates the
illusion of coverage. This file documents every false positive this project
produced and the measured decision that resolved it.

## Benign noise deliberately planted in the corpus

The labelled corpus is adversarial in both directions. These behaviours are
innocent but look suspicious, and exist specifically to punish lazy rules:

| Behaviour | Why it tempts a false positive |
|---|---|
| Backup agent with an expired password: 6 failures in 25 seconds, hourly | Bursty failures from one source — looks exactly like brute force |
| Developer SSH client retrying a stale key, 4 failures in 12 seconds | Same shape, smaller volume |
| Googlebot requesting 12 removed pages | High 404 count from one source — looks like directory scanning |
| Users mistyping passwords before succeeding | Failure-then-success — the compromise signature |
| Staff authenticating outside 09:00–17:00 | Off-hours access |
| Internal jump hosts generating high event volume | Volume anomaly |

## Threshold sweep: ssh_brute_force

Measured by `python -m siem.cli metrics --threshold-sweep`, which re-runs the whole
pipeline at each value against the labelled corpus.

| Threshold (failures / 60s) | Alerts | True positives | False positives | Precision |
|---|---|---|---|---|
| 3 | 5 | 3 | 2 | 60% |
| 5 | 4 | 3 | 1 | 75% |
| **8** | **3** | **3** | **0** | **100%** |
| **10 (chosen)** | **3** | **3** | **0** | **100%** |
| 15 | 2 | 2 | 0 | 100% |
| 20 | 2 | 2 | 0 | 100% |
| 30 | 1 | 1 | 0 | 100% |

**Decision: 10.** At 3 and 5 the misconfigured backup agent and the developer's
stale key both alert, and an analyst learns within a week to dismiss this rule on
sight. At 15 and above, the Windows credential attack in S4 — which paced itself
slower — starts being missed; at 30 only one of three real attacks survives.

Ten sits in the middle of the plateau rather than at its edge, which leaves margin
for environments noisier than this corpus. The honest limitation: an attacker who
paces below 10 attempts per minute evades this rule entirely. That is not a flaw to
hide, it is the reason the password-spray rule uses a 10-minute window and the
behavioral baseline exists.

## False positives found and fixed

### 1. Stateless compromise rule — 56 alerts, 96% FP rate

`003_account_compromise.yml` matched `event.outcome: success`, intending "success
after failures". Stateless Sigma cannot express "after", so it fired on every
legitimate login in the environment: 56 critical alerts on a corpus containing 2
real compromises.

**Fix:** rule disabled; the real implementation is stateful
(`correlation.py::success_after_failures`), tracking prior failures per source
inside a sliding window. The YAML file is retained for its ATT&CK mapping and
response guidance, and `test_stateless_compromise_rule_is_disabled` prevents
anyone re-enabling it.

**Lesson worth stating in an interview:** not every detection can be a signature.
Recognising which ones need state is most of detection engineering.

### 2. Behavioral hour baseline — 9 alerts on ordinary staff

The unusual-hour baseline flagged internal users logging in at 21:00. People work
late; this is not an incident.

**Fix:** suppress for internal sources entirely, retain for external ones where
off-hours access is genuinely anomalous. Cut 9 false positives to 0 with no loss of
true positives — the compromised `deploy` account was still caught, because the
attacker's session came from an external address.

### 3. Sudo events bypassing the internal check

Local actions such as sudo carry no source address, so `source.internal` was absent
and the suppression above never applied to them.

**Fix:** restrict hour and host baselines to `event.category: authentication`.
Local privilege use is covered by `priv_esc_after_external_login` instead, which
correlates it with a preceding external login.

### 4. Volume outlier on internal infrastructure

Jump hosts, CI runners and monitoring legitimately generate far more events than a
workstation, so the 3-sigma volume rule flagged them every run.

**Fix:** compute the baseline from external sources only, and skip internal sources
at detection time.

### 5. Entity bucket named "unknown"

Windows local logons carry no `IpAddress`, so every one of them collapsed into a
single entity called "unknown" — merging unrelated activity into one meaningless
high-risk blob.

**Fix:** entity resolution falls back `source.ip` → `host.name` → `user.name`, and
labels the entity type accordingly.

## Result

| | Before tuning | After tuning |
|---|---|---|
| Alerts | 86 | 28 |
| False positives | 59 | 0 |
| Precision | 31% | 100% |
| Recall | 100% | 100% |

Recall never dropped. Every tuning change removed noise, not coverage — which is
the only kind of tuning worth doing.

## What would change in production

These thresholds are tuned to this corpus. In a real environment:

1. Run in monitor-only mode for two weeks and collect the alert volume per rule.
2. Rank rules by alerts-per-day; anything over ~5/day for a single analyst needs
   tuning or an allowlist, not a bigger team.
3. Build allowlists for known scanners, monitoring and backup infrastructure rather
   than raising thresholds globally — a raised threshold weakens the rule everywhere,
   an allowlist weakens it in exactly one place.
4. Re-measure after every change. A tuning decision without a before-and-after
   number is a preference, not engineering.
