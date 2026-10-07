# SIEMQL — Search Language

Detection rules answer *"did this known-bad thing happen?"*. Search answers
*"what the hell happened?"*, which is what an analyst actually does during an
investigation. Every commercial SIEM has a query language — SPL in Splunk, KQL in
Sentinel, EQL in Elastic. This is a working equivalent over the normalized events.

```bash
python -m siem.cli shell --input-dir sample_logs          # interactive
python -m siem.cli search 'event.outcome = failure | top source.ip 10'
python -m siem.cli search --examples                      # 10 worked examples
```

## Syntax

```
<filter> | <command> | <command> ...
```

### Filter operators

| Operator | Example |
|---|---|
| `=` `!=` | `event.outcome = failure` |
| `>` `>=` `<` `<=` | `http.response.status_code >= 400` |
| `=~` | `url.path =~ "union.*select"` (regex, case-insensitive) |
| `contains` / `startswith` / `endswith` | `url.path contains ".env"` |
| `in [a, b]` | `user.name in [root, admin]` |
| `= *` | `threat.indicator.source = *` (field exists) |
| `and` `or` `not` `( )` | `not source.internal = true and event.outcome = failure` |

### Commands

| Command | Purpose |
|---|---|
| `where <expr>` | filter mid-pipeline |
| `stats <agg> [as name] by <fields>` | aggregate |
| `sort [-]field` | `-` prefix sorts descending |
| `head N` / `tail N` | limit rows |
| `fields a, b, c` | select columns |
| `top <field> [N]` / `rare <field> [N]` | frequency with percentages |
| `timechart span=1h [by field]` | bucket events over time |
| `eval name = field` | alias a field |

Aggregations: `count`, `dc(f)` (distinct count), `sum(f)`, `avg(f)`, `min(f)`,
`max(f)`, `values(f)`.

## The query that matters

This one separates a broken service account from a real password spray — both
produce a pile of failed logins, and the difference is the username count:

```
event.outcome = failure
  | stats count, dc(user.name) as users by source.ip
  | sort -count
```

```
  SOURCE.IP      COUNT  USERS
  ─────────────  ─────  ─────
  10.0.0.41      84     1       ← misconfigured backup agent, one account
  203.0.113.45   60     3       ← brute force, few accounts
  198.51.100.77  42     14      ← password spray, many accounts
  141.98.80.12   40     3
  66.249.66.1    12     0
```

Three different stories in one table. No detection rule told you that; you asked.

## More worked examples

```bash
# Timeline for one attacker across every log source
source.ip = "198.51.100.77" | sort @timestamp | fields @timestamp, event.action, user.name

# Usernames guessed that do not exist on the system
event.provider = sshd and user.invalid = true | top user.name 20

# Where are failed logins coming from geographically
not source.internal = true and event.category = authentication
  | stats count by source.geo.country_name

# Most-probed missing paths - what are scanners looking for
event.category = web and http.response.status_code = 404 | top url.path 15

# Activity volume over the day, by category
timechart span=1h count by event.category

# Everything from threat-intel-flagged sources
threat.indicator.source = * | stats count by source.ip, threat.indicator.category

# Successful privileged logins
user.privileged = true and event.outcome = success
  | fields @timestamp, user.name, source.ip, host.name
```

## Shell commands

Inside `siem shell`:

| | |
|---|---|
| `.fields` | every field present, with event counts — the fastest way to learn the schema |
| `.examples` | the worked examples above |
| `.history` | queries run this session |
| `.help` | syntax reference |
| `.quit` | exit |

## Honest limitations

**No index.** Every query is a linear scan over events held in memory. Fine for
the volumes this pipeline handles; a real backend builds inverted indexes and
answers in milliseconds over billions of rows.

**No joins or subsearches.** SPL can correlate two result sets; this cannot.

**No streaming queries.** You search a loaded corpus, not a live tail.

**Aggregation only at the end.** No `eventstats`, no windowed functions over
groups.

What it does prove: the pipeline produces data clean and well-named enough to be
queried ad hoc, which is the real test of whether normalization was done properly.
