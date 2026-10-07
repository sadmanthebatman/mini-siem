"""
query.py - SIEMQL, an interactive search language over normalized events.

The thing every commercial SIEM has and most hobby projects lack: a way to ask
questions of the data that nobody wrote a rule for in advance. Detection rules
answer "did this known-bad thing happen". Search answers "what the hell
happened", which is what an analyst actually does during an investigation.

Syntax, pipeline-style like SPL:

    source.ip = "203.0.113.45" and event.outcome = failure
      | stats count, dc(user.name) as users by source.ip
      | sort -count
      | head 10

Filter operators
    =  !=  >  >=  <  <=        comparison (numbers compare numerically)
    =~                         regex match
    contains / startswith / endswith
    in [a, b, c]               membership
    and / or / not / ( )       boolean composition
    field = *                  field exists and is non-null

Commands
    where <expr>                       filter mid-pipeline
    fields a, b, c                     select columns
    stats <agg> [as name] by <fields>  aggregate: count, dc(f), sum(f),
                                       avg(f), min(f), max(f), values(f)
    sort [-]field                       - prefix for descending
    head N / tail N                    limit
    top <field> [N] / rare <field> [N] frequency analysis
    timechart span=1h [agg]            bucket by time
    eval name = <field>                alias a field onto a new name

Everything runs in memory over the parsed event list. There is no index, so
this is linear scan - fine for the volumes this pipeline handles, and the
honest tradeoff versus a real search backend.
"""
from __future__ import annotations

import re
import statistics
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Iterable

from .models import Event

# ==========================================================================
# Tokenizer
# ==========================================================================
TOKEN_RE = re.compile(r"""
    (?P<WS>\s+)
  | (?P<STRING>"[^"]*"|'[^']*')
  | (?P<DURATION>\d+(?:\.\d+)?[smhd]\b)
  | (?P<NUMBER>-?\d+\.\d+|-?\d+)
  | (?P<PIPE>\|)
  | (?P<LBRACK>\[) | (?P<RBRACK>\])
  | (?P<LPAREN>\() | (?P<RPAREN>\))
  | (?P<COMMA>,)
  | (?P<OP>=~|>=|<=|!=|=|>|<)
  | (?P<MINUS>-)
  | (?P<STAR>\*)
  | (?P<IDENT>[@A-Za-z_][A-Za-z0-9_.@-]*)
""", re.VERBOSE)

KEYWORDS = {"and", "or", "not", "by", "as", "in", "contains", "startswith", "endswith", "span"}


class Token:
    __slots__ = ("kind", "value")

    def __init__(self, kind: str, value: Any):
        self.kind, self.value = kind, value

    def __repr__(self):
        return f"{self.kind}:{self.value}"


class QueryError(Exception):
    """Raised on malformed queries. Message is shown directly to the user."""


def tokenize(text: str) -> list[Token]:
    tokens, pos = [], 0
    while pos < len(text):
        m = TOKEN_RE.match(text, pos)
        if not m:
            raise QueryError(f"unexpected character {text[pos]!r} at position {pos}")
        pos = m.end()
        kind = m.lastgroup
        value = m.group()
        if kind == "WS":
            continue
        if kind == "DURATION":
            tokens.append(Token("VALUE", value))
        elif kind == "STRING":
            tokens.append(Token("VALUE", value[1:-1]))
        elif kind == "NUMBER":
            tokens.append(Token("VALUE", float(value) if "." in value else int(value)))
        elif kind == "IDENT":
            low = value.lower()
            tokens.append(Token("KW" if low in KEYWORDS else "IDENT",
                                low if low in KEYWORDS else value))
        else:
            tokens.append(Token(kind, value))
    return tokens


# ==========================================================================
# Filter expressions
# ==========================================================================
def _get(row: Any, field: str) -> Any:
    if isinstance(row, Event):
        return row.get_path(field)
    if isinstance(row, dict):
        if field in row:
            return row[field]
        node: Any = row
        for part in field.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return None
        return node
    return getattr(row, field, None)


def _compare(value: Any, op: str, expected: Any) -> bool:
    if value is None:
        return op == "!=" and expected is not None
    if op in ("=", "!="):
        if expected == "*":
            return (value is not None) == (op == "=")
        if isinstance(expected, bool) or str(expected).lower() in ("true", "false"):
            exp = expected if isinstance(expected, bool) else str(expected).lower() == "true"
            return (bool(value) == exp) == (op == "=")
        eq = str(value).lower() == str(expected).lower()
        return eq if op == "=" else not eq
    if op == "=~":
        return re.search(str(expected), str(value), re.IGNORECASE) is not None
    if op == "contains":
        return str(expected).lower() in str(value).lower()
    if op == "startswith":
        return str(value).lower().startswith(str(expected).lower())
    if op == "endswith":
        return str(value).lower().endswith(str(expected).lower())
    if op == "in":
        return any(str(value).lower() == str(e).lower() for e in expected)
    # numeric / datetime comparison
    try:
        if isinstance(value, datetime):
            other = expected if isinstance(expected, datetime) else datetime.fromisoformat(str(expected))
        else:
            value, other = float(value), float(expected)
    except (TypeError, ValueError):
        value, other = str(value), str(expected)
    return {">": value > other, ">=": value >= other,
            "<": value < other, "<=": value <= other}.get(op, False)


class Parser:
    """Recursive-descent parser for filter expressions."""

    def __init__(self, tokens: list[Token]):
        self.tokens, self.pos = tokens, 0

    def peek(self) -> Token | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> Token:
        tok = self.peek()
        if tok is None:
            raise QueryError("unexpected end of query")
        self.pos += 1
        return tok

    def expect(self, kind: str) -> Token:
        tok = self.next()
        if tok.kind != kind:
            raise QueryError(f"expected {kind}, found {tok.value!r}")
        return tok

    def parse_expr(self):
        return self.parse_or()

    def parse_or(self):
        left = self.parse_and()
        while (t := self.peek()) and t.kind == "KW" and t.value == "or":
            self.next()
            right = self.parse_and()
            left = (lambda a, b: lambda row: a(row) or b(row))(left, right)
        return left

    def parse_and(self):
        left = self.parse_unary()
        while (t := self.peek()) and t.kind == "KW" and t.value == "and":
            self.next()
            right = self.parse_unary()
            left = (lambda a, b: lambda row: a(row) and b(row))(left, right)
        return left

    def parse_unary(self):
        t = self.peek()
        if t and t.kind == "KW" and t.value == "not":
            self.next()
            inner = self.parse_unary()
            return lambda row: not inner(row)
        if t and t.kind == "LPAREN":
            self.next()
            inner = self.parse_expr()
            self.expect("RPAREN")
            return inner
        return self.parse_comparison()

    def parse_comparison(self):
        field_tok = self.next()
        if field_tok.kind != "IDENT":
            raise QueryError(f"expected a field name, found {field_tok.value!r}")
        field = field_tok.value
        op_tok = self.peek()
        if op_tok is None:
            # bare field: treat as existence check
            return lambda row: _get(row, field) is not None
        if op_tok.kind == "OP":
            self.next()
            op = op_tok.value
        elif op_tok.kind == "KW" and op_tok.value in ("contains", "startswith", "endswith", "in"):
            self.next()
            op = op_tok.value
        else:
            return lambda row: _get(row, field) is not None

        if op == "in":
            self.expect("LBRACK")
            values = []
            while True:
                tok = self.next()
                if tok.kind == "RBRACK":
                    break
                if tok.kind == "COMMA":
                    continue
                values.append(tok.value)
            return lambda row: _compare(_get(row, field), "in", values)

        val_tok = self.next()
        if val_tok.kind not in ("VALUE", "IDENT", "STAR"):
            raise QueryError(f"expected a value after {op!r}, found {val_tok.value!r}")
        expected = "*" if val_tok.kind == "STAR" else val_tok.value
        return lambda row: _compare(_get(row, field), op, expected)


# ==========================================================================
# Pipeline commands
# ==========================================================================
AGGREGATORS = {
    "count": lambda vals: len(vals),
    "dc": lambda vals: len({str(v) for v in vals if v is not None}),
    "count_distinct": lambda vals: len({str(v) for v in vals if v is not None}),
    "sum": lambda vals: round(sum(float(v) for v in vals if v is not None), 2),
    "avg": lambda vals: round(statistics.mean([float(v) for v in vals if v is not None]), 2)
                        if any(v is not None for v in vals) else 0,
    "min": lambda vals: min((v for v in vals if v is not None), default=None),
    "max": lambda vals: max((v for v in vals if v is not None), default=None),
    "values": lambda vals: ", ".join(sorted({str(v) for v in vals if v is not None})[:10]),
}


def _parse_duration(text: str) -> timedelta:
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    unit = text[-1].lower()
    if unit not in units:
        raise QueryError(f"bad duration {text!r} (use 30s, 5m, 1h, 1d)")
    return timedelta(**{units[unit]: float(text[:-1])})


def _rowify(item: Any) -> dict:
    """Flatten an Event or Alert into a plain row dict for display."""
    if isinstance(item, Event):
        return {k: v for k, v in item.items()}
    if hasattr(item, "to_dict"):
        return item.to_dict()
    return dict(item)


def _cmd_stats(rows: list, args: list[Token]) -> list[dict]:
    """stats count, dc(user.name) as users by source.ip"""
    aggs: list[tuple[str, str | None, str]] = []   # (func, field, output_name)
    group_by: list[str] = []
    i, in_by = 0, False
    while i < len(args):
        tok = args[i]
        if tok.kind == "KW" and tok.value == "by":
            in_by = True
            i += 1
            continue
        if tok.kind == "COMMA":
            i += 1
            continue
        if in_by:
            if tok.kind == "IDENT":
                group_by.append(tok.value)
            i += 1
            continue
        if tok.kind == "IDENT":
            func = tok.value.lower()
            field = None
            if func not in AGGREGATORS:
                raise QueryError(f"unknown aggregation {func!r}. "
                                 f"Available: {', '.join(sorted(AGGREGATORS))}")
            if i + 1 < len(args) and args[i + 1].kind == "LPAREN":
                i += 2
                field = args[i].value
                i += 1
                if i < len(args) and args[i].kind == "RPAREN":
                    i += 1
            else:
                i += 1
            name = f"{func}({field})" if field else func
            if i + 1 < len(args) and args[i].kind == "KW" and args[i].value == "as":
                name = args[i + 1].value
                i += 2
            aggs.append((func, field, name))
            continue
        i += 1

    if not aggs:
        aggs = [("count", None, "count")]

    groups: dict[tuple, list] = defaultdict(list)
    for row in rows:
        key = tuple(str(_get(row, f)) for f in group_by) if group_by else ("all",)
        groups[key].append(row)

    out = []
    for key, members in groups.items():
        rec: dict = {}
        if group_by:
            rec.update(dict(zip(group_by, key)))
        for func, field, name in aggs:
            vals = [_get(r, field) for r in members] if field else members
            rec[name] = AGGREGATORS[func](vals)
        out.append(rec)
    return out


def _cmd_timechart(rows: list, args: list[Token]) -> list[dict]:
    """timechart span=1h count by event.category"""
    span = timedelta(hours=1)
    group_by: list[str] = []
    i, in_by = 0, False
    while i < len(args):
        tok = args[i]
        if tok.kind == "KW" and tok.value == "span":
            if i + 2 < len(args):
                span = _parse_duration(str(args[i + 2].value))
                i += 3
                continue
        if tok.kind == "KW" and tok.value == "by":
            in_by = True
        elif in_by and tok.kind == "IDENT":
            group_by.append(tok.value)
        i += 1

    buckets: dict[tuple, int] = defaultdict(int)
    for row in rows:
        ts = _get(row, "@timestamp") or _get(row, "timestamp")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except ValueError:
                continue
        if not isinstance(ts, datetime):
            continue
        secs = int(span.total_seconds())
        epoch = int(ts.timestamp()) // secs * secs
        bucket = datetime.fromtimestamp(epoch)
        key = (bucket,) + tuple(str(_get(row, f)) for f in group_by)
        buckets[key] += 1

    out = []
    for key, count in sorted(buckets.items()):
        rec = {"time": key[0].strftime("%Y-%m-%d %H:%M")}
        rec.update(dict(zip(group_by, key[1:])))
        rec["count"] = count
        out.append(rec)
    return out


def _cmd_sort(rows: list[dict], args: list[Token]) -> list[dict]:
    """sort -count  (descending)   |   sort user.name  (ascending)"""
    if not args:
        return rows
    desc = False
    idx = 0
    if args[0].kind == "MINUS":
        desc, idx = True, 1
    if idx >= len(args):
        raise QueryError("sort needs a field name after '-'")
    field = str(args[idx].value).lstrip("-")
    if str(args[idx].value).startswith("-"):
        desc = True

    def key(row):
        v = _get(row, field)
        if v is None:
            return (1, 0, "")
        if isinstance(v, (int, float)):
            return (0, -v if desc else v, "")
        if isinstance(v, datetime):
            return (0, -v.timestamp() if desc else v.timestamp(), "")
        return (0, 0, str(v).lower())

    out = sorted(rows, key=key)
    if desc and out and isinstance(_get(out[0], field), str):
        out.reverse()
    return out


def _cmd_top(rows: list, args: list[Token], rare: bool = False) -> list[dict]:
    if not args:
        raise QueryError("top/rare needs a field name")
    field = str(args[0].value)
    limit = int(args[1].value) if len(args) > 1 and isinstance(args[1].value, (int, float)) else 10
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        v = _get(row, field)
        if v is not None:
            counts[str(v)] += 1
    total = sum(counts.values()) or 1
    ordered = sorted(counts.items(), key=lambda kv: (kv[1], kv[0]) if rare else (-kv[1], kv[0]))
    return [{field: k, "count": v, "percent": f"{v/total:.1%}"} for k, v in ordered[:limit]]


# ==========================================================================
# Engine
# ==========================================================================
class Query:
    def __init__(self, text: str):
        self.text = text
        # A leading pipe means there is no filter stage - everything is a
        # command, so "| frobnicate" must error rather than be read as a
        # bare field-existence filter.
        self.leading_pipe = text.strip().startswith("|")
        self.stages = [s.strip() for s in self._split_pipes(text) if s.strip()]

    @staticmethod
    def _split_pipes(text: str) -> list[str]:
        """Split on | but not inside quotes or brackets."""
        parts, buf, depth, quote = [], [], 0, None
        for ch in text:
            if quote:
                buf.append(ch)
                if ch == quote:
                    quote = None
                continue
            if ch in "\"'":
                quote = ch
                buf.append(ch)
            elif ch == "[":
                depth += 1
                buf.append(ch)
            elif ch == "]":
                depth -= 1
                buf.append(ch)
            elif ch == "|" and depth == 0:
                parts.append("".join(buf))
                buf = []
            else:
                buf.append(ch)
        parts.append("".join(buf))
        return parts

    def run(self, data: Iterable) -> list[dict]:
        rows: list = list(data)
        for index, stage in enumerate(self.stages):
            tokens = tokenize(stage)
            if not tokens:
                continue
            head = tokens[0]
            name = str(head.value).lower() if head.kind in ("IDENT", "KW") else ""

            if index == 0 and not self.leading_pipe and name not in ("where", "stats", "sort", "head", "tail",
                                           "fields", "top", "rare", "timechart", "eval"):
                parser = Parser(tokens)
                predicate = parser.parse_expr()
                if parser.peek() is not None:
                    raise QueryError(f"unexpected {parser.peek().value!r} after filter expression")
                rows = [r for r in rows if predicate(r)]
                continue

            args = tokens[1:]
            if name == "where":
                rows = [r for r in rows if Parser(args).parse_expr()(r)]
            elif name == "stats":
                rows = _cmd_stats(rows, args)
            elif name == "timechart":
                rows = _cmd_timechart(rows, args)
            elif name == "sort":
                rows = _cmd_sort([_rowify(r) if not isinstance(r, dict) else r for r in rows], args)
            elif name == "head":
                n = int(args[0].value) if args else 10
                rows = rows[:n]
            elif name == "tail":
                n = int(args[0].value) if args else 10
                rows = rows[-n:]
            elif name == "fields":
                wanted = [str(a.value) for a in args if a.kind == "IDENT"]
                rows = [{f: _get(r, f) for f in wanted} for r in rows]
            elif name == "top":
                rows = _cmd_top(rows, args)
            elif name == "rare":
                rows = _cmd_top(rows, args, rare=True)
            elif name == "eval":
                # eval newname = existing.field
                if len(args) >= 3:
                    new, src = str(args[0].value), str(args[2].value)
                    rows = [{**_rowify(r), new: _get(r, src)} for r in rows]
            else:
                raise QueryError(f"unknown command {name!r}")

        return [r if isinstance(r, dict) else _rowify(r) for r in rows]


def search(data: Iterable, query: str) -> list[dict]:
    return Query(query).run(data)


# ==========================================================================
# Table rendering
# ==========================================================================
def render_table(rows: list[dict], max_rows: int = 50, max_width: int = 46) -> str:
    if not rows:
        return "  (no results)"
    columns: list[str] = []
    for row in rows[:200]:
        for key in row:
            if key not in columns:
                columns.append(key)
    # drop columns that are entirely empty
    columns = [c for c in columns if any(r.get(c) not in (None, "") for r in rows)]
    if len(columns) > 9:
        columns = columns[:9]

    def fmt(v) -> str:
        if v is None:
            return "-"
        if isinstance(v, datetime):
            return v.strftime("%m-%d %H:%M:%S")
        if isinstance(v, float):
            return f"{v:g}"
        s = str(v)
        return s[:max_width - 1] + "…" if len(s) > max_width else s

    widths = {c: min(max(len(c), *(len(fmt(r.get(c))) for r in rows[:max_rows])), max_width)
              for c in columns}
    sep = "  "
    out = [sep.join(c.upper().ljust(widths[c]) for c in columns),
           sep.join("─" * widths[c] for c in columns)]
    for row in rows[:max_rows]:
        out.append(sep.join(fmt(row.get(c)).ljust(widths[c])[:widths[c]] for c in columns))
    if len(rows) > max_rows:
        out.append(f"... {len(rows) - max_rows} more rows ({len(rows)} total)")
    else:
        out.append(f"({len(rows)} row{'s' if len(rows) != 1 else ''})")
    return "\n".join("  " + line for line in out)


EXAMPLES = [
    ('event.outcome = failure and source.internal = false',
     'all failed logins from external sources'),
    ('event.category = authentication | top user.name 10',
     'most-targeted accounts'),
    ('event.outcome = failure | stats count, dc(user.name) as users by source.ip | sort -count',
     'failures per source with distinct usernames tried - spray detection by hand'),
    ('url.path =~ "union.*select"',
     'SQL injection attempts by regex'),
    ('source.ip = "198.51.100.77" | sort @timestamp | fields @timestamp, event.action, user.name',
     'full timeline for one attacker'),
    ('event.category = web and http.response.status_code = 404 | top url.path 15',
     'most-probed missing paths'),
    ('timechart span=1h count by event.category',
     'event volume over time by category'),
    ('threat.indicator.source = * | stats count by source.ip, threat.indicator.category',
     'activity from threat-intel-flagged addresses'),
    ('user.privileged = true and event.outcome = success | fields @timestamp, user.name, source.ip',
     'successful privileged logins'),
    ('event.provider = sshd and user.invalid = true | top user.name 20',
     'usernames guessed that do not exist'),
]
