"""
dashboard.py - Self-contained HTML SOC dashboard.

No Streamlit, no CDN, no build step. One HTML file with inline SVG charts
that opens in any browser and can be committed as an artifact or attached to
a report. Everything is generated from the PipelineResult.
"""
from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

SEV_COLOR = {"critical": "#ff4757", "high": "#ff7f50", "medium": "#ffc048",
             "low": "#4bcffa", "informational": "#7f8fa6"}


def _esc(x) -> str:
    return html.escape(str(x))


def _timeline_svg(alerts, width=1100, height=190) -> str:
    """Attack timeline: one dot per alert, coloured by severity."""
    if not alerts:
        return "<p class='muted'>No alerts</p>"
    times = [a.timestamp for a in alerts]
    t0, t1 = min(times), max(times)
    span = max((t1 - t0).total_seconds(), 1)
    rows = ["critical", "high", "medium", "low"]
    pad_l, pad_r, pad_t = 70, 30, 24
    plot_w = width - pad_l - pad_r
    row_h = (height - pad_t - 34) / len(rows)

    parts = [f"<svg viewBox='0 0 {width} {height}' class='chart'>"]
    for i, sev in enumerate(rows):
        y = pad_t + i * row_h + row_h / 2
        parts.append(f"<line x1='{pad_l}' y1='{y}' x2='{width-pad_r}' y2='{y}' "
                     f"stroke='#232838' stroke-width='1'/>")
        parts.append(f"<text x='{pad_l-12}' y='{y+4}' text-anchor='end' class='axis'>{sev}</text>")
    for a in alerts:
        if a.severity not in rows:
            continue
        i = rows.index(a.severity)
        x = pad_l + ((a.timestamp - t0).total_seconds() / span) * plot_w
        y = pad_t + i * row_h + row_h / 2
        r = 7 if a.severity == "critical" else 5
        tip = f"{a.timestamp:%H:%M:%S} · {a.rule_name} · {a.entity}"
        parts.append(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='{r}' fill='{SEV_COLOR[a.severity]}' "
                     f"fill-opacity='0.85' stroke='#0b0e17' stroke-width='1.5'>"
                     f"<title>{_esc(tip)}</title></circle>")
    for frac in (0, 0.25, 0.5, 0.75, 1):
        x = pad_l + frac * plot_w
        ts = t0 + (t1 - t0) * frac
        parts.append(f"<text x='{x:.0f}' y='{height-12}' text-anchor='middle' class='axis'>"
                     f"{ts:%H:%M}</text>")
    parts.append("</svg>")
    return "".join(parts)


def _bar_svg(pairs, width=520, bar_h=26, color="#5b8def") -> str:
    if not pairs:
        return "<p class='muted'>No data</p>"
    top = max(v for _, v in pairs) or 1
    height = len(pairs) * (bar_h + 8) + 10
    label_w = 190
    parts = [f"<svg viewBox='0 0 {width} {height}' class='chart'>"]
    for i, (label, value) in enumerate(pairs):
        y = i * (bar_h + 8) + 6
        w = max((value / top) * (width - label_w - 70), 3)
        parts.append(f"<text x='{label_w-10}' y='{y+bar_h*0.7}' text-anchor='end' class='axis'>"
                     f"{_esc(label)[:28]}</text>")
        parts.append(f"<rect x='{label_w}' y='{y}' width='{w:.1f}' height='{bar_h}' rx='4' "
                     f"fill='{color}' fill-opacity='0.85'/>")
        parts.append(f"<text x='{label_w+w+10:.1f}' y='{y+bar_h*0.7}' class='axis strong'>{value}</text>")
    parts.append("</svg>")
    return "".join(parts)


def _donut_svg(counts: dict, size=190) -> str:
    total = sum(counts.values()) or 1
    cx = cy = size / 2
    r, stroke = size / 2 - 18, 26
    circ = 2 * 3.14159265 * r
    offset = 0.0
    parts = [f"<svg viewBox='0 0 {size} {size}' class='donut'>"]
    for sev in ("critical", "high", "medium", "low", "informational"):
        n = counts.get(sev, 0)
        if not n:
            continue
        frac = n / total
        parts.append(
            f"<circle cx='{cx}' cy='{cy}' r='{r}' fill='none' stroke='{SEV_COLOR[sev]}' "
            f"stroke-width='{stroke}' stroke-dasharray='{circ*frac:.2f} {circ:.2f}' "
            f"stroke-dashoffset='{-circ*offset:.2f}' transform='rotate(-90 {cx} {cy})'>"
            f"<title>{sev}: {n}</title></circle>")
        offset += frac
    parts.append(f"<text x='{cx}' y='{cy-2}' text-anchor='middle' class='donut-num'>{total}</text>"
                 f"<text x='{cx}' y='{cy+18}' text-anchor='middle' class='axis'>alerts</text></svg>")
    return "".join(parts)


def render_dashboard(result, path: str = "out/dashboard.html") -> str:
    s = result.summary()
    sev_counts = s["alerts_by_severity"]
    entities = result.risk_engine.ranked()[:10] if result.risk_engine else []
    rule_counts = Counter(a.rule_name for a in result.alerts).most_common(8)
    tech_counts: dict[str, int] = defaultdict(int)
    for a in result.alerts:
        for t in a.tags:
            if t.upper().startswith("T") and t[1:2].isdigit():
                tech_counts[t.upper()] += 1

    # ---- cases ----
    case_html = []
    for c in result.cases:
        tl = "".join(
            f"<li><span class='t'>{a.timestamp:%H:%M:%S}</span>"
            f"<span class='pill' style='background:{SEV_COLOR[a.severity]}22;color:{SEV_COLOR[a.severity]}'>"
            f"{a.severity}</span>{_esc(a.rule_name)}</li>"
            for a in c.entity.timeline[:10])
        acts = "".join(f"<li>{_esc(a)}</li>" for a in c.recommended_actions[:6])
        techs = "".join(f"<span class='tag'>{_esc(t)}</span>" for t in c.entity.techniques[:10])
        case_html.append(f"""
        <details class="case" {'open' if c.severity == 'critical' else ''}>
          <summary>
            <span class="sev" style="background:{SEV_COLOR[c.severity]}">{c.severity.upper()}</span>
            <span class="cid">{_esc(c.id)}</span>
            <span class="ctitle">{_esc(c.entity.type)} {_esc(c.entity.id)}</span>
            <span class="score">risk {c.entity.score:.0f}</span>
            <span class="sla">SLA {c.sla_hours}h</span>
          </summary>
          <div class="case-body">
            <p class="summary">{_esc(c.summary)}</p>
            <div class="tags">{techs}</div>
            <div class="cols">
              <div><h4>Attack timeline</h4><ul class="timeline">{tl}</ul></div>
              <div><h4>Recommended actions</h4><ol class="actions">{acts}</ol></div>
            </div>
          </div>
        </details>""")

    # ---- alert table ----
    rows = []
    for a in sorted(result.alerts, key=lambda a: a.timestamp):
        ctx = " · ".join(f"{k.split('.')[-1]}={v}" for k, v in list(a.context.items())[:3])
        rows.append(f"""<tr data-sev="{a.severity}">
          <td class="mono">{a.timestamp:%H:%M:%S}</td>
          <td><span class="dot" style="background:{SEV_COLOR[a.severity]}"></span>{a.severity}</td>
          <td>{_esc(a.rule_name)}</td>
          <td class="mono">{_esc(a.entity)}</td>
          <td class="mono">{a.risk_score}</td>
          <td class="muted">{_esc(a.description)[:150]}</td>
          <td class="muted mono small">{_esc(ctx)}</td></tr>""")

    actions_rows = "".join(
        f"<tr><td>{'✓' if a['executed'] else '○'}</td><td>{_esc(a['action'])}</td>"
        f"<td class='mono'>{_esc(a['target'])}</td><td class='muted'>{_esc(a['detail'])}</td>"
        f"<td class='mono small'>{_esc(a['mode'])}</td></tr>" for a in result.actions)

    parse_rows = "".join(
        f"<tr><td class='mono'>{_esc(Path(p).name)}</td><td>{_esc(st['source'])}</td>"
        f"<td class='mono'>{st['parsed']}</td><td class='mono muted'>{st['skipped']}</td></tr>"
        for p, st in result.stats.get("parsing", {}).items())

    d = result.stats.get("detections", {})
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    return _write(path, f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIEM Dashboard</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#0b0e17;color:#e6e9f0;
 font-family:ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:14px;line-height:1.5}}
.wrap{{max-width:1240px;margin:0 auto;padding:28px 22px 60px}}
header{{display:flex;justify-content:space-between;align-items:flex-end;
 border-bottom:1px solid #1d2231;padding-bottom:18px;margin-bottom:26px;flex-wrap:wrap;gap:12px}}
h1{{margin:0;font-size:24px;letter-spacing:-.4px}}
h1 span{{color:#5b8def}}
h2{{font-size:13px;text-transform:uppercase;letter-spacing:1.4px;color:#8a93a8;
 margin:34px 0 14px;font-weight:600}}
h4{{margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#8a93a8}}
.sub{{color:#8a93a8;font-size:13px}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}
.kpi{{background:#121726;border:1px solid #1d2231;border-radius:10px;padding:16px 18px}}
.kpi .n{{font-size:28px;font-weight:650;letter-spacing:-.5px}}
.kpi .l{{color:#8a93a8;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-top:3px}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
.grid3{{display:grid;grid-template-columns:220px 1fr;gap:16px;align-items:center}}
.card{{background:#121726;border:1px solid #1d2231;border-radius:10px;padding:18px}}
.chart{{width:100%;height:auto}}
.donut{{width:190px;height:190px}}
.donut-num{{fill:#e6e9f0;font-size:30px;font-weight:650}}
.axis{{fill:#8a93a8;font-size:11px}}
.axis.strong{{fill:#e6e9f0;font-weight:600}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;color:#8a93a8;font-weight:600;font-size:11px;text-transform:uppercase;
 letter-spacing:.8px;padding:8px 10px;border-bottom:1px solid #1d2231}}
td{{padding:8px 10px;border-bottom:1px solid #161b29;vertical-align:top}}
tr:hover td{{background:#151a28}}
.mono{{font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:12px}}
.small{{font-size:11px}}
.muted{{color:#8a93a8}}
.dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px}}
.case{{background:#121726;border:1px solid #1d2231;border-radius:10px;margin-bottom:10px;
 overflow:hidden}}
.case summary{{padding:14px 18px;cursor:pointer;display:flex;align-items:center;gap:12px;
 flex-wrap:wrap;list-style:none}}
.case summary::-webkit-details-marker{{display:none}}
.case[open] summary{{border-bottom:1px solid #1d2231}}
.sev{{color:#0b0e17;font-weight:700;font-size:10px;letter-spacing:.8px;padding:3px 9px;
 border-radius:4px}}
.cid{{font-family:ui-monospace,monospace;font-size:12px;color:#8a93a8}}
.ctitle{{font-weight:600;flex:1}}
.score,.sla{{font-size:11px;color:#8a93a8;font-family:ui-monospace,monospace}}
.case-body{{padding:16px 18px}}
.summary{{margin:0 0 12px;color:#c3c9d6}}
.cols{{display:grid;grid-template-columns:1fr 1fr;gap:22px}}
.timeline{{list-style:none;padding:0;margin:0}}
.timeline li{{padding:5px 0;border-bottom:1px solid #161b29;display:flex;gap:10px;
 align-items:center;font-size:13px}}
.timeline .t{{font-family:ui-monospace,monospace;font-size:11px;color:#8a93a8;width:62px}}
.pill{{font-size:10px;padding:2px 7px;border-radius:3px;font-weight:600;text-transform:uppercase}}
.actions{{margin:0;padding-left:18px}}
.actions li{{padding:3px 0;color:#c3c9d6}}
.tags{{margin-bottom:14px;display:flex;flex-wrap:wrap;gap:5px}}
.tag{{background:#1a2133;color:#7aa2f7;font-size:11px;padding:3px 8px;border-radius:4px;
 font-family:ui-monospace,monospace}}
.filters{{display:flex;gap:7px;margin-bottom:12px;flex-wrap:wrap}}
.filters button{{background:#151a28;border:1px solid #1d2231;color:#8a93a8;padding:5px 13px;
 border-radius:6px;cursor:pointer;font-size:12px;font-family:inherit}}
.filters button.on{{background:#5b8def;color:#0b0e17;border-color:#5b8def;font-weight:600}}
footer{{margin-top:42px;padding-top:18px;border-top:1px solid #1d2231;color:#8a93a8;font-size:12px}}
@media(max-width:860px){{.grid,.cols{{grid-template-columns:1fr}}.grid3{{grid-template-columns:1fr}}}}
</style></head><body><div class="wrap">

<header>
  <div>
    <h1>SOC <span>Dashboard</span></h1>
    <div class="sub">Detection, correlation and response summary</div>
  </div>
  <div class="sub mono">generated {generated}</div>
</header>

<div class="kpis">
  <div class="kpi"><div class="n">{s['events_parsed']:,}</div><div class="l">Events</div></div>
  <div class="kpi"><div class="n">{s['alerts']}</div><div class="l">Alerts</div></div>
  <div class="kpi"><div class="n" style="color:{SEV_COLOR['critical']}">{sev_counts.get('critical',0)}</div><div class="l">Critical</div></div>
  <div class="kpi"><div class="n">{s['cases_opened']}</div><div class="l">Cases</div></div>
  <div class="kpi"><div class="n">{s['entities_scored']}</div><div class="l">Entities</div></div>
  <div class="kpi"><div class="n">{s['techniques_covered']}</div><div class="l">ATT&amp;CK</div></div>
</div>

<h2>Attack timeline</h2>
<div class="card">{_timeline_svg(result.alerts)}</div>

<h2>Risk and detection breakdown</h2>
<div class="grid">
  <div class="card grid3">
    {_donut_svg(sev_counts)}
    <div>
      <h4>Pipeline stages</h4>
      <table><tr><td>Atomic (Sigma)</td><td class="mono">{d.get('atomic',0)}</td></tr>
      <tr><td>Stateful</td><td class="mono">{d.get('stateful',0)}</td></tr>
      <tr><td>Behavioral</td><td class="mono">{d.get('behavioral',0)}</td></tr>
      <tr><td>Correlation</td><td class="mono">{d.get('correlation',0)}</td></tr></table>
    </div>
  </div>
  <div class="card"><h4>Top risk entities</h4>
    {_bar_svg([(e.id, round(e.score)) for e in entities], color="#ff6b6b")}</div>
</div>

<div class="grid">
  <div class="card"><h4>Most frequent detections</h4>{_bar_svg(rule_counts)}</div>
  <div class="card"><h4>ATT&amp;CK techniques observed</h4>
    {_bar_svg(sorted(tech_counts.items(), key=lambda x:-x[1])[:8], color="#9b8cff")}</div>
</div>

<h2>Cases ({len(result.cases)})</h2>
{''.join(case_html) or '<div class="card muted">No cases opened.</div>'}

<h2>Alerts</h2>
<div class="filters">
  <button class="on" data-f="all">All</button>
  <button data-f="critical">Critical</button><button data-f="high">High</button>
  <button data-f="medium">Medium</button><button data-f="low">Low</button>
</div>
<div class="card" style="padding:4px 10px">
<table id="alerts"><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Entity</th>
<th>Risk</th><th>Description</th><th>Context</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>

<h2>Response actions</h2>
<div class="card" style="padding:4px 10px">
<table><thead><tr><th></th><th>Action</th><th>Target</th><th>Detail</th><th>Mode</th></tr></thead>
<tbody>{actions_rows}</tbody></table></div>

<h2>Ingestion</h2>
<div class="card" style="padding:4px 10px">
<table><thead><tr><th>File</th><th>Source</th><th>Parsed</th><th>Skipped</th></tr></thead>
<tbody>{parse_rows}</tbody></table></div>

<footer>Generated by the SIEM pipeline · response actions ran in dry-run mode ·
all data from analysed log files</footer>
</div>
<script>
document.querySelectorAll('.filters button').forEach(function(b){{
  b.addEventListener('click', function(){{
    document.querySelectorAll('.filters button').forEach(function(x){{x.classList.remove('on')}});
    b.classList.add('on');
    var f = b.dataset.f;
    document.querySelectorAll('#alerts tbody tr').forEach(function(tr){{
      tr.style.display = (f === 'all' || tr.dataset.sev === f) ? '' : 'none';
    }});
  }});
}});
</script></body></html>""")


def _write(path: str, content: str) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return str(p)
