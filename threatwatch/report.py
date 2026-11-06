"""Self-contained offline dashboard with escaped user-controlled content."""
from collections import Counter
from html import escape
from pathlib import Path
from .detector import Alert, Event

CSS = '''
:root{font-family:Inter,system-ui,-apple-system,sans-serif;color:#dfe7f5;background:#0c1220}
*{box-sizing:border-box}body{margin:0}main{max-width:1160px;margin:auto;padding:35px 22px}
h1{font-size:32px;margin:0 0 8px}.subtitle{color:#91a2be;margin:0 0 32px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:22px}
.card,.panel{background:#151f32;border:1px solid #2b3b54;border-radius:14px;padding:20px}
.number{font-size:30px;font-weight:750;margin-top:10px}.muted{color:#91a2be;font-size:13px}
h2{font-size:18px;margin:0 0 16px}.bar{height:13px;border-radius:7px;background:#263750;overflow:hidden}
.fill{height:100%;background:#4fc2c2}.severity{border-radius:999px;padding:4px 9px;font-size:12px;font-weight:bold}
.critical{background:#68233b;color:#ffb1bf}.high{background:#624020;color:#ffcd9c}
.medium{background:#254c67;color:#9ddffd}.low{background:#35543f;color:#aeebbd}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;border-bottom:1px solid #2b3b54;padding:12px 9px;vertical-align:top}th{color:#9fb0c7}
.controls{display:flex;gap:10px;margin-bottom:15px;flex-wrap:wrap}
input,select{background:#0c1220;color:#e6eaf1;border:1px solid #344760;padding:10px;border-radius:8px}
input{flex:1;min-width:230px}.scroll{overflow-x:auto}.panel{margin-bottom:20px}
footer{margin-top:20px;color:#8294ad;font-size:12px}
'''


def render_report(events: list[Event], alerts: list[Alert], dest: str) -> None:
    counts = Counter(a.severity for a in alerts)
    ips = len({a.source_ip for a in alerts})
    cards = [('Events analyzed', str(len(events))), ('Alerts generated', str(len(alerts))),
             ('High + critical', str(counts['high'] + counts['critical'])), ('Flagged source IPs', str(ips))]
    metric_html = ''.join(f'<div class="card"><div class="muted">{escape(label)}</div><div class="number">{escape(value)}</div></div>' for label, value in cards)
    rows = '\n'.join(
        '<tr data-severity="{sev}"><td>{time}</td><td><span class="severity {sev}">{sev}</span></td>'
        '<td>{rule}</td><td>{ip}</td><td>{details}</td><td>{count}</td></tr>'.format(
            sev=escape(a.severity), time=escape(a.timestamp), rule=escape(a.title),
            ip=escape(a.source_ip), details=escape(a.details), count=a.evidence_count)
        for a in alerts)
    if not rows:
        rows = '<tr><td colspan="6">No suspicious activity detected.</td></tr>'
    breakdown = ''.join(
        f'<div style="margin:12px 0"><div class="muted">{severity.upper()} — {counts[severity]}</div>'
        f'<div class="bar"><div class="fill" style="width:{(100 * counts[severity] / max(len(alerts), 1)):.1f}%"></div></div></div>'
        for severity in ('critical', 'high', 'medium', 'low'))
    page = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatWatch | Security Detection Report</title><style>{CSS}</style></head>
<body><main><h1>ThreatWatch</h1><p class="subtitle">Offline security event detection dashboard · defensive log analysis</p>
<div class="cards">{metric_html}</div><section class="panel"><h2>Alert severity distribution</h2>{breakdown}</section>
<section class="panel"><h2>Investigation queue</h2><div class="controls"><input id="search" aria-label="Search alerts" placeholder="Search IP, rule or details"><select id="severity" aria-label="Filter severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></div>
<div class="scroll"><table><thead><tr><th>Time (UTC)</th><th>Severity</th><th>Detection</th><th>Source IP</th><th>Evidence</th><th>Count</th></tr></thead>
<tbody id="results">{rows}</tbody></table></div></section>
<footer>Demonstration only. Alerts are heuristics, not confirmation of compromise. No external network requests.</footer></main>
<script>const q=document.getElementById('search'),s=document.getElementById('severity');function filter(){{for(const row of document.querySelectorAll('#results tr')){{row.hidden=!(row.textContent.toLowerCase().includes(q.value.toLowerCase())&&(!s.value||row.dataset.severity===s.value));}}}}q.addEventListener('input',filter);s.addEventListener('change',filter);</script>
</body></html>'''
    Path(dest).write_text(page, encoding='utf-8')
