# ThreatWatch — Cybersecurity Threat Detection System

**ThreatWatch** is a defensive, offline Python application that analyzes normalized authentication and web request logs, identifies potentially suspicious patterns, and exports an interactive HTML dashboard plus JSON/CSV alert reports.

Built for a cybersecurity analyst / SOC analyst portfolio. **All included IP addresses are reserved documentation IPs and all demo events are synthetic.** The application does not scan networks, contact hosts, or require an API key.

## Features

- **Brute-force login detection:** 5 failed authentication attempts from one IP within 10 minutes.
- **Password spraying detection:** failed authentication attempts against 4 distinct usernames from one IP within 15 minutes.
- **Suspicious successful login:** one successful authentication after 3+ failed attempts for the same IP/account within 15 minutes.
- **HTTP request-rate spikes:** 20 or more web requests from one IP within 60 seconds.
- **Sensitive-path probes:** requests containing `/.env`, `/wp-admin`, `/.git/`, `/phpmyadmin`, or `/etc/passwd`.
- **Readable output:** severity, timestamp, IP, evidence details and count, CSV and JSON export, and a searchable/filterable standalone HTML dashboard.
- **Input validation:** rejects malformed records with line numbers; optional strict mode.
- **Automated tests** using Python's built-in `unittest` framework.

## Quick start (macOS / Linux / Windows)

Requires Python **3.10 or newer**. No third-party packages are needed to run from source.

```bash
# Run this command inside the threatwatch folder
python3 -m threatwatch --input sample_data/demo_events.jsonl --output reports
```

On Windows, use `py -m threatwatch --input sample_data/demo_events.jsonl --output reports` if `python3` is unavailable.

Then open `reports/dashboard.html` in your browser. Outputs are:

- `reports/dashboard.html` — interactive offline dashboard
- `reports/alerts.json` — structured alerts for further processing
- `reports/alerts.csv` — spreadsheet-friendly detection results

To run tests:

```bash
python3 -m unittest discover -s tests -v
```

To fail rather than skip malformed lines:

```bash
python3 -m threatwatch --input sample_data/demo_events.jsonl --output reports --strict
```

## Input format

Input is **JSON Lines**: one JSON object per line. The application works with already-normalized log events; it does not parse raw Windows Event Logs, syslog, or PCAP files yet.

```json
{"timestamp":"2026-10-30T12:00:00Z","event_type":"auth","source_ip":"203.0.113.10","username":"admin","status":"failure"}
{"timestamp":"2026-10-30T12:00:01Z","event_type":"http","source_ip":"192.0.2.45","path":"/.env"}
```

| Field | Required | Allowed values |
|---|---|---|
| `timestamp` | Yes | ISO 8601 with timezone (UTC `Z` recommended) |
| `event_type` | Yes | `auth`, `http` |
| `source_ip` | Yes | IPv4 or IPv6 address |
| `username` | For meaningful auth analysis | Username string |
| `status` | Auth events | `success` or `failure` |
| `path` | For HTTP path analysis | Request path string |

### Rule behavior and limitations

Detection is based on sliding event-time windows, with input sorted by timestamp. Each IP gets its own windows. Repeated brute-force/password-spray alerts are suppressed until a successful login clears a relevant set of failures; rate spike alerts are suppressed until the corresponding request window empties. Sensitive-path probes are deduplicated by IP and path signature for the whole run. These tradeoffs keep the demo alert queue readable but may miss later distinct episodes. Authentication success-after-failure events may produce more than one alert if multiple successes have their own remaining failed-login evidence.

The signals are **heuristics**, not proof of intrusion. NAT, shared IPs, legitimate load testing, administrators, and expected scanner traffic can create false positives. Results are not automatically enriched with threat intelligence. Logs are processed locally and reports may contain sensitive IPs/usernames: don't publish real organization logs to GitHub. The dashboard is not a live server; rerun the CLI for updated reports.

## Project structure

```text
threatwatch/
├── threatwatch/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py          # Input / output / CLI
│   ├── detector.py     # Defensive detection rules
│   └── report.py       # Standalone HTML dashboard
├── sample_data/
│   └── demo_events.jsonl
├── tests/
│   └── test_detector.py
├── docs/
│   └── detection-rules.md
├── pyproject.toml
├── .gitignore
└── README.md
```

## Portfolio talking points

Be ready to discuss sliding-window calculations, rule thresholds, event validation, reducing false positives, severity classification, safe HTML escaping, and how you'd handle multi-GB logs or streaming ingestion. Good next steps: raw syslog parser, Windows Event log adapter, SIEM ingestion, configurable thresholds, rule unit tests with edge cases, and alert persistence.

**Example resume bullets (use only after you independently validate and understand the work):**

- Built a Python-based threat detection system that analyzes authentication and HTTP events using sliding time windows to flag brute-force logins, password spraying, anomalous traffic, and sensitive-path probes.
- Developed an offline security analytics dashboard with severity-ranked alerts, investigative evidence, and JSON/CSV exports; added automated unit tests and input-validation controls.

## License

MIT. See `LICENSE`.
