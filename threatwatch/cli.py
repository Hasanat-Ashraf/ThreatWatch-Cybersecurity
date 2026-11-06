"""Command-line interface for local security log analysis."""
import argparse
import csv
import json
import sys
from pathlib import Path
from .detector import detect, parse_jsonl
from .report import render_report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Analyze normalized JSONL logs for suspicious activity")
    parser.add_argument('--input', required=True, help='Input JSONL file')
    parser.add_argument('--output', default='reports', help='Report directory (default: reports)')
    parser.add_argument('--strict', action='store_true', help='Exit with error if input has invalid lines')
    args = parser.parse_args(argv)
    try:
        events, errors = parse_jsonl(args.input)
    except OSError as exc:
        parser.error(str(exc))
    for error in errors:
        print(f'WARNING: {error}', file=sys.stderr)
    if args.strict and errors:
        print('Input rejected: validation errors in strict mode.', file=sys.stderr)
        return 2
    alerts = detect(events)
    dest = Path(args.output)
    dest.mkdir(parents=True, exist_ok=True)
    with (dest / 'alerts.json').open('w', encoding='utf-8') as f:
        json.dump([a.to_dict() for a in alerts], f, indent=2)
    with (dest / 'alerts.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=('timestamp', 'severity', 'rule_id', 'title', 'source_ip', 'details', 'evidence_count'))
        writer.writeheader()
        writer.writerows(a.to_dict() for a in alerts)
    render_report(events, alerts, str(dest / 'dashboard.html'))
    print(f'Analyzed {len(events)} events | generated {len(alerts)} alerts | skipped {len(errors)} invalid lines')
    print(f'Open {dest / "dashboard.html"} in your browser')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
