import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threatwatch.detector import Event, detect, parse_jsonl
from threatwatch.report import render_report

BASE = datetime(2026, 10, 30, tzinfo=timezone.utc)

def event(sec, kind='auth', ip='203.0.113.5', **kwargs):
    record = dict(timestamp=(BASE + timedelta(seconds=sec)).isoformat(), event_type=kind, source_ip=ip, **kwargs)
    return Event.from_dict(record)

class DetectionTests(unittest.TestCase):
    def test_brute_force_and_success(self):
        events = [event(i*20, username='admin', status='failure') for i in range(5)]
        events.append(event(110, username='admin', status='success'))
        rules = [a.rule_id for a in detect(events)]
        self.assertIn('AUTH_BRUTE_FORCE', rules)
        self.assertIn('AUTH_SUCCESS_AFTER_FAILURES', rules)

    def test_old_failures_expire(self):
        events = [event(i*900, username='admin', status='failure') for i in range(5)]
        self.assertNotIn('AUTH_BRUTE_FORCE', [a.rule_id for a in detect(events)])

    def test_password_spray(self):
        events = [event(i*45, username=u, status='failure') for i, u in enumerate(('a','b','c','d'))]
        self.assertIn('AUTH_PASSWORD_SPRAY', [a.rule_id for a in detect(events)])

    def test_http_rate_and_probe(self):
        events = [event(i, kind='http', path='/home') for i in range(20)]
        events.append(event(30, kind='http', path='/.env?x=1'))
        rules = [a.rule_id for a in detect(events)]
        self.assertIn('HTTP_RATE_SPIKE', rules)
        self.assertIn('HTTP_SENSITIVE_PATH', rules)

    def test_no_false_positives_for_benign(self):
        events = [event(i*90, username='user', status='success') for i in range(8)]
        self.assertEqual(detect(events), [])

    def test_validation(self):
        with self.assertRaises(ValueError):
            Event.from_dict(dict(timestamp='2026-10-30T10:00:00', event_type='http',source_ip='192.0.2.1'))
        with self.assertRaises(ValueError):
            event(0, ip='bad IP', username='x', status='failure')

    def test_skips_invalid_jsonl_and_reports_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'logs.jsonl'
            good = dict(timestamp='2026-10-30T12:00:00Z', event_type='http', source_ip='192.0.2.1',path='/')
            path.write_text(json.dumps(good)+'\nnot-json\n')
            events, errors = parse_jsonl(str(path))
            self.assertEqual(len(events), 1)
            self.assertEqual(len(errors), 1)

    def test_report_html_escapes_log_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            e = event(0, kind='http', path='/.env<img src=x onerror=alert(1)>')
            path = Path(tmp)/'dashboard.html'
            render_report([e], detect([e]), str(path))
            html = path.read_text()
            self.assertIn('&lt;img', html)
            self.assertNotIn('<img src=x', html)

if __name__ == '__main__':
    unittest.main()
