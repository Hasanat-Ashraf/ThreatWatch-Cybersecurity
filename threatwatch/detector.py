"""Deterministic defensive detection rules for normalized authentication and HTTP logs."""
from __future__ import annotations
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, asdict
from typing import Iterable
import ipaddress
import json


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    event_type: str
    source_ip: str
    username: str = ""
    status: str = ""
    path: str = ""

    @staticmethod
    def from_dict(record: dict) -> "Event":
        required = ("timestamp", "event_type", "source_ip")
        for key in required:
            if key not in record:
                raise ValueError(f"Missing required field: {key}")
        ts = datetime.fromisoformat(str(record["timestamp"]).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        ipaddress.ip_address(str(record["source_ip"]))
        kind = str(record["event_type"])
        status = str(record.get("status", ""))
        if kind not in ("auth", "http"):
            raise ValueError("event_type must be auth or http")
        if kind == "auth" and status not in ("success", "failure"):
            raise ValueError("auth status must be success or failure")
        return Event(ts.astimezone(timezone.utc), kind, str(record["source_ip"]),
                     str(record.get("username", "")), status, str(record.get("path", "")))


@dataclass(frozen=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    source_ip: str
    timestamp: str
    details: str
    evidence_count: int

    def to_dict(self) -> dict:
        return asdict(self)


SUSPICIOUS_PATHS = ("/.env", "/wp-admin", "/.git/", "/phpmyadmin", "/etc/passwd")


def detect(events: Iterable[Event]) -> list[Alert]:
    """Evaluate per-IP sliding windows. One alert per episode per rule/IP.

    Thresholds: 5 auth failures/10 minutes; 4 distinct failed usernames/15 minutes;
    success after 3 failures for same IP and username/15 minutes; 20 HTTP
    requests/60 seconds; known probing paths (one alert per IP/path).
    """
    ordered = sorted(events, key=lambda e: e.timestamp)
    failures = defaultdict(deque)       # source IP => (time, username)
    http_hits = defaultdict(deque)      # source IP => times
    emitted_brute = set()
    emitted_spray = set()
    emitted_rate = set()
    emitted_probe = set()
    alerts: list[Alert] = []

    def emit(rule, title, severity, e, details, count):
        alerts.append(Alert(rule, title, severity, e.source_ip,
                            e.timestamp.isoformat().replace("+00:00", "Z"), details, count))

    for e in ordered:
        ip = e.source_ip
        if e.event_type == "auth":
            q = failures[ip]
            while q and e.timestamp - q[0][0] > timedelta(minutes=15):
                q.popleft()
            if e.status == "failure":
                q.append((e.timestamp, e.username))
                last_10 = [(t, u) for t, u in q if e.timestamp - t <= timedelta(minutes=10)]
                if len(last_10) >= 5 and ip not in emitted_brute:
                    emit("AUTH_BRUTE_FORCE", "Repeated failed logins", "high", e,
                         f"{len(last_10)} authentication failures within 10 minutes", len(last_10))
                    emitted_brute.add(ip)
                if len({u for _, u in q if u}) >= 4 and ip not in emitted_spray:
                    emit("AUTH_PASSWORD_SPRAY", "Multiple accounts targeted", "high", e,
                         f"Failed logins for {len({u for _, u in q if u})} distinct accounts within 15 minutes", len(q))
                    emitted_spray.add(ip)
            else:
                previous = sum(1 for _, username in q if username == e.username)
                if previous >= 3:
                    emit("AUTH_SUCCESS_AFTER_FAILURES", "Login succeeded after failures", "critical", e,
                         f"Successful login for {e.username!r} following {previous} failures within 15 minutes", previous + 1)
                # Reset associated failures on successful authentication so subsequent episodes can alert.
                failures[ip] = deque((t, u) for t, u in q if u != e.username)
                if not failures[ip]:
                    emitted_brute.discard(ip)
                    emitted_spray.discard(ip)
        elif e.event_type == "http":
            q = http_hits[ip]
            while q and e.timestamp - q[0] > timedelta(seconds=60):
                q.popleft()
            if not q:
                emitted_rate.discard(ip)
            q.append(e.timestamp)
            if len(q) >= 20 and ip not in emitted_rate:
                emit("HTTP_RATE_SPIKE", "Unusually high request volume", "medium", e,
                     f"{len(q)} requests within 60 seconds", len(q))
                emitted_rate.add(ip)
            path = e.path.lower().split("?", 1)[0]
            match = next((p for p in SUSPICIOUS_PATHS if p in path), None)
            if match and (ip, match) not in emitted_probe:
                emit("HTTP_SENSITIVE_PATH", "Sensitive path probing", "medium", e,
                     f"Request to suspicious path {e.path[:160]!r}", 1)
                emitted_probe.add((ip, match))
    return sorted(alerts, key=lambda a: (a.timestamp, a.rule_id, a.source_ip))


def parse_jsonl(path: str) -> tuple[list[Event], list[str]]:
    events: list[Event] = []
    errors: list[str] = []
    with open(path, encoding="utf-8") as stream:
        for line_num, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError("each line must be a JSON object")
                events.append(Event.from_dict(obj))
            except (ValueError, TypeError, KeyError) as exc:
                errors.append(f"line {line_num}: {exc}")
    return events, errors
