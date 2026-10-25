"""Web rules: scanning, login attacks, sensitive paths, and injection attempts."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import List
from urllib.parse import unquote_plus

from ..models import Alert, Event, Severity
from ..settings import Settings
from ._util import best_window, group_by, sample_lines

SCAN_MITRE = "T1595 - Active Scanning"
CRED_MITRE = "T1110.001 - Brute Force: Password Guessing"
DISCOVERY_MITRE = "T1083 - File and Directory Discovery"
INJECTION_MITRE = "T1190 - Exploit Public-Facing Application"

SENSITIVE_PATHS = (
    "/.env",
    "/.git",
    "/.aws/credentials",
    "/server-status",
    "/phpmyadmin",
    "/wp-login.php",
    "/actuator/env",
    "/backup.zip",
    "/config.php",
)

INJECTION_PATTERNS = (
    "union select",
    "or 1=1",
    "' or '1'='1",
    "<script",
    "etc/passwd",
    "information_schema",
    "sleep(",
    "benchmark(",
    "wp-config",
)


def _requests(events: List[Event], settings: Settings) -> List[Event]:
    return [e for e in events if e.kind == "http_request" and not settings.is_allowed(e.ip)]


def scanning(events: List[Event], settings: Settings) -> List[Alert]:
    """A burst of client errors from one source is usually a directory sweep."""
    alerts: List[Alert] = []
    window = timedelta(minutes=settings.web_scan_window_minutes)
    errors = [e for e in _requests(events, settings) if 400 <= e.status < 500]

    for ip, group in group_by(errors, lambda e: e.ip).items():
        count, start, end = best_window([e.timestamp for e in group], window)
        if count < settings.web_scan_threshold:
            continue
        inside = [e for e in group if start <= e.timestamp <= end]
        top_paths = Counter(e.path for e in inside).most_common(4)
        alerts.append(
            Alert(
                rule_id="WEB-001",
                title="Directory and file scanning",
                severity=Severity.MEDIUM,
                summary=(
                    f"{count} client-error responses to {ip} within "
                    f"{settings.web_scan_window_minutes} minutes"
                ),
                count=count,
                first_seen=start,
                last_seen=end,
                entities={
                    "ip": ip,
                    "top paths": ", ".join(f"{path} ({hits})" for path, hits in top_paths),
                },
                evidence=sample_lines(inside),
                recommendation=(
                    "Rate-limit the source, front the site with a WAF, and make sure error pages do not "
                    "confirm which paths exist."
                ),
                mitre=SCAN_MITRE,
            )
        )
    return alerts


def login_bruteforce(events: List[Event], settings: Settings) -> List[Alert]:
    """Repeated 401/403 on a login endpoint - the web equivalent of SSH guessing."""
    alerts: List[Alert] = []
    window = timedelta(minutes=settings.web_login_window_minutes)

    attempts = [
        e
        for e in _requests(events, settings)
        if e.status in (401, 403) and e.method in ("POST", "PUT") and "login" in e.path.lower()
    ]

    for ip, group in group_by(attempts, lambda e: e.ip).items():
        count, start, end = best_window([e.timestamp for e in group], window)
        if count < settings.web_login_fail_threshold:
            continue
        inside = [e for e in group if start <= e.timestamp <= end]
        alerts.append(
            Alert(
                rule_id="WEB-002",
                title="Login endpoint brute force",
                severity=Severity.HIGH,
                summary=(
                    f"{count} failed logins to {inside[0].path} from {ip} within "
                    f"{settings.web_login_window_minutes} minutes"
                ),
                count=count,
                first_seen=start,
                last_seen=end,
                entities={"ip": ip, "path": inside[0].path},
                evidence=sample_lines(inside),
                recommendation=(
                    "Rate-limit and lock out per account and per source, add a CAPTCHA after a few "
                    "failures, and require MFA on accounts with access."
                ),
                mitre=CRED_MITRE,
            )
        )
    return alerts


def sensitive_paths(events: List[Event], settings: Settings) -> List[Alert]:
    """Requests for files that should never be reachable from the internet."""
    alerts: List[Alert] = []
    hits = [
        e
        for e in _requests(events, settings)
        if any(e.path.lower().startswith(prefix) for prefix in SENSITIVE_PATHS)
    ]

    for ip, group in group_by(hits, lambda e: e.ip).items():
        succeeded = [e for e in group if e.status == 200]
        paths = sorted({e.path for e in group})
        severity = Severity.HIGH if succeeded else Severity.MEDIUM
        finding = "returned content" if succeeded else "did not return content"
        alerts.append(
            Alert(
                rule_id="WEB-003",
                title="Sensitive path probing" + (" (content returned)" if succeeded else ""),
                severity=severity,
                summary=(
                    f"{len(group)} request(s) for sensitive paths from {ip}; "
                    f"{len(succeeded)} {finding}"
                ),
                count=len(group),
                first_seen=min(e.timestamp for e in group),
                last_seen=max(e.timestamp for e in group),
                entities={"ip": ip, "paths": ", ".join(paths[:6])},
                evidence=sample_lines(group),
                recommendation=(
                    "Remove the files from the web root, deny dotfiles at the server, and rotate any "
                    "credential the exposed file contained."
                ),
                mitre=DISCOVERY_MITRE,
            )
        )
    return alerts


def injection_attempts(events: List[Event], settings: Settings) -> List[Alert]:
    """Payload-shaped strings in the request path or query string."""
    alerts: List[Alert] = []
    hits = []
    for event in _requests(events, settings):
        probe = unquote_plus(event.target).lower()
        matched = [pattern for pattern in INJECTION_PATTERNS if pattern in probe]
        if matched:
            hits.append((event, matched))

    for ip, pairs in group_by(hits, lambda pair: pair[0].ip).items():
        matched_patterns = sorted({pattern for _, found in pairs for pattern in found})
        events_only = [event for event, _ in pairs]
        alerts.append(
            Alert(
                rule_id="WEB-004",
                title="Injection payloads in requests",
                severity=Severity.HIGH,
                summary=(
                    f"{len(pairs)} request(s) from {ip} contained injection-shaped input "
                    f"({', '.join(matched_patterns[:4])})"
                ),
                count=len(pairs),
                first_seen=min(e.timestamp for e in events_only),
                last_seen=max(e.timestamp for e in events_only),
                entities={"ip": ip, "patterns": ", ".join(matched_patterns)},
                evidence=sample_lines(events_only),
                recommendation=(
                    "Confirm the parameter is handled with prepared statements or output encoding. "
                    "A 500 or a 200 with unusual content is worth reproducing by hand."
                ),
                mitre=INJECTION_MITRE,
            )
        )
    return alerts
