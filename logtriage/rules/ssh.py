"""SSH rules: brute force, spraying, success after failure, and multi-IP logins."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import List

from ..models import Alert, Event, Severity
from ..settings import Settings
from ._util import best_window, distinct_users_in_window, group_by, sample_lines

BRUTE_MITRE = "T1110.001 - Brute Force: Password Guessing"
SPRAY_MITRE = "T1110.003 - Brute Force: Password Spraying"
VALID_MITRE = "T1078 - Valid Accounts"


def _failures(events: List[Event], settings: Settings) -> List[Event]:
    return [e for e in events if e.kind == "auth_failed" and not settings.is_allowed(e.ip)]


def brute_force(events: List[Event], settings: Settings) -> List[Alert]:
    alerts: List[Alert] = []
    window = timedelta(minutes=settings.ssh_fail_window_minutes)

    for ip, group in group_by(_failures(events, settings), lambda e: e.ip).items():
        count, start, end = best_window([e.timestamp for e in group], window)
        if count < settings.ssh_fail_threshold:
            continue
        inside = [e for e in group if start <= e.timestamp <= end]
        users = sorted({e.user for e in inside})
        alerts.append(
            Alert(
                rule_id="SSH-001",
                title="SSH brute-force attempts",
                severity=Severity.HIGH,
                summary=(
                    f"{count} failed SSH logins from {ip} within {settings.ssh_fail_window_minutes} minutes, "
                    f"against {len(users)} username(s)"
                ),
                count=count,
                first_seen=start,
                last_seen=end,
                entities={"ip": ip, "users": ", ".join(users[:6])},
                evidence=sample_lines(inside),
                recommendation=(
                    "Block the source, disable password authentication for external SSH, require keys, "
                    "and consider fail2ban or a bastion host."
                ),
                mitre=BRUTE_MITRE,
            )
        )
    return alerts


def password_spray(events: List[Event], settings: Settings) -> List[Alert]:
    """Many usernames, few attempts each - the pattern that slips past lockouts."""
    alerts: List[Alert] = []
    window = timedelta(minutes=settings.ssh_spray_window_minutes)

    for ip, group in group_by(_failures(events, settings), lambda e: e.ip).items():
        users, start, end = distinct_users_in_window(group, window)
        if users < settings.ssh_spray_user_threshold:
            continue
        inside = [e for e in group if start <= e.timestamp <= end]
        names = sorted({e.user for e in inside})
        alerts.append(
            Alert(
                rule_id="SSH-002",
                title="Password spraying",
                severity=Severity.HIGH,
                summary=(
                    f"{users} distinct usernames tried from {ip} within "
                    f"{settings.ssh_spray_window_minutes} minutes"
                ),
                count=len(inside),
                first_seen=start,
                last_seen=end,
                entities={"ip": ip, "users": ", ".join(names[:8])},
                evidence=sample_lines(inside),
                recommendation=(
                    "Spraying targets many accounts with few guesses to dodge lockouts. Block the source, "
                    "alert on distributed attempts, and enforce MFA for all remote access."
                ),
                mitre=SPRAY_MITRE,
            )
        )
    return alerts


def success_after_failures(events: List[Event], settings: Settings) -> List[Alert]:
    """The one that matters: a login that worked right after a burst of failures."""
    alerts: List[Alert] = []
    window = timedelta(minutes=settings.ssh_success_window_minutes)
    scoped = [e for e in events if not settings.is_allowed(e.ip)]

    for ip, group in group_by(scoped, lambda e: e.ip).items():
        failures = sorted((e for e in group if e.kind == "auth_failed"), key=lambda e: e.timestamp)
        successes = sorted((e for e in group if e.kind == "auth_success"), key=lambda e: e.timestamp)
        if not failures or not successes:
            continue

        for success in successes:
            recent = [f for f in failures if timedelta(0) <= success.timestamp - f.timestamp <= window]
            if len(recent) >= settings.ssh_success_fail_threshold:
                alerts.append(
                    Alert(
                        rule_id="SSH-003",
                        title="Successful login after repeated failures",
                        severity=Severity.CRITICAL,
                        summary=(
                            f"'{success.user}' logged in from {ip} after {len(recent)} failed attempts "
                            f"in the preceding {settings.ssh_success_window_minutes} minutes"
                        ),
                        count=len(recent) + 1,
                        first_seen=recent[0].timestamp,
                        last_seen=success.timestamp,
                        entities={"ip": ip, "user": success.user},
                        evidence=sample_lines(recent) + [success.raw],
                        recommendation=(
                            "Treat the account as compromised: force a password reset, revoke sessions and "
                            "keys, review what the account touched, and check for persistence."
                        ),
                        mitre=VALID_MITRE,
                    )
                )
                break
    return alerts


def multi_ip_login(events: List[Event], settings: Settings) -> List[Alert]:
    """One account, several source addresses, minutes apart."""
    alerts: List[Alert] = []
    window = timedelta(minutes=settings.ssh_multi_ip_window_minutes)
    scoped = [e for e in events if e.kind == "auth_success" and not settings.is_allowed(e.ip)]

    for user, group in group_by(scoped, lambda e: e.user).items():
        ordered = sorted(group, key=lambda e: e.timestamp)
        counts: Counter = Counter()
        left = 0
        best, best_start, best_end = 0, None, None

        for right, event in enumerate(ordered):
            counts[event.ip] += 1
            while event.timestamp - ordered[left].timestamp > window:
                leaving = ordered[left].ip
                counts[leaving] -= 1
                if not counts[leaving]:
                    del counts[leaving]
                left += 1
            if len(counts) > best:
                best = len(counts)
                best_start, best_end = ordered[left].timestamp, event.timestamp

        if best >= 2:
            inside = [e for e in ordered if best_start <= e.timestamp <= best_end]
            alerts.append(
                Alert(
                    rule_id="SSH-004",
                    title="Account used from multiple addresses",
                    severity=Severity.MEDIUM,
                    summary=(
                        f"'{user}' logged in from {best} different addresses within "
                        f"{settings.ssh_multi_ip_window_minutes} minutes"
                    ),
                    count=len(inside),
                    first_seen=best_start,
                    last_seen=best_end,
                    entities={"user": user, "ips": ", ".join(sorted({e.ip for e in inside}))},
                    evidence=sample_lines(inside),
                    recommendation=(
                        "Confirm with the account owner - a VPN, a jump host, or a scripted job explains "
                        "some of these. If not, treat it as credential sharing or theft."
                    ),
                    mitre=VALID_MITRE,
                )
            )
    return alerts
