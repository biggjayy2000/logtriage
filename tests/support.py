"""Helpers for building events without touching a log file."""

from __future__ import annotations

from datetime import datetime, timedelta

from logtriage.models import Event

BASE = datetime(2026, 3, 14, 3, 0, 0)


def at(seconds: int = 0) -> datetime:
    return BASE + timedelta(seconds=seconds)


def ssh_fail(ip: str = "203.0.113.5", user: str = "root", seconds: int = 0) -> Event:
    return Event(
        timestamp=at(seconds),
        source="sshd",
        kind="auth_failed",
        ip=ip,
        user=user,
        raw=f"Mar 14 03:00:{seconds:02d} web01 sshd[1]: Failed password for {user} from {ip} port 50000 ssh2",
    )


def ssh_success(ip: str = "203.0.113.5", user: str = "root", seconds: int = 0) -> Event:
    return Event(
        timestamp=at(seconds),
        source="sshd",
        kind="auth_success",
        ip=ip,
        user=user,
        raw=f"Mar 14 03:00:{seconds:02d} web01 sshd[1]: Accepted password for {user} from {ip} port 50001 ssh2",
    )


def http(
    path: str = "/",
    status: int = 200,
    ip: str = "198.51.100.7",
    method: str = "GET",
    seconds: int = 0,
) -> Event:
    return Event(
        timestamp=at(seconds),
        source="web",
        kind="http_request",
        ip=ip,
        method=method,
        target=path,
        status=status,
        raw=f'{ip} - - [14/Mar/2026:03:00:{seconds:02d} +0000] "{method} {path} HTTP/1.1" {status} 100 "-" "test"',
    )
