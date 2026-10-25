"""OpenSSH auth.log parsing (syslog format, no year in the line)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from ..models import Event

MONTHS = {name: index for index, name in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s*(?P<msg>.*)$"
)
IP = r"(?P<ip>[0-9a-fA-F:.]+)"
FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from " + IP)
INVALID = re.compile(r"Invalid user (?P<user>\S+) from " + IP)
ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from " + IP)


def parse(line: str, year: Optional[int] = None) -> Optional[Event]:
    match = LINE.match(line.rstrip("\n"))
    if not match:
        return None

    stamp, message = match.group("ts"), match.group("msg")
    try:
        month_name, day, clock = stamp.split()
        hour, minute, second = (int(part) for part in clock.split(":"))
        timestamp = datetime(
            year or datetime.now().year,
            MONTHS[month_name],
            int(day),
            hour,
            minute,
            second,
        )
    except (KeyError, ValueError):
        return None

    for pattern, kind in ((FAILED, "auth_failed"), (INVALID, "auth_failed"), (ACCEPTED, "auth_success")):
        hit = pattern.search(message)
        if hit:
            return Event(
                timestamp=timestamp,
                source="sshd",
                kind=kind,
                ip=hit.group("ip"),
                user=hit.group("user"),
                raw=line.rstrip("\n"),
            )
    return None
