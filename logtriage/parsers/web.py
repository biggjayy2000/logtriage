"""Apache / Nginx 'combined' access log parsing."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from ..models import Event

COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<target>[^"\s]+)[^"]*"\s+'
    r'(?P<status>\d{3})\s+\S+'
)
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse(line: str) -> Optional[Event]:
    match = COMBINED.match(line.rstrip("\n"))
    if not match:
        return None

    try:
        timestamp = datetime.strptime(match.group("ts"), TIME_FORMAT)
    except ValueError:
        return None

    # Normalise to naive UTC so mixed sources sort together.
    timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)

    return Event(
        timestamp=timestamp,
        source="web",
        kind="http_request",
        ip=match.group("ip"),
        method=match.group("method"),
        target=match.group("target"),
        status=int(match.group("status")),
        raw=line.rstrip("\n"),
    )
