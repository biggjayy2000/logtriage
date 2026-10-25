"""Format detection and dispatching.

The format is detected per line, so a directory of mixed logs can be triaged in one
pass without the operator pre-sorting them.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from ..models import Event
from . import sshd, web

SSHD, WEB = "sshd", "web"


def detect(line: str) -> Optional[str]:
    if "sshd[" in line:
        return SSHD
    if web.COMBINED.match(line):
        return WEB
    return None


def parse_lines(lines: Iterable[str], year: Optional[int] = None) -> Tuple[List[Event], int]:
    """Return (events, unparsed_line_count)."""
    events: List[Event] = []
    failed = 0
    for line in lines:
        if not line.strip():
            continue
        kind = detect(line)
        event = sshd.parse(line, year) if kind == SSHD else web.parse(line) if kind == WEB else None
        if event is None:
            failed += 1
        else:
            events.append(event)
    events.sort(key=lambda event: event.timestamp)
    return events, failed
