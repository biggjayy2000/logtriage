"""Engine: read files, normalise events, run every rule, return an incident."""

from __future__ import annotations

import datetime as _dt
import os
import time
from typing import Iterable, List, Optional

from .models import Incident
from .parsers import parse_lines
from .rules import RULES
from .settings import Settings


def _read(path: str, errors: List[str]):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.readlines(), True
    except OSError as exc:
        errors.append(f"Could not read {path}: {exc}")
        return [], False


def triage(paths: Iterable[str], settings: Optional[Settings] = None) -> Incident:
    settings = settings or Settings()
    started_at = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    began = time.monotonic()

    sources: List[str] = []
    errors: List[str] = []
    lines: List[str] = []

    for path in paths:
        candidates = (
            [os.path.join(path, name) for name in sorted(os.listdir(path))]
            if os.path.isdir(path)
            else [path]
        )
        for candidate in candidates:
            if not os.path.isfile(candidate):
                continue
            content, ok = _read(candidate, errors)
            if ok:
                lines.extend(content)
                sources.append(candidate)

    events, failed = parse_lines(lines, year=settings.year or None)

    incident = Incident(
        sources=sources,
        started=started_at,
        events=len(events),
        failed_lines=failed,
        errors=errors,
        first_event=events[0].timestamp if events else None,
        last_event=events[-1].timestamp if events else None,
    )

    for label, rule in RULES:
        try:
            incident.alerts.extend(rule(events, settings))
        except Exception as exc:  # one broken rule must not lose the rest
            errors.append(f"{label} rule failed: {exc}")

    incident.duration = time.monotonic() - began
    return incident
