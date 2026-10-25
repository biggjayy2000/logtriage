"""Core types: a normalised event, an alert produced by a rule, and the incident."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


@dataclass(frozen=True)
class Event:
    """One parsed log line, normalised so rules never touch raw text."""

    timestamp: datetime
    source: str  # "sshd" or "web"
    kind: str  # auth_failed | auth_success | http_request
    ip: str
    user: str = ""
    method: str = ""
    target: str = ""
    status: int = 0
    raw: str = ""

    @property
    def path(self) -> str:
        return self.target.split("?", 1)[0] if self.target else ""


@dataclass(frozen=True)
class Alert:
    rule_id: str
    title: str
    severity: Severity
    summary: str
    count: int
    first_seen: datetime
    last_seen: datetime
    entities: Dict[str, str] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    recommendation: str = ""
    mitre: str = ""

    @property
    def rank(self) -> int:
        return _RANK[self.severity.value]


@dataclass
class Incident:
    sources: List[str] = field(default_factory=list)
    started: str = ""
    duration: float = 0.0
    events: int = 0
    failed_lines: int = 0
    first_event: Optional[datetime] = None
    last_event: Optional[datetime] = None
    alerts: List[Alert] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def sorted_alerts(self) -> List[Alert]:
        return sorted(self.alerts, key=lambda a: (a.rank, a.first_seen))

    def counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for alert in self.alerts:
            counts[alert.severity.value] += 1
        return counts

    def timeline(self) -> List[Alert]:
        return sorted(self.alerts, key=lambda a: a.first_seen)

    def exit_code(self, fail_on: str = "High") -> int:
        threshold = _RANK[Severity(fail_on).value]
        return 1 if any(a.rank <= threshold for a in self.alerts) else 0
