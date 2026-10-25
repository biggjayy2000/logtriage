"""Report rendering: an incident summary for humans, JSON for tooling."""

from __future__ import annotations

import json
from typing import List

from .models import Incident, Severity

COLORS = {
    "Critical": "\033[1;35m",
    "High": "\033[1;31m",
    "Medium": "\033[1;33m",
    "Low": "\033[1;36m",
    "Info": "\033[1;37m",
}
RESET = "\033[0m"


KEY_LABELS = {
    "ip": "IP",
    "ips": "Source addresses",
    "user": "Account",
    "users": "Usernames",
    "paths": "Paths",
    "patterns": "Patterns",
    "path": "Path",
    "top paths": "Top paths",
}


def _stamp(moment) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S") if moment else "-"


def _label(key: str) -> str:
    return KEY_LABELS.get(key.lower(), key.replace("_", " ").title())


def render_markdown(incident: Incident) -> str:
    lines: List[str] = []
    lines.append("# Security Log Triage")
    lines.append("")
    lines.append(f"- **Sources:** {', '.join(incident.sources) or 'none'}")
    lines.append(f"- **Analysed:** {incident.started} ({incident.duration:.2f}s)")
    lines.append(f"- **Events parsed:** {incident.events}")
    if incident.first_event and incident.last_event:
        lines.append(f"- **Covering:** {_stamp(incident.first_event)} to {_stamp(incident.last_event)}")
    lines.append(f"- **Alerts:** {len(incident.alerts)}")
    if incident.failed_lines:
        lines.append(f"- **Unparsed lines:** {incident.failed_lines}")
    lines.append("")

    counts = incident.counts()
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Alerts |")
    lines.append("| --- | --- |")
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        lines.append(f"| {severity.value} | {counts[severity.value]} |")
    lines.append("")

    if incident.errors:
        lines.append("## Processing notes")
        lines.append("")
        for error in incident.errors:
            lines.append(f"- {error}")
        lines.append("")

    timeline = incident.timeline()
    if timeline:
        lines.append("## Timeline")
        lines.append("")
        lines.append("| First seen | Severity | Rule | What happened |")
        lines.append("| --- | --- | --- | --- |")
        for alert in timeline:
            lines.append(
                f"| {_stamp(alert.first_seen)} | {alert.severity.value} | `{alert.rule_id}` | {alert.summary} |"
            )
        lines.append("")

    lines.append("## Alerts")
    lines.append("")
    if not incident.alerts:
        lines.append("No alerts. Nothing in these logs crossed a detection threshold.")
        lines.append("")

    for index, alert in enumerate(incident.sorted_alerts(), start=1):
        lines.append(f"### {index}. [{alert.severity.value}] {alert.title}")
        lines.append("")
        lines.append(f"- **Rule:** `{alert.rule_id}`  ")
        lines.append(f"- **Occurrences:** {alert.count}  ")
        lines.append(f"- **Window:** {_stamp(alert.first_seen)} to {_stamp(alert.last_seen)}")
        if alert.entities:
            for key, value in alert.entities.items():
                lines.append(f"- **{_label(key)}:** {value}")
        if alert.mitre:
            lines.append(f"- **MITRE ATT&CK:** {alert.mitre}")
        lines.append("")
        lines.append("**Evidence**")
        lines.append("")
        lines.append("```")
        for raw in alert.evidence:
            lines.append(raw)
        lines.append("```")
        lines.append("")
        lines.append(f"**Next step:** {alert.recommendation}")
        lines.append("")

    lines.append("## Method")
    lines.append("")
    lines.append(
        "SSH auth logs and web access logs are normalised, then evaluated against fixed detection rules "
        "with explicit thresholds. Times come from the log lines themselves; syslog entries have no year, "
        "so it is supplied at runtime."
    )
    lines.append("")
    return "\n".join(lines)


def render_json(incident: Incident) -> str:
    payload = {
        "sources": incident.sources,
        "analysed": incident.started,
        "duration_seconds": round(incident.duration, 3),
        "events": incident.events,
        "unparsed_lines": incident.failed_lines,
        "counts": incident.counts(),
        "errors": incident.errors,
        "alerts": [
            {
                "rule_id": alert.rule_id,
                "title": alert.title,
                "severity": alert.severity.value,
                "summary": alert.summary,
                "count": alert.count,
                "first_seen": alert.first_seen.isoformat() if alert.first_seen else None,
                "last_seen": alert.last_seen.isoformat() if alert.last_seen else None,
                "entities": alert.entities,
                "evidence": alert.evidence,
                "recommendation": alert.recommendation,
                "mitre": alert.mitre,
            }
            for alert in incident.sorted_alerts()
        ],
    }
    return json.dumps(payload, indent=2)


def render_console(incident: Incident, color: bool = True, verbose: bool = True) -> str:
    def paint(text: str, severity: str) -> str:
        return f"{COLORS.get(severity, '')}{text}{RESET}" if color else text

    lines: List[str] = [""]
    lines.append(f"  Sources  {', '.join(incident.sources) or 'none'}")
    span = ""
    if incident.first_event and incident.last_event:
        span = f"{_stamp(incident.first_event)} to {_stamp(incident.last_event)}"
    lines.append(f"  Events   {incident.events} parsed" + (f"  |  {span}" if span else ""))
    if incident.failed_lines:
        lines.append(f"  Skipped  {incident.failed_lines} unparsed line(s)")
    lines.append("")

    counts = incident.counts()
    summary = "  ".join(
        paint(f"{severity.value} {counts[severity.value]}", severity.value)
        for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
    )
    lines.append(f"  {summary}")
    lines.append("")

    for alert in incident.sorted_alerts():
        tag = paint(f"[{alert.severity.value:^8}]", alert.severity.value)
        lines.append(f"  {tag} {alert.rule_id}  {alert.title}")
        lines.append(f"             {alert.summary}")
        if verbose:
            lines.append(f"             first seen {_stamp(alert.first_seen)}")
    lines.append("")

    for error in incident.errors:
        lines.append(f"  note: {error}")

    return "\n".join(lines)
