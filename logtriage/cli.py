"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .engine import triage
from .models import Severity
from .report import render_console, render_json, render_markdown
from .settings import Settings

BANNER = "logtriage - offline detection over SSH and web logs"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logtriage",
        description=(
            "Triage SSH auth logs and web access logs: normalise them, run detection rules "
            "(brute force, spraying, success after failures, scanning, sensitive paths, injection), "
            "and produce an incident summary."
        ),
    )
    parser.add_argument("logs", nargs="+", metavar="LOG", help="log file(s) or a directory")
    parser.add_argument("--markdown", metavar="PATH", help="write a Markdown incident report")
    parser.add_argument("--json", metavar="PATH", help="write a JSON incident report")
    parser.add_argument(
        "--allowlist",
        action="append",
        default=[],
        metavar="IP",
        help="never alert on this source address (repeatable)",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=0,
        help="year for syslog lines, which omit it (default: current year)",
    )
    parser.add_argument("--no-color", action="store_true", help="plain terminal output")
    parser.add_argument("--quiet", action="store_true", help="summary only")
    parser.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity] + ["never"],
        default=Severity.HIGH.value,
        help="exit non-zero when an alert at or above this severity exists (default: High)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content if content.endswith("\n") else content + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    print(BANNER)
    print("Defensive analysis only - reads files, opens no sockets.\n")

    settings = Settings.from_args(allowlist=args.allowlist, year=args.year)
    incident = triage(args.logs, settings)

    if not incident.sources:
        print("No readable log files were provided.", file=sys.stderr)
        return 2

    print(render_console(incident, color=not args.no_color, verbose=not args.quiet))

    if args.markdown:
        _write(args.markdown, render_markdown(incident))
        print(f"Markdown report written to {args.markdown}")
    if args.json:
        _write(args.json, render_json(incident))
        print(f"JSON report written to {args.json}")

    if args.fail_on == "never":
        return 0
    return incident.exit_code(args.fail_on)
