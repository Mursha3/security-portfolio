"""Command line entry point.

Exit codes are part of the interface, because the intended use is a pipeline:

* ``0`` - ran, nothing at or above ``--fail-on``
* ``2`` - ran, findings at or above ``--fail-on``
* ``3`` - could not read the input

Usage::

    logtriage /var/log/auth.log --md report.md --fail-on high
    zgrep sshd /var/log/auth.log.*.gz | logtriage - --window 30m
"""

from __future__ import annotations

import argparse
import gzip
import io
import sys
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

from . import __version__
from .engine import Report, analyze
from .models import SEVERITIES, Event, severity_rank
from .options import Options, format_duration, parse_duration
from .parser import AuthLogParser
from .report import render_console, render_json, render_markdown
from .rules import default_rules

EXIT_OK = 0
EXIT_FINDINGS = 2
EXIT_USAGE = 3

# Severity levels accepted by --fail-on, plus the "never fail" switch.
FAIL_LEVELS = ("none",) + SEVERITIES


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logtriage",
        description=(
            "Read authentication logs and report activity worth a human's attention. "
            "Read-only: it never touches the host it reads logs from."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  logtriage /var/log/auth.log\n"
            "  logtriage auth.log auth.log.1 --window 30m --md report.md\n"
            "  logtriage - --year 2026 --fail-on medium < auth.log\n"
            "  logtriage --list-rules\n"
        ),
    )
    parser.add_argument("paths", nargs="*", metavar="LOG",
                        help="log files to read; '-' reads standard input; .gz is handled")
    parser.add_argument("--version", action="version", version="logtriage {}".format(__version__))
    parser.add_argument("--year", type=int, default=None,
                        help="year for logs whose timestamps carry none (default: current year)")
    parser.add_argument("--window", default="10m",
                        help="sliding window for rate-based rules (30s, 10m, 2h, 1d)")
    parser.add_argument("--fail-threshold", type=int, default=Options.fail_threshold,
                        help="failed SSH logins from one address that count as brute force")
    parser.add_argument("--spray-users", type=int, default=Options.spray_users,
                        help="distinct accounts one address may try before it is a spray")
    parser.add_argument("--enum-users", type=int, default=Options.enum_users,
                        help="non-existent usernames one address may probe before it is enumeration")
    parser.add_argument("--distributed-sources", type=int, default=Options.distributed_sources,
                        help="distinct addresses attacking one account before it is distributed")
    parser.add_argument("--sudo-fail-threshold", type=int, default=Options.sudo_fail_threshold,
                        help="failed sudo authentications before it is reported")
    parser.add_argument("--off-hours", default="22-6", metavar="START-END",
                        help="hours considered outside working time, e.g. 22-6")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="info",
                        help="hide findings below this level; the score follows what is shown")
    parser.add_argument("--max-per-rule", type=int, default=Options.max_per_rule,
                        help="cap on findings kept per rule")
    parser.add_argument("--json", metavar="PATH", help="write the full result as JSON")
    parser.add_argument("--md", metavar="PATH", help="write a Markdown report")
    parser.add_argument("--no-color", action="store_true", help="plain console output")
    parser.add_argument("--fail-on", choices=FAIL_LEVELS, default="high",
                        help="exit 2 when a finding at or above this level is present")
    parser.add_argument("--list-rules", action="store_true",
                        help="print the detection catalogue and exit")
    return parser


def _open_lines(path: str) -> Iterator[str]:
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                yield line
        return
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            yield line


def _events_from(lines: Iterable[str], year: Optional[int]) -> Iterator[Event]:
    parser = AuthLogParser(year=year)
    for number, line in enumerate(lines, start=1):
        event = parser.parse_line(line, line_no=number)
        if event is not None:
            yield event


def load_events(paths: Sequence[str], year: Optional[int]) -> List[Event]:
    """Parse every input into events. Line numbers restart per file."""
    events: List[Event] = []
    for path in paths:
        if path == "-":
            events.extend(_events_from(sys.stdin, year))
        else:
            events.extend(_events_from(_open_lines(path), year))
    return events


def _off_hours(value: str) -> Tuple[int, int]:
    parts = value.replace(":", "").split("-")
    if len(parts) != 2:
        raise ValueError("expected START-END, e.g. 22-6")
    start, end = int(parts[0]), int(parts[1])
    if not (0 <= start <= 23 and 0 <= end <= 23):
        raise ValueError("hours must be between 0 and 23")
    return start, end


def _list_rules() -> str:
    lines = ["Detection catalogue ({} rules)".format(len(default_rules())), ""]
    for rule in default_rules():
        lines.append("{:<28} {:<9} {}".format(rule.id, rule.severity, rule.title))
        if rule.mitre:
            lines.append("{:<28} {}".format("", rule.mitre))
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        print(_list_rules())
        return EXIT_OK

    if not args.paths:
        parser.error("no input given (pass a log file or '-' for stdin)")

    try:
        window = parse_duration(args.window)
        off_start, off_end = _off_hours(args.off_hours)
    except ValueError as error:
        print("logtriage: {}".format(error), file=sys.stderr)
        return EXIT_USAGE

    options = Options(
        window=window,
        fail_threshold=args.fail_threshold,
        spray_users=args.spray_users,
        enum_users=args.enum_users,
        distributed_sources=args.distributed_sources,
        sudo_fail_threshold=args.sudo_fail_threshold,
        off_hours_start=off_start,
        off_hours_end=off_end,
        max_per_rule=args.max_per_rule,
    )

    try:
        events = load_events(args.paths, args.year)
    except OSError as error:
        print("logtriage: cannot read input: {}".format(error), file=sys.stderr)
        return EXIT_USAGE

    report = analyze(
        events,
        default_rules(options),
        inputs=list(args.paths),
        options=options,
        max_per_rule=args.max_per_rule,
    )

    limit = severity_rank(args.min_severity)
    visible = [f for f in report.findings if severity_rank(f.severity) <= limit]
    report.hidden = len(report.findings) - len(visible)
    report.findings = visible

    print(render_console(report, color=not args.no_color))

    if args.json:
        _write(args.json, render_json(report))
        print("JSON written to {}".format(args.json))
    if args.md:
        _write(args.md, render_markdown(report))
        print("Markdown written to {}".format(args.md))

    if args.fail_on != "none" and report.above(args.fail_on):
        return EXIT_FINDINGS
    return EXIT_OK


def _write(path: str, content: str) -> None:
    with io.open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
