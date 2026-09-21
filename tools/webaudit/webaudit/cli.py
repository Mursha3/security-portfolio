"""Command line entry point.

Exit codes: ``0`` no finding at or above ``--fail-on``; ``1`` threshold breached;
``2`` the target could not be reached at all.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Sequence
from urllib.parse import urljoin, urlsplit

from . import __version__
from .checks import audit, clean_checks
from .fetch import fetch, fetch_allowed_methods, fetch_text, normalize_url
from .models import SEVERITY_ORDER
from .report import render_console, render_json, render_markdown

_FAIL_LEVELS = ("critical", "high", "medium", "low", "info", "none")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webaudit",
        description=(
            "Passive web security posture audit. Sends a read-only GET for the page, "
            "security.txt, robots.txt and one OPTIONS request. No authentication, no "
            "payloads, no state changes."
        ),
        epilog="Point it at hosts you own or are authorised to assess.",
    )
    parser.add_argument("url", help="target URL or bare hostname (https:// is assumed)")
    parser.add_argument("--json", metavar="PATH", help="write the machine-readable report here")
    parser.add_argument("--md", metavar="PATH", help="write a Markdown report here")
    parser.add_argument("--timeout", type=float, default=15.0, help="per-request timeout in seconds")
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_LEVELS,
        default="high",
        help="exit 1 when a finding at this severity or worse exists (default: high)",
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    parser.add_argument(
        "--no-wellknown",
        action="store_true",
        help="skip security.txt, robots.txt and the OPTIONS probe",
    )
    parser.add_argument("--version", action="version", version=f"webaudit {__version__}")
    return parser


def _site_root(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content if content.endswith("\n") else content + "\n")


def _threshold_breached(findings: Sequence, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = SEVERITY_ORDER.index(fail_on)
    return any(SEVERITY_ORDER.index(f.severity) <= threshold for f in findings)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    target = normalize_url(args.url)

    result = fetch(target, timeout=args.timeout)

    security_txt: Optional[str] = None
    robots: Optional[str] = None
    allow_header: Optional[str] = None
    if not args.no_wellknown and result.hops:
        root = _site_root(result.final_url)
        security_txt = fetch_text(urljoin(root + "/", ".well-known/security.txt"), args.timeout)
        robots = fetch_text(urljoin(root + "/", "robots.txt"), args.timeout)
        allow_header = fetch_allowed_methods(result.final_url, args.timeout)

    findings = audit(result, security_txt, robots, allow_header)
    clean = clean_checks(findings, result)

    # Artifacts that were absent cannot have passed their check, so drop them from
    # the pass list instead of implying the target was verified against them.
    not_examined = set()
    if allow_header is None:
        not_examined.update({"methods-trace", "methods-write"})
    if robots is None:
        not_examined.add("robots-sensitive")
    if not_examined:
        clean = [entry for entry in clean if entry[0] not in not_examined]

    color = not args.no_color and sys.stdout.isatty()
    sys.stdout.write(render_console(result, findings, clean, color=color))

    if args.json:
        _write(args.json, render_json(result, findings, clean))
        print(f"json report written to {args.json}")
    if args.md:
        _write(args.md, render_markdown(result, findings, clean))
        print(f"markdown report written to {args.md}")

    if result.error and not result.hops:
        return 2
    return 1 if _threshold_breached(findings, args.fail_on) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
