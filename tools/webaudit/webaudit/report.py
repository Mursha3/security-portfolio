"""Rendering: one set of findings, three output shapes.

The Markdown renderer exists so an audit can be committed straight into a review
or a portfolio writeup; the JSON renderer so runs can be diffed between deploys.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Sequence, Tuple

from .fetch import FetchResult
from .models import SEVERITY_ORDER, Finding, grade, group_by_severity, score

_RESET = "\033[0m"
_COLORS = {
    "critical": "\033[97;41m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
    "ok": "\033[92m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}
_LABELS = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED",
    "low": "LOW",
    "info": "INFO",
}


def _paint(text: str, style: str, enabled: bool) -> str:
    if not enabled or style not in _COLORS:
        return text
    return f"{_COLORS[style]}{text}{_RESET}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def render_console(
    result: FetchResult,
    findings: Sequence[Finding],
    clean: Iterable[Tuple[str, str]] = (),
    color: bool = True,
) -> str:
    """Human-readable report for a terminal."""
    value = score(findings)
    lines: List[str] = []

    header = f"{result.requested_url}"
    lines.append(_paint(f"webaudit  {header}", "bold", color))
    lines.append(
        f"  final   : {result.final_url}  (HTTP {result.status or '-'})"
    )
    if result.resolved_ips:
        lines.append(f"  resolved: {', '.join(result.resolved_ips)}")
    if result.tls is not None:
        tls = result.tls
        lines.append(
            f"  tls     : {tls.version or '-'} / {tls.cipher or '-'} / "
            f"expires in {tls.days_to_expiry if tls.days_to_expiry is not None else '?'}d"
        )
    lines.append(f"  scanned : {_utc_now()}")
    if result.error:
        lines.append(_paint(f"  note    : {result.error}", "dim", color))
    lines.append("")

    grade_style = "ok" if value >= 80 else ("medium" if value >= 55 else "high")
    lines.append(f"  score {_paint(f'{value}/100', grade_style, color)}  "
                 f"grade {_paint(grade(value), grade_style, color)}  "
                 f"({len(findings)} finding(s))")
    lines.append("")

    grouped = group_by_severity(list(findings))
    for severity in SEVERITY_ORDER:
        bucket = grouped[severity]
        if not bucket:
            continue
        lines.append(_paint(f"  {_LABELS[severity]} ({len(bucket)})", severity, color))
        for finding in bucket:
            lines.append(f"    - {finding.title}  [{finding.check_id}]")
            lines.append(_paint(f"      {finding.detail}", "dim", color))
            if finding.evidence:
                lines.append(_paint(f"      evidence : {finding.evidence}", "dim", color))
            if finding.remediation:
                lines.append(f"      fix      : {finding.remediation}")
        lines.append("")

    clean_list = list(clean)
    if clean_list:
        lines.append(_paint(f"  PASSED ({len(clean_list)})", "ok", color))
        for check_id, title in clean_list:
            lines.append(_paint(f"    + {title}  [{check_id}]", "dim", color))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_json(
    result: FetchResult,
    findings: Sequence[Finding],
    clean: Iterable[Tuple[str, str]] = (),
) -> str:
    """Machine-readable report: stable check ids, full evidence."""
    payload = {
        "tool": "webaudit",
        "generated_at": _utc_now(),
        "target": result.as_dict(),
        "score": score(findings),
        "grade": grade(score(findings)),
        "summary": {
            severity: len(group_by_severity(list(findings))[severity])
            for severity in SEVERITY_ORDER
        },
        "findings": [finding.as_dict() for finding in findings],
        "passed": [{"check": cid, "title": title} for cid, title in clean],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_markdown(
    result: FetchResult,
    findings: Sequence[Finding],
    clean: Iterable[Tuple[str, str]] = (),
) -> str:
    """Report suitable for a pull request, ticket or writeup."""
    value = score(findings)
    grouped = group_by_severity(list(findings))
    tls: Optional[dict] = result.tls.as_dict() if result.tls else None

    lines: List[str] = [
        f"# Passive security audit — {result.final_url}",
        "",
        f"*Generated {_utc_now()} with webaudit 0.1.0 (passive, read-only checks).*",
        "",
        f"**Score: {value}/100 (grade {grade(value)})** — {len(findings)} finding(s).",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for severity in SEVERITY_ORDER:
        lines.append(f"| {severity} | {len(grouped[severity])} |")

    lines += [
        "",
        "## Target",
        "",
        f"- Requested URL: `{result.requested_url}`",
        f"- Final URL: `{result.final_url}`",
        f"- HTTP status: `{result.status or '-'}`",
        f"- Resolved IPs: `{', '.join(result.resolved_ips) or 'none'}`",
    ]
    if tls:
        lines += [
            f"- TLS: `{tls.get('version')}` / `{tls.get('cipher')}`",
            f"- Certificate valid: `{tls.get('verified')}`",
            f"- Certificate expires in: `{tls.get('days_to_expiry')}` day(s)",
        ]
    if result.hops:
        lines += ["", "### Redirect chain", ""]
        for index, hop in enumerate(result.hops, start=1):
            lines.append(f"{index}. `{hop.status}` {hop.url}")
            if hop.location:
                lines.append(f"   - Location: `{hop.location}`")

    lines += ["", "## Findings", ""]
    if not findings:
        lines += ["No findings. Every check in the registry passed.", ""]
    for severity in SEVERITY_ORDER:
        for finding in grouped[severity]:
            lines += [
                f"### [{_LABELS[severity]}] {finding.title}",
                "",
                f"- Check: `{finding.check_id}`",
                f"- Category: `{finding.category}`",
                "",
                finding.detail,
                "",
            ]
            if finding.evidence:
                lines += ["```", finding.evidence, "```", ""]
            if finding.remediation:
                lines += [f"**Remediation.** {finding.remediation}", ""]
            if finding.references:
                lines += ["**References**", ""]
                lines += [f"- {reference}" for reference in finding.references]
                lines.append("")

    clean_list = list(clean)
    if clean_list:
        lines += ["## Checks that passed", ""]
        lines += [f"- {title} (`{cid}`)" for cid, title in clean_list]
        lines.append("")

    lines += [
        "---",
        "",
        "Method: webaudit performs a read-only GET of the target, a GET of "
        "`/.well-known/security.txt` and `/robots.txt`, and a single `OPTIONS` request. "
        "It never authenticates, never submits data and never changes remote state.",
        "",
    ]
    return "\n".join(lines)
