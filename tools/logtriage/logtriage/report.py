"""Render a Report as console text, JSON or Markdown.

Renderers are pure functions of the report. Nothing here reads the filesystem or
recomputes a detection - if a renderer disagrees with a finding, the bug is in
the rule, and this module is the wrong place to fix it.
"""

from __future__ import annotations

import json
from typing import Dict, Iterable, List

from .models import SEVERITIES
from .engine import Report

__all__ = ["render_console", "render_json", "render_markdown"]

_COLORS = {
    "critical": "\033[1;91m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[36m",
    "info": "\033[90m",
    "reset": "\033[0m",
    "dim": "\033[90m",
    "bold": "\033[1m",
}

_SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def _paint(text: str, severity: str, color: bool) -> str:
    if not color or severity not in _COLORS:
        return text
    return "{}{}{}".format(_COLORS[severity], text, _COLORS["reset"])


def _stamp(value) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else "unknown time"


def render_console(report: Report, color: bool = True) -> str:
    out: List[str] = []
    header = "logtriage - authentication log triage"
    out.append(header if not color else "{}{}{}".format(_COLORS["bold"], header, _COLORS["reset"]))
    names = list(report.inputs[:4])
    if len(report.inputs) > 4:
        names.append("+{} more".format(len(report.inputs) - 4))
    out.append(
        "inputs: {} file(s), {} event(s) parsed".format(len(report.inputs), report.events)
    )
    if names:
        out.append("         {}".format(", ".join(names)))
    params = report.params
    out.append(
        "window {}  |  failed-logins threshold {}  |  spray {} users  |  "
        "sudo failures {}  |  quiet hours {}".format(
            params.get("window", "?"),
            params.get("fail_threshold", "?"),
            params.get("spray_users", "?"),
            params.get("sudo_fail_threshold", "?"),
            params.get("off_hours", "?"),
        )
    )
    out.append("")

    if not report.findings:
        out.append(_paint("No findings.", "low", color))
    else:
        by_severity: Dict[str, List] = {}
        for finding in report.findings:
            by_severity.setdefault(finding.severity, []).append(finding)

        for severity in SEVERITIES:
            group = by_severity.get(severity)
            if not group:
                continue
            label = _SEVERITY_LABEL[severity]
            out.append(_paint("{} ({})".format(label, len(group)), severity, color))
            if severity == "info":
                out.append("  context only - useful for correlation, not a problem by itself")
            for finding in group:
                # ASCII only in console output: this runs on Windows terminals
                # whose codepage will happily mangle anything prettier.
                out.append(
                    "  {}  -  source {}".format(finding.rule, finding.source or "n/a")
                )
                if finding.summary:
                    out.append("    {}".format(finding.summary))
                span = "{} -> {}".format(_stamp(finding.first_seen), _stamp(finding.last_seen))
                out.append(
                    "    {} in window, {} in total, {}".format(
                        finding.count, finding.total, span
                    )
                )
                if finding.actors:
                    out.append("    accounts: {}".format(", ".join(finding.actors[:8])))
                if finding.mitre:
                    out.append("    MITRE: {}".format(finding.mitre))
                if finding.evidence:
                    out.append("    evidence:")
                    for line in finding.evidence:
                        out.append("      | {}".format(line[:200]))
                    if finding.suppressed_evidence:
                        out.append(
                            "      (+{} further matching lines not shown)".format(
                                finding.suppressed_evidence
                            )
                        )
                if finding.remediation:
                    out.append("    fix: {}".format(finding.remediation))
                out.append("")

    fired_rules = {f.rule for f in report.findings}
    quiet = [r for r in report.rules if r.id not in fired_rules]
    if quiet:
        out.append("RULES WITH NO MATCH ({})".format(len(quiet)))
        for outcome in quiet:
            out.append(
                "  {}  -  evaluated {} event(s)".format(outcome.id, outcome.evaluated)
            )
        out.append("")

    counts = report.count_by_severity()
    summary = "score {}/100  grade {}  ({} finding(s) across {} rule(s))".format(
        report.score,
        report.grade,
        len(report.findings),
        len(fired_rules),
    )
    if counts:
        summary += "  |  " + "  ".join(
            "{} {}".format(counts[s], s) for s in SEVERITIES if s in counts
        )
    if report.suppressed:
        summary += "  |  {} finding(s) beyond the per-rule cap".format(report.suppressed)
    if report.hidden:
        summary += "  |  {} finding(s) hidden by --min-severity".format(report.hidden)
    out.append(summary)
    return "\n".join(out)


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)


def _md_table(findings: Iterable) -> List[str]:
    lines = [
        "| Severity | Rule | Source | Count in window | Total | First seen | Last seen |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        lines.append(
            "| {} | `{}` | `{}` | {} | {} | {} | {} |".format(
                finding.severity.upper(),
                finding.rule,
                finding.source or "-",
                finding.count,
                finding.total,
                _stamp(finding.first_seen),
                _stamp(finding.last_seen),
            )
        )
    return lines


def render_markdown(report: Report) -> str:
    params = report.params
    out: List[str] = []
    out.append("# Authentication log triage")
    out.append("")
    out.append("Generated {}.".format(report.generated_at.strftime("%Y-%m-%d %H:%M:%S")))
    out.append("")
    out.append("- Inputs: {}".format(", ".join("`{}`".format(i) for i in report.inputs) or "stdin"))
    out.append("- Events parsed: {}".format(report.events))
    out.append("- Window: {} · failed-login threshold {} · spray threshold {} users".format(
        params.get("window"), params.get("fail_threshold"), params.get("spray_users")))
    out.append("- **Score {}/100, grade {}** ({} finding(s))".format(
        report.score, report.grade, len(report.findings)))
    if report.hidden:
        out.append("- {} finding(s) hidden by --min-severity".format(report.hidden))
    if report.suppressed:
        out.append("- {} finding(s) beyond the per-rule cap".format(report.suppressed))
    out.append("")

    if not report.findings:
        out.append("No findings.")
        out.append("")
    else:
        out.append("## Summary")
        out.append("")
        out.extend(_md_table(report.findings))
        out.append("")
        out.append("## Findings")
        out.append("")
        for finding in report.findings:
            out.append("### {} — {} ({})".format(
                finding.severity.upper(), finding.title, finding.rule))
            out.append("")
            if finding.summary:
                out.append(finding.summary)
                out.append("")
            out.append("- Source: `{}`".format(finding.source or "n/a"))
            out.append("- Events: {} inside the window, {} in total".format(
                finding.count, finding.total))
            out.append("- Window: {} → {}".format(
                _stamp(finding.first_seen), _stamp(finding.last_seen)))
            if finding.actors:
                out.append("- Accounts involved: {}".format(
                    ", ".join("`{}`".format(a) for a in finding.actors[:10])))
            if finding.mitre:
                out.append("- MITRE ATT&CK: {}".format(finding.mitre))
            out.append("")
            if finding.evidence:
                out.append("Evidence:")
                out.append("")
                out.append("```")
                out.extend(finding.evidence)
                if finding.suppressed_evidence:
                    out.append("(+{} further matching lines)".format(finding.suppressed_evidence))
                out.append("```")
                out.append("")
            if finding.remediation:
                out.append("**Remediation.** {}".format(finding.remediation))
                out.append("")

    fired_rules = {f.rule for f in report.findings}
    out.append("## Rule coverage")
    out.append("")
    out.append("| Rule | Severity | Events evaluated | Findings | MITRE |")
    out.append("| --- | --- | --- | --- | --- |")
    for outcome in report.rules:
        out.append("| `{}` | {} | {} | {} | {} |".format(
            outcome.id,
            outcome.severity,
            outcome.evaluated,
            outcome.fired,
            outcome.mitre or "-",
        ))
    out.append("")
    quiet = [r.id for r in report.rules if r.id not in fired_rules]
    if quiet:
        out.append("Rules that ran and matched nothing: {}.".format(
            ", ".join("`{}`".format(r) for r in quiet)))
        out.append("")
    return "\n".join(out)
