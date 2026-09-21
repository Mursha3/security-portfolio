"""Run the rules over a stream of events and assemble one report.

The engine knows nothing about files or formats. It takes events, rules and
parameters, and returns a :class:`Report` - a plain data structure three
renderers can turn into console text, JSON or Markdown.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Sequence

from .models import Finding, grade_for_score, score_from_findings, severity_rank
from .options import Options, format_duration
from .rules import Rule

__all__ = ["Report", "RuleOutcome", "analyze"]


@dataclass
class RuleOutcome:
    """What one rule did, including the rules that matched nothing.

    A report that only lists hits is a report you cannot trust: it never says
    whether a quiet result means "nothing happened" or "that check crashed".
    """

    id: str
    title: str
    severity: str
    mitre: str
    evaluated: int = 0
    fired: int = 0

    @property
    def matched(self) -> bool:
        return self.fired > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "mitre": self.mitre,
            "events_evaluated": self.evaluated,
            "findings": self.fired,
        }


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    rules: List[RuleOutcome] = field(default_factory=list)
    events: int = 0
    inputs: List[str] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)
    suppressed: int = 0
    hidden: int = 0
    generated_at: datetime.datetime = field(default_factory=datetime.datetime.now)

    @property
    def score(self) -> int:
        return score_from_findings(self.findings)

    @property
    def grade(self) -> str:
        return grade_for_score(self.score)

    def count_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def above(self, severity: str) -> List[Finding]:
        """Findings at least as severe as the given level."""
        limit = severity_rank(severity)
        return [f for f in self.findings if severity_rank(f.severity) <= limit]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "logtriage",
            "generated_at": self.generated_at.isoformat(timespec="seconds"),
            "inputs": list(self.inputs),
            "events_parsed": self.events,
            "params": dict(self.params),
            "score": self.score,
            "grade": self.grade,
            "findings_count": len(self.findings),
            "hidden_by_min_severity": self.hidden,
            "suppressed_findings": self.suppressed,
            "findings": [f.to_dict() for f in self.findings],
            "rules": [r.to_dict() for r in self.rules],
        }


def _sort_key(finding: Finding):
    return (severity_rank(finding.severity), -finding.total, finding.rule, finding.source)


def analyze(
    events: Sequence[Any],
    rules: Iterable[Rule],
    inputs: Sequence[str] = (),
    options: Options = None,
    max_per_rule: int = 20,
) -> Report:
    """Feed every event to every rule, then collect and cap the findings."""
    options = options or Options()
    rule_list = list(rules)

    for event in events:
        for rule in rule_list:
            rule.feed(event)

    findings: List[Finding] = []
    outcomes: List[RuleOutcome] = []
    suppressed = 0

    for rule in rule_list:
        produced = sorted(
            rule.findings(),
            key=lambda f: (severity_rank(f.severity), -f.total, f.source),
        )
        suppressed += max(0, len(produced) - max_per_rule)
        produced = produced[:max_per_rule]
        findings.extend(produced)
        outcomes.append(
            RuleOutcome(
                id=rule.id,
                title=rule.title,
                severity=rule.severity,
                mitre=rule.mitre,
                evaluated=rule.evaluated,
                fired=len(rule.findings()),
            )
        )

    findings.sort(key=_sort_key)

    params = {
        "window": format_duration(options.window),
        "fail_threshold": options.fail_threshold,
        "spray_users": options.spray_users,
        "enum_users": options.enum_users,
        "distributed_sources": options.distributed_sources,
        "sudo_fail_threshold": options.sudo_fail_threshold,
        "off_hours": "{:02d}:00-{:02d}:00".format(options.off_hours_start, options.off_hours_end),
        "max_per_rule": max_per_rule,
    }

    return Report(
        findings=findings,
        rules=outcomes,
        events=len(events),
        inputs=list(inputs),
        params=params,
        suppressed=suppressed,
    )
