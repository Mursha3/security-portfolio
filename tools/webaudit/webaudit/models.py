"""Core data types and the scoring model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

# Penalty applied per finding when computing the 0-100 posture score.
SEVERITY_WEIGHTS: Dict[str, int] = {
    "critical": 40,
    "high": 20,
    "medium": 8,
    "low": 3,
    "info": 0,
}

SEVERITY_ORDER: Tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# (minimum score, letter) evaluated in order, highest threshold first.
_GRADE_BANDS: Tuple[Tuple[int, str], ...] = (
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (55, "D"),
    (40, "E"),
)


@dataclass(frozen=True)
class Finding:
    """A single observation about the target.

    ``check_id`` is stable and machine readable so report diffs stay meaningful
    between runs; ``severity`` must be one of :data:`SEVERITY_ORDER`.
    """

    check_id: str
    title: str
    severity: str
    category: str
    detail: str
    evidence: str = ""
    remediation: str = ""
    references: Sequence[str] = ()

    def as_dict(self) -> dict:
        return {
            "check": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": list(self.references),
        }


def score(findings: Iterable[Finding]) -> int:
    """Posture score: 100 minus the summed severity weight, floored at 0."""
    penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    return max(0, 100 - penalty)


def grade(value: int) -> str:
    """Letter grade for a posture score."""
    for threshold, letter in _GRADE_BANDS:
        if value >= threshold:
            return letter
    return "F"


def group_by_severity(findings: Sequence[Finding]) -> Dict[str, List[Finding]]:
    """Bucket findings by severity, in report order."""
    return {sev: [f for f in findings if f.severity == sev] for sev in SEVERITY_ORDER}


def worst_severity(findings: Sequence[Finding]) -> str:
    """Highest severity present, or ``"info"`` for an empty set."""
    for sev in SEVERITY_ORDER:
        if any(f.severity == sev for f in findings):
            return sev
    return "info"
