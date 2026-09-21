"""Core data types for logtriage.

A log line is parsed exactly once, into an :class:`Event`. From that point on no
rule touches raw text again: rules decide, the parser reads, the report writes.
The same split as webaudit, for the same reason - detection logic stays testable
without a filesystem, a socket or a clock.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

__all__ = [
    "SEVERITIES",
    "SEVERITY_WEIGHTS",
    "severity_rank",
    "score_from_findings",
    "grade_for_score",
    "Event",
    "Finding",
]

# Ordered from most to least severe. Anything user-facing iterates this order.
SEVERITIES = ("critical", "high", "medium", "low", "info")

# Weights are intentionally in one place and separate from detection logic: if
# you disagree with how much a finding costs, you change a number here and
# nothing else. Same numbers as webaudit, so scores from the two tools read the
# same way in a report.
SEVERITY_WEIGHTS: Dict[str, int] = {
    "critical": 40,
    "high": 20,
    "medium": 8,
    "low": 3,
    "info": 0,
}


def severity_rank(severity: str) -> int:
    """Lower number means more severe. Unknown severities sort last."""
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return len(SEVERITIES)


def score_from_findings(findings: List["Finding"]) -> int:
    """100 minus the weight of every finding, floored at 0.

    Counts a finding per affected source, not per rule: ten source addresses
    each failing authentication are ten separate problems on the wire.
    """
    penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    return max(0, 100 - penalty)


def grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


# Event kinds. Strings rather than an enum so that a rule file and a test both
# stay readable, and so an unknown kind from a future parser is still printable.
SSH_ACCEPTED_PASSWORD = "ssh_accepted_password"
SSH_ACCEPTED_PUBKEY = "ssh_accepted_pubkey"
SSH_FAILED_PASSWORD = "ssh_failed_password"
SSH_INVALID_USER = "ssh_invalid_user"
SSH_MAX_ATTEMPTS = "ssh_max_attempts"
SSH_DISCONNECT = "ssh_disconnect"
SSH_SESSION_OPEN = "ssh_session_open"
SESSION_NEW = "session_new"
SUDO_COMMAND = "sudo_command"
SUDO_AUTH_FAILURE = "sudo_auth_failure"
AUTH_FAILURE = "auth_failure"
SU_SESSION_OPEN = "su_session_open"
USER_ADD = "user_add"
USER_MODIFY = "user_modify"
PASSWORD_CHANGE = "password_change"
GROUP_MODIFY = "group_modify"
CRON_COMMAND = "cron_command"
OTHER = "other"


@dataclass
class Event:
    """One parsed log line.

    ``ts`` is None when the line carries no timestamp we could trust; windowed
    rules skip those events rather than guessing at a time.
    """

    raw: str
    line_no: int = 0
    ts: Optional[datetime.datetime] = None
    host: str = ""
    process: str = ""
    pid: Optional[int] = None
    kind: str = OTHER
    message: str = ""
    user: str = ""
    target: str = ""
    source_ip: str = ""
    source_port: Optional[int] = None
    command: str = ""
    tty: str = ""
    invalid_user: bool = False
    auth_method: str = ""

    def key(self) -> str:
        """Best available identity for the actor behind the line."""
        return self.source_ip or self.user or "?"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "line_no": self.line_no,
            "ts": self.ts.isoformat() if self.ts else None,
            "host": self.host,
            "process": self.process,
            "kind": self.kind,
            "user": self.user,
            "target": self.target,
            "source_ip": self.source_ip,
            "command": self.command,
            "raw": self.raw,
        }


@dataclass
class Finding:
    """A detection that fired, aggregated over every event behind it.

    One finding per rule per source: as more evidence arrives the same object is
    updated (count, severity, last_seen) instead of a new one being appended.
    That keeps a 50,000-line log from producing 3,000 identical findings, and it
    makes the finding itself the timeline.
    """

    rule: str
    title: str
    severity: str
    source: str = ""
    summary: str = ""
    count: int = 0
    total: int = 0
    evidence: List[str] = field(default_factory=list)
    actors: List[str] = field(default_factory=list)
    first_seen: Optional[datetime.datetime] = None
    last_seen: Optional[datetime.datetime] = None
    mitre: str = ""
    remediation: str = ""
    tags: List[str] = field(default_factory=list)
    suppressed_evidence: int = 0

    def add_actor(self, name: str) -> None:
        if name and name not in self.actors:
            self.actors.append(name)

    def add_evidence(self, line: str, keep: int) -> None:
        if len(self.evidence) < keep:
            self.evidence.append(line)
        else:
            self.suppressed_evidence += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity,
            "source": self.source,
            "summary": self.summary,
            "count": self.count,
            "total": self.total,
            "actors": sorted(self.actors),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "mitre": self.mitre,
            "remediation": self.remediation,
            "tags": list(self.tags),
            "evidence": list(self.evidence),
            "suppressed_evidence": self.suppressed_evidence,
        }
