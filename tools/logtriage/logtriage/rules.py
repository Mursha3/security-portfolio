"""Detection rules.

Every rule is a pure state machine: it is fed Events, it keeps its own small
window of them, and it updates Findings. No rule reads a file, opens a socket,
consults the clock or prints anything. That is what lets the whole detection
surface be tested by handing it six lines of text, and it is the same split
webaudit uses between `checks.py` and `fetch.py`.

Rules aggregate rather than append: one finding per rule per source, mutated as
more evidence arrives. A 50,000-line brute force produces one finding with a
count, a peak rate and the first five lines - not 12,000 findings nobody reads.
"""

from __future__ import annotations

import datetime
import os
import re
from collections import deque
from typing import Deque, Dict, Iterable, List, Optional, Tuple

from .models import (
    CRON_COMMAND,
    GROUP_MODIFY,
    PASSWORD_CHANGE,
    SSH_ACCEPTED_PASSWORD,
    SSH_ACCEPTED_PUBKEY,
    SSH_FAILED_PASSWORD,
    SSH_INVALID_USER,
    SUDO_AUTH_FAILURE,
    SUDO_COMMAND,
    SU_SESSION_OPEN,
    USER_ADD,
    USER_MODIFY,
    Event,
    Finding,
    severity_rank,
)
from .options import Options, format_duration

__all__ = ["Rule", "default_rules"]

# Interpreters and remote-shell tools. Running any of these through sudo is
# equivalent to handing over a root shell, which is usually not what an
# operations team intends to grant - and is exactly what an intruder does after
# stealing a password.
_SHELLS = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "ash",
    "python", "python2", "python3", "perl", "ruby", "php", "node", "lua",
    "awk", "gawk", "expect", "busybox", "nc", "ncat", "netcat", "socat",
    "su", "sudo", "screen", "tmux", "env", "find", "vi", "vim", "nano", "less",
}

_PAYLOAD_FETCH = re.compile(r"\b(curl|wget|tftp|ftp|nc|ncat|socat)\b")
_PIPE_TO_SHELL = re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b|\|\s*(?:python\d?|perl|ruby)\b")

# Things worth alerting on when they appear inside a sudo command. Each entry is
# a pattern plus the plain-language reason, because a report that says "matched
# pattern X" teaches nobody anything.
_SENSITIVE_TARGETS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"authorized_keys"), "SSH authorized_keys"),
    (re.compile(r"/etc/sudoers|visudo"), "sudo configuration"),
    (re.compile(r"/etc/shadow"), "password hashes"),
    (re.compile(r"/etc/passwd"), "local account database"),
    (re.compile(r"/etc/ssh/sshd_config"), "SSH server configuration"),
    (re.compile(r"chmod\s+(?:777|666|\+s|u\+s|g\+s)"), "world-writable or setuid bit"),
    (re.compile(r"chown\s+root"), "ownership handed to root"),
    (re.compile(r"iptables\s+-F|ufw\s+disable|setenforce\s+0|apparmor_parser\s+-R"),
     "host firewall or mandatory access control disabled"),
    (re.compile(r"systemctl\s+(?:stop|disable|mask)\s+\S*(?:auditd|rsyslog|ufw|apparmor|syslog)"),
     "auditing or logging service stopped"),
    (re.compile(r"history\s+-c"), "shell history wiped"),
    (re.compile(r">>?\s*/etc/"), "redirection into /etc"),
    (re.compile(r"crontab\s+-"), "cron table written"),
    (re.compile(r"dd\b.*of=/dev/"), "raw write to a block device"),
    (re.compile(r"base64\s+-d|xxd\s+-r|openssl\s+enc\s+-d"), "encoded payload decoded"),
]

_SUSPICIOUS_CRON = re.compile(
    r"\b(curl|wget|nc|ncat|socat|base64|python\d?|perl|bash|sh\s+-c)\b|\|\s*(?:sh|bash)\b"
)

# Groups that carry administrative power on a normal Linux host.
_PRIVILEGED_GROUPS = {
    "sudo", "wheel", "adm", "admin", "root", "shadow", "disk", "docker", "lxd",
}

_FAILED_SSH_KINDS = (SSH_FAILED_PASSWORD,)
_SUCCESS_SSH_KINDS = (SSH_ACCEPTED_PASSWORD, SSH_ACCEPTED_PUBKEY)


def _basename(token: str) -> str:
    token = token.strip().strip("\"'")
    return os.path.basename(token).lower()


def _first_token(command: str) -> str:
    parts = command.strip().split()
    return _basename(parts[0]) if parts else ""


def _escalate(count: int, medium_at: int, high_at: int, critical_at: int) -> str:
    if count >= critical_at:
        return "critical"
    if count >= high_at:
        return "high"
    if count >= medium_at:
        return "medium"
    return "low"


class Rule:
    """Base class: window bookkeeping, finding aggregation, nothing else."""

    id = "rule"
    title = "Rule"
    severity = "medium"
    mitre = ""
    remediation = ""
    tags: Tuple[str, ...] = ()

    def __init__(self, options: Optional[Options] = None) -> None:
        self.options = options or Options()
        self._findings: Dict[str, Finding] = {}
        self._buckets: Dict[str, Deque[Event]] = {}
        self._counters: Dict[str, int] = {}
        self.evaluated = 0

    # --- helpers ---------------------------------------------------------
    def _window(self, key: str, event: Event) -> Deque[Event]:
        """Append the event and drop anything older than the window."""
        bucket = self._buckets.setdefault(key, deque())
        bucket.append(event)
        self._prune(bucket, event.ts)
        return bucket

    def _prune(self, bucket: Deque[Event], now: Optional[datetime.datetime]) -> None:
        """Drop events that have aged out. Rules that read a bucket without
        adding to it must prune first, or a quiet hour of old failures still
        counts against the rate."""
        if now is None:
            return
        cutoff = now - self.options.window
        while bucket and bucket[0].ts is not None and bucket[0].ts < cutoff:
            bucket.popleft()

    def _finding(self, key: str, event: Event) -> Finding:
        finding = self._findings.get(key)
        if finding is None:
            finding = Finding(
                rule=self.id,
                title=self.title,
                severity=self.severity,
                source=key,
                mitre=self.mitre,
                remediation=self.remediation,
                tags=list(self.tags),
                first_seen=event.ts,
            )
            self._findings[key] = finding
        return finding

    def _bump(self, key: str) -> int:
        """Count an event that does not (yet) deserve a finding of its own."""
        value = self._counters.get(key, 0) + 1
        self._counters[key] = value
        return value

    def _record(
        self,
        key: str,
        event: Event,
        severity: str,
        count: int,
        summary: str,
        actor: str = "",
        total: Optional[int] = None,
        evidence: Optional[Iterable[Event]] = None,
    ) -> Finding:
        finding = self._finding(key, event)
        finding.severity = severity
        finding.count = count
        # `count` is the rate inside the window; `total` is everything the rule
        # saw for this source across the whole log. Two numbers, because a slow
        # and quiet attack and a fast and loud one are different problems.
        finding.total = total if total is not None else max(finding.total, count)
        finding.summary = summary
        if event.ts is not None:
            if finding.first_seen is None or event.ts < finding.first_seen:
                finding.first_seen = event.ts
            finding.last_seen = event.ts
        finding.add_actor(actor or event.user)
        # A rate-based finding is only defensible with the lines behind the rate,
        # so when a rule hands over its window, the evidence is replaced with
        # that window rather than appended to. Appending would re-add the same
        # lines on every update and inflate the count of what was left out.
        if evidence is not None:
            finding.evidence = []
            finding.suppressed_evidence = 0
            for item in evidence:
                finding.add_evidence(item.raw.strip(), self.options.max_evidence)
                finding.add_actor(item.user)
        else:
            finding.add_evidence(event.raw.strip(), self.options.max_evidence)
        return finding

    def feed(self, event: Event) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def finish(self) -> None:
        """Hook for rules that can only decide once every event was seen."""

    def findings(self) -> List[Finding]:
        return [self._findings[k] for k in sorted(self._findings)]

    def window_text(self) -> str:
        return format_duration(self.options.window)


class SshBruteForceSingleSource(Rule):
    id = "ssh-bruteforce-single-source"
    title = "Repeated SSH authentication failures from one source"
    severity = "medium"
    mitre = "T1110.001 (Brute Force: Password Guessing)"
    remediation = (
        "Block the source address at the edge, confirm password authentication is "
        "disabled for every account, and check whether any of the attempts used a "
        "name that exists locally."
    )
    tags = ("authentication", "remote-access")

    def feed(self, event: Event) -> None:
        if event.kind not in _FAILED_SSH_KINDS or event.ts is None:
            return
        if not event.source_ip:
            return
        self.evaluated += 1
        bucket = self._window(event.source_ip, event)
        total = self._bump("brute:" + event.source_ip)
        count = len(bucket)
        if count < self.options.fail_threshold:
            return
        base = self.options.fail_threshold
        severity = _escalate(count, base, base * 3, base * 10)
        self._record(
            event.source_ip,
            event,
            severity,
            count,
            "{} failed SSH logins from {} within {} ({:.1f}/min), {} in total".format(
                count,
                event.source_ip,
                self.window_text(),
                count / max(self.options.window.total_seconds() / 60.0, 1e-9),
                total,
            ),
            event.user,
            total=total,
            evidence=bucket,
        )


class SshPasswordSpray(Rule):
    id = "ssh-password-spray"
    title = "One source trying many different accounts"
    severity = "high"
    mitre = "T1110.003 (Brute Force: Password Spraying)"
    remediation = (
        "Spraying means the attacker already knows valid account names. Block the "
        "source, and treat every account that was tried as potentially locked out."
    )
    tags = ("authentication", "remote-access")

    def feed(self, event: Event) -> None:
        if event.kind not in _FAILED_SSH_KINDS or event.ts is None:
            return
        if not event.source_ip or not event.user:
            return
        self.evaluated += 1
        bucket = self._window("spray:{}".format(event.source_ip), event)
        users = {e.user for e in bucket if e.user}
        if len(users) < self.options.spray_users:
            return
        self._bump("spray:" + event.source_ip)
        # Spraying rarely covers a hundred accounts; ten names from one address in
        # ten minutes is already a deliberate sweep, not a person mistyping.
        severity = "critical" if len(users) >= self.options.spray_users * 2 else "high"
        self._record(
            event.source_ip,
            event,
            severity,
            len(users),
            "{} distinct accounts tried from {} within {}: {}".format(
                len(users),
                event.source_ip,
                self.window_text(),
                ", ".join(sorted(users)[:6]),
            ),
            event.user,
            evidence=bucket,
        )


class SshUserEnumeration(Rule):
    id = "ssh-user-enumeration"
    title = "Invalid usernames probed over SSH"
    severity = "medium"
    mitre = "T1087.001 (Account Discovery: Local Account)"
    remediation = (
        "Names that do not exist still reveal which ones do, and they fill the log "
        "with noise. Block the source and keep an eye on the addressed names - they "
        "usually reappear in a later spray."
    )
    tags = ("discovery", "remote-access")

    def feed(self, event: Event) -> None:
        if event.kind not in (SSH_INVALID_USER, SSH_FAILED_PASSWORD) or event.ts is None:
            return
        if not event.invalid_user or not event.source_ip:
            return
        self.evaluated += 1
        bucket = self._window("enum:{}".format(event.source_ip), event)
        names = {e.user for e in bucket if e.user}
        if len(names) < self.options.enum_users:
            return
        self._bump("enum:" + event.source_ip)
        self._record(
            event.source_ip,
            event,
            "medium",
            len(names),
            "{} non-existent usernames probed from {} within {}: {}".format(
                len(names),
                event.source_ip,
                self.window_text(),
                ", ".join(sorted(names)[:6]),
            ),
            event.user,
            evidence=bucket,
        )


class SshDistributedBruteForce(Rule):
    id = "ssh-distributed-bruteforce"
    title = "One account attacked from many sources"
    severity = "high"
    mitre = "T1110.003 (Brute Force: Password Spraying)"
    remediation = (
        "Distributed attempts defeat per-address blocking. Enforce key-only "
        "authentication, rate limit at the load balancer, and enable fail2ban with "
        "the recidive jail or an equivalent control."
    )
    tags = ("authentication", "remote-access")

    def feed(self, event: Event) -> None:
        if event.kind not in _FAILED_SSH_KINDS or event.ts is None:
            return
        if not event.user or not event.source_ip:
            return
        self.evaluated += 1
        bucket = self._window("dist:{}".format(event.user), event)
        sources = {e.source_ip for e in bucket if e.source_ip}
        if len(sources) < self.options.distributed_sources:
            return
        self._bump("dist:" + event.user)
        severity = "critical" if len(sources) >= self.options.distributed_sources * 4 else "high"
        self._record(
            event.user,
            event,
            severity,
            len(sources),
            "account '{}' failed authentication from {} distinct addresses within {}".format(
                event.user, len(sources), self.window_text()
            ),
            event.user,
            evidence=bucket,
        )


class SshFailedThenAccepted(Rule):
    id = "ssh-failed-then-accepted"
    title = "Successful SSH login after failed attempts from the same source"
    severity = "high"
    mitre = "T1078 (Valid Accounts), following T1110 (Brute Force)"
    remediation = (
        "Treat the session as compromised until proven otherwise: rotate the "
        "account's credentials and keys, review what the session did, and check "
        "whether it installed persistence."
    )
    tags = ("authentication", "possible-compromise")

    def feed(self, event: Event) -> None:
        if event.ts is None or not event.source_ip:
            return
        if event.kind in _FAILED_SSH_KINDS:
            self.evaluated += 1
            self._bump("fails:" + event.source_ip)
            self._window(event.source_ip, event)
            return
        if event.kind not in _SUCCESS_SSH_KINDS:
            return
        self.evaluated += 1
        bucket = self._buckets.get(event.source_ip)
        if bucket:
            self._prune(bucket, event.ts)
        count = len(bucket) if bucket else 0
        if count == 0:
            return
        # One failure before a success is usually a typo, so it is worth a medium
        # and not a critical. A threshold's worth of failures before a success is
        # not a typo any more - that is a worklist, and it worked.
        threshold = self.options.fail_threshold
        if count >= threshold:
            severity = "critical"
        elif count >= max(2, threshold // 2):
            severity = "high"
        else:
            severity = "medium"
        self._record(
            event.source_ip,
            event,
            severity,
            count,
            "'{}' authenticated from {} over {} after {} failed attempt(s) in the same "
            "window ({} in total)".format(
                event.user or "?",
                event.source_ip,
                event.auth_method or "password",
                count,
                self._counters.get("fails:" + event.source_ip, count),
            ),
            event.user,
            # The failures, plus the login that ended them - that pairing is the
            # whole point of the finding, so the success must not be crowded out.
            evidence=list(bucket)[: max(self.options.max_evidence - 1, 1)] + [event],
        )


class SshRootLogin(Rule):
    id = "ssh-root-login"
    title = "Direct login as root over SSH"
    severity = "high"
    mitre = "T1078.003 (Valid Accounts: Local Accounts)"
    remediation = (
        "Set PermitRootLogin to prohibit-password or no, and give administrators "
        "named accounts with sudo instead - an event log then says who did it."
    )
    tags = ("authentication", "misconfiguration")

    def feed(self, event: Event) -> None:
        if event.kind not in _SUCCESS_SSH_KINDS or event.user != "root":
            return
        self.evaluated += 1
        key = event.source_ip or "unknown-source"
        self._record(
            key,
            event,
            "high",
            1,
            "root authenticated over SSH from {} using {} as {}".format(
                event.source_ip or "an unknown source",
                event.auth_method or "password",
                event.user,
            ),
            "root",
            total=self._bump("root-login:" + key),
        )


class SudoShellEscape(Rule):
    id = "sudo-shell-escape"
    title = "sudo used to start a shell or interpreter"
    severity = "high"
    mitre = "T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching)"
    remediation = (
        "Replace the rule with explicit command allow-listing, or move the "
        "workload into a unit that does not need a shell. A blanket NOPASSWD shell "
        "entry is a root shell with extra steps."
    )
    tags = ("privilege-escalation",)

    def feed(self, event: Event) -> None:
        if event.kind != SUDO_COMMAND:
            return
        token = _first_token(event.command)
        if token not in _SHELLS:
            return
        self.evaluated += 1
        key = event.user or "unknown"
        self._record(
            key,
            event,
            "high",
            1,
            "'{}' escalated to {} and started '{}', which is a full shell rather than "
            "a single command".format(event.user or "unknown", event.target or "root", token),
            event.user,
            total=self._bump("shell-escape:" + key),
        )


class SudoSensitiveCommand(Rule):
    id = "sudo-sensitive-command"
    title = "sudo command touching authentication or audit configuration"
    severity = "high"
    mitre = "T1098 (Account Manipulation), T1562.001 (Impair Defenses)"
    remediation = (
        "Confirm the change was authorised and recorded outside the log, then "
        "restore the file from configuration management. Changes like these are how "
        "access survives a password reset."
    )
    tags = ("privilege-escalation", "persistence")

    def feed(self, event: Event) -> None:
        if event.kind != SUDO_COMMAND:
            return
        for pattern, reason in _SENSITIVE_TARGETS:
            if not pattern.search(event.command):
                continue
            self.evaluated += 1
            key = "{}:{}".format(event.user or "unknown", pattern.pattern)
            self._record(
                key,
                event,
                "high",
                1,
                "'{}' ran a root command touching {}: {}".format(
                    event.user or "unknown", reason, event.command[:160]
                ),
                event.user,
                total=self._bump("sensitive:" + key),
            )
            return


class SudoPayloadFetch(Rule):
    id = "sudo-payload-fetch"
    title = "sudo used to download or pipe remote content"
    severity = "medium"
    mitre = "T1105 (Ingress Tool Transfer)"
    remediation = (
        "Fetch artifacts as an unprivileged user and install them through the "
        "package manager. A root-owned transfer from a bare IP or a temporary "
        "domain is the payload stage of an intrusion."
    )
    tags = ("privilege-escalation", "tool-transfer")

    def feed(self, event: Event) -> None:
        if event.kind != SUDO_COMMAND:
            return
        if not _PAYLOAD_FETCH.search(event.command):
            return
        self.evaluated += 1
        key = event.user or "unknown"
        piped = bool(_PIPE_TO_SHELL.search(event.command))
        self._record(
            key,
            event,
            "high" if piped else "medium",
            1,
            "'{}' used sudo to fetch remote content{}: {}".format(
                event.user or "unknown",
                " and pipe it straight into a shell" if piped else "",
                event.command[:160],
            ),
            event.user,
            total=self._bump("fetch:" + key),
        )


class SudoFailedAttempts(Rule):
    id = "sudo-failed-attempts"
    title = "Repeated failed sudo authentication"
    severity = "medium"
    mitre = "T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching)"
    remediation = (
        "An account guessing its own sudo password is either a user who forgot it "
        "or someone who just took over that account. Confirm which with the account "
        "owner before locking anything."
    )
    tags = ("privilege-escalation",)

    def feed(self, event: Event) -> None:
        if event.kind != SUDO_AUTH_FAILURE or event.process not in ("sudo", "su"):
            return
        self.evaluated += 1
        key = event.user or event.process
        count = self._bump("sudo-fail:" + key)
        if count < self.options.sudo_fail_threshold:
            return
        base = self.options.sudo_fail_threshold
        self._record(
            key,
            event,
            _escalate(count, base, base * 3, base * 10),
            count,
            "'{}' failed sudo authentication {} times".format(key, count),
            key,
        )


class SuToRoot(Rule):
    id = "su-to-root"
    title = "su session opened for root"
    severity = "medium"
    mitre = "T1548.003 (Abuse Elevation Control Mechanism)"
    remediation = (
        "Prefer sudo, which logs the command that ran. A su session has no "
        "authorisation decision in it: whoever knows the root password gets in."
    )
    tags = ("privilege-escalation",)

    def feed(self, event: Event) -> None:
        if event.kind != SU_SESSION_OPEN or event.target != "root" or not event.user:
            return
        if event.user == "root":
            return
        self.evaluated += 1
        self._record(
            event.user,
            event,
            "medium",
            1,
            "'{}' opened a root shell through su".format(event.user),
            event.user,
            total=self._bump("su:" + event.user),
        )


class AccountCreated(Rule):
    id = "account-created"
    title = "New local account created"
    severity = "high"
    mitre = "T1136.001 (Create Account: Local Account)"
    remediation = (
        "Verify against a change record. An account created outside change "
        "management is a durable way back in that survives a password reset."
    )
    tags = ("persistence", "account-changes")

    def feed(self, event: Event) -> None:
        if event.kind != USER_ADD or not event.user:
            return
        self.evaluated += 1
        self._record(
            event.user,
            event,
            "high",
            1,
            "account '{}' was created ({})".format(event.user, event.command or "no details"),
            event.user,
            total=self._bump("new:" + event.user),
        )


class PrivilegedGroupChange(Rule):
    id = "privileged-group-change"
    title = "Account added to an administrative group"
    severity = "high"
    mitre = "T1098 (Account Manipulation)"
    remediation = (
        "Check who authorised the change and remove the membership if it cannot be "
        "explained. Group membership is a quieter route to root than editing sudoers."
    )
    tags = ("persistence", "account-changes")

    def feed(self, event: Event) -> None:
        if event.kind not in (USER_MODIFY, GROUP_MODIFY):
            return
        group = (event.target or event.user or "").lower()
        if not group:
            return
        self.evaluated += 1
        key = "{}:{}".format(event.user or "?", group)
        if group not in _PRIVILEGED_GROUPS:
            self._record(
                key,
                event,
                "low",
                1,
                "'{}' membership of group '{}' changed".format(event.user or "?", group),
                event.user,
                total=self._bump("group:" + key),
            )
            return
        self._record(
            key,
            event,
            "high",
            1,
            "'{}' was added to administrative group '{}'".format(event.user or "?", group),
            event.user,
            total=self._bump("group:" + key),
        )


class PasswordChanged(Rule):
    id = "password-changed"
    title = "Local password change"
    severity = "medium"
    mitre = "T1098 (Account Manipulation)"
    remediation = (
        "Correlate with a ticket. A password change on a service or administrator "
        "account is how an intruder keeps access after the incident response that "
        "removed their first foothold."
    )
    tags = ("account-changes",)

    def feed(self, event: Event) -> None:
        if event.kind != PASSWORD_CHANGE or not event.user:
            return
        self.evaluated += 1
        self._record(
            event.user,
            event,
            "medium",
            1,
            "password changed for '{}'".format(event.user),
            event.user,
            total=self._bump("pw:" + event.user),
        )


class SuspiciousCron(Rule):
    id = "suspicious-cron-command"
    title = "Cron job running a shell, interpreter or download"
    severity = "high"
    mitre = "T1053.003 (Scheduled Task/Job: Cron)"
    remediation = (
        "Compare the cron table against configuration management. Scheduled tasks "
        "run unattended, survive reboots and are often missed entirely by "
        "perimeter-focused monitoring."
    )
    tags = ("persistence",)

    def feed(self, event: Event) -> None:
        if event.kind != CRON_COMMAND:
            return
        self.evaluated += 1
        if not _SUSPICIOUS_CRON.search(event.command):
            return
        key = "{}:{}".format(event.user or "?", event.command[:60])
        self._record(
            key,
            event,
            "high",
            1,
            "cron command by '{}' runs a shell or fetches content: {}".format(
                event.user or "?", event.command[:160]
            ),
            event.user,
            total=self._bump("cron:" + key),
        )


class OffHoursLogin(Rule):
    id = "off-hours-login"
    title = "Interactive login outside working hours"
    severity = "info"
    mitre = ""
    remediation = (
        "Nothing to fix on its own. Useful as correlation: an off-hours login from "
        "an address that also shows failed attempts is worth a phone call."
    )
    tags = ("context",)

    def feed(self, event: Event) -> None:
        if event.kind not in _SUCCESS_SSH_KINDS or event.ts is None:
            return
        hour = event.ts.hour
        start, end = self.options.off_hours_start, self.options.off_hours_end
        if start <= end:
            quiet = start <= hour < end
        else:
            quiet = hour >= start or hour < end
        if not quiet:
            return
        self.evaluated += 1
        key = "{}@{}".format(event.user or "?", event.source_ip or "local")
        self._record(
            key,
            event,
            "info",
            1,
            "'{}' logged in at {:02d}:{:02d}, outside the {:02d}:00-{:02d}:00 window".format(
                event.user or "?", event.ts.hour, event.ts.minute, end, start
            ),
            event.user,
            total=self._bump("off:" + key),
        )


def default_rules(options: Optional[Options] = None) -> List[Rule]:
    """Every shipped rule, in report order."""
    options = options or Options()
    classes = (
        SshFailedThenAccepted,
        SshBruteForceSingleSource,
        SshPasswordSpray,
        SshDistributedBruteForce,
        SshUserEnumeration,
        SshRootLogin,
        SudoShellEscape,
        SudoSensitiveCommand,
        SudoPayloadFetch,
        SudoFailedAttempts,
        SuToRoot,
        AccountCreated,
        PrivilegedGroupChange,
        PasswordChanged,
        SuspiciousCron,
        OffHoursLogin,
    )
    return [cls(options) for cls in classes]
