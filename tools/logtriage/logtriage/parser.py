"""Turn syslog lines into Events.

Two formats are handled, because both turn up in the same investigation: the
classic ``Sep 21 18:52:11 host sshd[123]: ...`` shape that ``/var/log/auth.log``
uses, and the ISO-8601 shape rsyslog writes with ``RSYSLOG_FileFormat``.

The classic format carries no year. This is the first thing that bites anyone
parsing auth.log, and it bites silently: events from last December end up sorted
as if they were from this month. So the parser takes a starting year and rolls
it forward on its own whenever the month goes backwards.
"""

from __future__ import annotations

import datetime
import re
from typing import Iterator, List, Optional, Tuple

from .models import (
    AUTH_FAILURE,
    CRON_COMMAND,
    GROUP_MODIFY,
    OTHER,
    PASSWORD_CHANGE,
    SESSION_NEW,
    SSH_ACCEPTED_PASSWORD,
    SSH_ACCEPTED_PUBKEY,
    SSH_DISCONNECT,
    SSH_FAILED_PASSWORD,
    SSH_INVALID_USER,
    SSH_MAX_ATTEMPTS,
    SSH_SESSION_OPEN,
    SUDO_AUTH_FAILURE,
    SUDO_COMMAND,
    SU_SESSION_OPEN,
    USER_ADD,
    USER_MODIFY,
    Event,
)

__all__ = ["AuthLogParser", "make_parser", "parse_lines"]

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_SYSLOG = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d{1,6})\d*)?\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[A-Za-z0-9_.\-/]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)

_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[A-Za-z0-9_.\-/]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)

_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:]+)"

# Ordered: the first pattern that matches wins. More specific shapes come first
# so that a sudo line is never read as a generic syslog entry.
_PATTERNS: List[Tuple[str, re.Pattern]] = [
    (
        SSH_FAILED_PASSWORD,
        re.compile(
            r"Failed (?:password|publickey|keyboard-interactive/pam) for "
            r"(?:(?P<invalid>invalid user) )?(?P<user>\S+) from "
            + _IP + r" port (?P<port>\d+) ssh2"
        ),
    ),
    (
        SSH_ACCEPTED_PASSWORD,
        re.compile(
            r"Accepted (?:password|keyboard-interactive/pam) for (?P<user>\S+) from "
            + _IP + r" port (?P<port>\d+) ssh2"
        ),
    ),
    (
        SSH_ACCEPTED_PUBKEY,
        re.compile(
            r"Accepted publickey for (?P<user>\S+) from "
            + _IP + r" port (?P<port>\d+) ssh2(?::\s*(?P<keytype>.*))?"
        ),
    ),
    (
        SSH_MAX_ATTEMPTS,
        re.compile(
            r"error: maximum authentication attempts exceeded for "
            r"(?:(?P<invalid>invalid user) )?(?P<user>\S+) from "
            + _IP + r" port (?P<port>\d+)"
        ),
    ),
    (
        SSH_INVALID_USER,
        re.compile(
            r"Invalid user (?P<user>\S+) from " + _IP + r" port (?P<port>\d+)"
        ),
    ),
    (
        SSH_DISCONNECT,
        re.compile(
            r"(?:Connection closed by|Disconnected from|Connection reset by|"
            r"Received disconnect from)"
            r"(?: invalid user (?P<user>\S+)| authenticating user (?P<user2>\S+))?"
            r" (?P<ip>\S+) port (?P<port>\d+)"
        ),
    ),
    (
        SSH_SESSION_OPEN,
        re.compile(
            r"pam_unix\(sshd:session\): session opened for user (?P<user>\S+)"
        ),
    ),
    (
        SESSION_NEW,
        re.compile(r"New session (?P<sid>\d+) of user (?P<user>\S+)"),
    ),
    (
        SUDO_AUTH_FAILURE,
        re.compile(
            r"^\s*(?P<user>\S+) : (?P<count>\d+) incorrect password attempts?\s*;"
            r"(?:.*?USER=(?P<target>\S+)\s*;\s*)?(?:COMMAND=(?P<cmd>.*))?"
        ),
    ),
    (
        SUDO_COMMAND,
        re.compile(
            r"^\s*(?P<user>\S+) : TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; "
            r"USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$"
        ),
    ),
    (
        # su reports a failed escalation with its own one-liner. It is counted;
        # the pam line that accompanies it is not, because counting both would
        # double every number this rule reports.
        SUDO_AUTH_FAILURE,
        re.compile(r"FAILED (?:su|sudo) for (?P<target>\S+) by (?P<user>\S+)"),
    ),
    (
        AUTH_FAILURE,
        re.compile(
            r"authentication failure; logname=(?P<logname>\S*) uid=\d+ euid=\d+ "
            r"tty=(?P<tty>\S+) ruser=(?P<ruser>\S*) rhost=(?P<ip>\S*)\s+"
            r"user=(?P<user>\S+)"
        ),
    ),
    (
        SU_SESSION_OPEN,
        re.compile(
            r"session opened for user (?P<target>\S+?)\(uid=\d+\) by (?P<user>\S+?)\(uid=\d+\)"
        ),
    ),
    (
        USER_ADD,
        re.compile(
            r"new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+)"
            r"(?:, home=(?P<home>[^,]*))?(?:, shell=(?P<shell>[^,]*))?"
        ),
    ),
    (
        USER_MODIFY,
        re.compile(
            r"(?:add|remove) '(?P<user>[^']+)' to group '(?P<group>[^']+)'"
        ),
    ),
    (
        GROUP_MODIFY,
        re.compile(
            r"(?:group added to|group changed in|group removed from) "
            r".*?(?:group=(?P<group>\S+))?.*?(?:gid=(?P<gid>\d+))?"
        ),
    ),
    (
        PASSWORD_CHANGE,
        re.compile(r"password changed for (?P<user>\S+)"),
    ),
    (
        USER_MODIFY,
        re.compile(r"^new password for (?P<user>\S+)$|^password for (?P<user2>\S+) changed"),
    ),
    (
        CRON_COMMAND,
        re.compile(r"^\((?P<user>\S+)\) CMD \((?P<cmd>.*)\)$"),
    ),
]

# Which process is allowed to produce which kind. Stops a line from an unrelated
# daemon that happens to match a regex from being reported as SSH activity.
_PROCESS_GUARDS = {
    SSH_FAILED_PASSWORD: ("sshd",),
    SSH_ACCEPTED_PASSWORD: ("sshd",),
    SSH_ACCEPTED_PUBKEY: ("sshd",),
    SSH_MAX_ATTEMPTS: ("sshd",),
    SSH_INVALID_USER: ("sshd",),
    SSH_DISCONNECT: ("sshd",),
    SSH_SESSION_OPEN: ("sshd",),
    SUDO_COMMAND: ("sudo",),
    SUDO_AUTH_FAILURE: ("sudo", "su"),
    # Parsed for context - pam records the source address the tool-specific line
    # omits - but deliberately not counted by the rate rules: the same failed
    # attempt usually produces both lines.
    AUTH_FAILURE: ("sudo", "su", "sshd", "login", "gdm-password"),
    USER_ADD: ("useradd", "adduser"),
    GROUP_MODIFY: ("groupadd", "groupmod", "groupdel"),
    PASSWORD_CHANGE: ("passwd", "chpasswd", "gpasswd", "usermod"),
    CRON_COMMAND: ("CRON", "cron", "crond"),
}


def _guess_year(month: int, previous_month: Optional[int], year: int) -> int:
    """Roll the year forward when the log crosses December into January."""
    if previous_month is not None and month < previous_month:
        return year + 1
    return year


def _parse_iso(text: str) -> Optional[datetime.datetime]:
    cleaned = text.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    # fromisoformat wants a colon in the offset on Python 3.9/3.10.
    if re.search(r"[+-]\d{4}$", cleaned):
        cleaned = cleaned[:-5] + cleaned[-5:-2] + ":" + cleaned[-2:]
    try:
        parsed = datetime.datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    # The offset is dropped rather than kept: events from one host are compared
    # against each other in a sliding window, and mixing aware and naive
    # timestamps raises. The wall clock the host wrote is what an analyst needs
    # to see, so that is what is kept.
    if parsed.tzinfo is not None:
        parsed = parsed.replace(tzinfo=None)
    return parsed


class AuthLogParser:
    """Stateful line-by-line parser.

    State exists for one reason: the year. Everything else is a pure function of
    the line.
    """

    def __init__(self, year: Optional[int] = None) -> None:
        self.year = year if year is not None else datetime.date.today().year
        self._last_month: Optional[int] = None

    def parse_line(self, line: str, line_no: int = 0) -> Optional[Event]:
        text = line.rstrip("\r\n")
        if not text.strip():
            return None

        head = _ISO.match(text)
        if head:
            event = self._event_from_head(text, line_no, head)
            if event is not None:
                event.ts = _parse_iso(head.group("ts"))
            return event

        head = _SYSLOG.match(text)
        if head:
            month = _MONTHS.get(head.group("month"))
            if month is None:
                return None
            event = self._event_from_head(text, line_no, head)
            if event is None:
                return None
            self.year = _guess_year(month, self._last_month, self.year)
            self._last_month = month
            event.ts = self._build_ts(head, month)
            return event

        # A line with no recognisable header still gets inspected: plenty of
        # appliances ship the message body alone, and dropping it silently is
        # how a brute force goes unnoticed.
        return self._event_from_message(text, line_no, ts=None, host="", process="", pid=None)

    def _build_ts(self, head: "re.Match", month: int) -> Optional[datetime.datetime]:
        try:
            hour, minute, second = (int(p) for p in head.group("time").split(":"))
            day = int(head.group("day"))
            frac = head.group("frac") or ""
            micro = int(frac.ljust(6, "0")) if frac else 0
            return datetime.datetime(
                self.year, month, day, hour, minute, second, micro
            )
        except (ValueError, TypeError):
            return None

    def _event_from_head(
        self, raw: str, line_no: int, head: "re.Match"
    ) -> Optional[Event]:
        pid_text = head.group("pid")
        return self._event_from_message(
            raw,
            line_no,
            ts=None,
            host=head.group("host"),
            process=head.group("proc"),
            pid=int(pid_text) if pid_text else None,
            message=head.group("msg"),
        )

    def _event_from_message(
        self,
        raw: str,
        line_no: int,
        ts: Optional[datetime.datetime],
        host: str,
        process: str,
        pid: Optional[int],
        message: Optional[str] = None,
    ) -> Optional[Event]:
        msg = raw if message is None else message
        event = Event(
            raw=raw,
            line_no=line_no,
            ts=ts,
            host=host,
            process=process,
            pid=pid,
            message=msg,
        )
        if not msg:
            return event

        for kind, pattern in _PATTERNS:
            guard = _PROCESS_GUARDS.get(kind)
            if guard and process and process not in guard:
                continue
            match = pattern.search(msg)
            if not match:
                continue
            self._apply(event, kind, match)
            return event
        return event

    @staticmethod
    def _apply(event: Event, kind: str, match: "re.Match") -> None:
        groups = match.groupdict()
        event.kind = kind

        if kind in (SSH_FAILED_PASSWORD, SSH_ACCEPTED_PASSWORD, SSH_ACCEPTED_PUBKEY):
            event.user = groups.get("user") or ""
            event.source_ip = groups.get("ip") or ""
            event.source_port = _int_or_none(groups.get("port"))
            event.auth_method = {
                SSH_FAILED_PASSWORD: "password",
                SSH_ACCEPTED_PASSWORD: "password",
                SSH_ACCEPTED_PUBKEY: "publickey",
            }[kind]
            event.invalid_user = bool(groups.get("invalid"))
            if kind == SSH_ACCEPTED_PUBKEY:
                event.command = groups.get("keytype") or ""
        elif kind in (SSH_MAX_ATTEMPTS, SSH_INVALID_USER, SSH_DISCONNECT):
            event.user = groups.get("user") or groups.get("user2") or ""
            event.source_ip = groups.get("ip") or ""
            event.source_port = _int_or_none(groups.get("port"))
            event.invalid_user = bool(groups.get("invalid")) or kind == SSH_INVALID_USER
        elif kind == SSH_SESSION_OPEN:
            event.target = groups.get("user") or event.user
            event.user = ""
        elif kind == SESSION_NEW:
            # logind closes the sentence with a full stop: "New session 3 of user bob."
            event.user = (groups.get("user") or "").rstrip(".")
        elif kind == SUDO_COMMAND:
            event.user = groups.get("user") or ""
            event.target = groups.get("target") or "root"
            event.command = (groups.get("cmd") or "").strip()
            event.tty = groups.get("tty") or ""
        elif kind == SUDO_AUTH_FAILURE:
            event.user = groups.get("user") or groups.get("logname") or ""
            event.target = groups.get("target") or ""
            event.command = (groups.get("cmd") or "").strip()
            event.tty = groups.get("tty") or ""
            event.source_ip = groups.get("ip") or ""
            event.source_port = None
            event.command = event.command or (groups.get("count") or "")
        elif kind == AUTH_FAILURE:
            event.user = groups.get("user") or ""
            event.source_ip = groups.get("ip") or ""
            event.tty = groups.get("tty") or ""
            event.target = groups.get("ruser") or ""
        elif kind == SU_SESSION_OPEN:
            event.target = groups.get("target") or ""
            event.user = groups.get("user") or ""
        elif kind == USER_ADD:
            event.user = (groups.get("user") or "").strip()
            event.target = event.user
            event.command = "uid={} gid={} home={} shell={}".format(
                groups.get("uid") or "?",
                groups.get("gid") or "?",
                groups.get("home") or "?",
                groups.get("shell") or "?",
            )
        elif kind == PASSWORD_CHANGE:
            event.user = groups.get("user") or groups.get("user2") or ""
        elif kind == USER_MODIFY:
            event.user = groups.get("user") or groups.get("user2") or ""
            if groups.get("group"):
                event.target = groups["group"]
        elif kind == GROUP_MODIFY:
            event.user = groups.get("group") or ""
        elif kind == CRON_COMMAND:
            event.user = groups.get("user") or ""
            event.command = (groups.get("cmd") or "").strip()


def _int_or_none(value: Optional[str]) -> Optional[int]:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def make_parser(year: Optional[int] = None) -> AuthLogParser:
    return AuthLogParser(year=year)


def parse_lines(lines: Iterator[str], year: Optional[int] = None) -> List[Event]:
    """Convenience wrapper for tests and one-off analysis."""
    parser = AuthLogParser(year=year)
    events = []
    for index, line in enumerate(lines, start=1):
        event = parser.parse_line(line, line_no=index)
        if event is not None:
            events.append(event)
    return events
