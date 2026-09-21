"""Helpers shared by the tests: real log lines with controllable timestamps.

Nothing here is a mock. Every line is a string an sshd, sudo or useradd on a
Debian host would actually write, and it goes through the real parser before a
rule ever sees it. If a rule passes here, it passes on the host.
"""

import datetime
from typing import Iterable, List, Optional, Sequence

from logtriage.models import Event, Finding
from logtriage.parser import AuthLogParser
from logtriage.rules import Rule

YEAR = 2026
BASE_SECONDS = 18 * 3600  # 18:00:00, comfortably inside working hours


def clock(offset_seconds: int = 0) -> str:
    moment = datetime.datetime(2026, 1, 1) + datetime.timedelta(
        seconds=BASE_SECONDS + offset_seconds
    )
    # The date is fixed at Sep 21 by every builder below; only the time moves.
    return moment.strftime("%H:%M:%S")


def line(message: str, offset_seconds: int = 0, host: str = "web01", process: str = "sshd",
         pid: int = 12345, month: str = "Sep", day: int = 21) -> str:
    return "{} {:2d} {} {} {}[{}]: {}".format(
        month, day, clock(offset_seconds), host, process, pid, message
    )


def parse_log(text: str, year: int = YEAR) -> List[Event]:
    parser = AuthLogParser(year=year)
    events = []
    for number, raw in enumerate(text.splitlines(), start=1):
        event = parser.parse_line(raw, line_no=number)
        if event is not None:
            events.append(event)
    return events


def parse_one(text: str, year: int = YEAR) -> Event:
    events = parse_log(text, year=year)
    assert len(events) == 1, "expected exactly one event, got {}".format(len(events))
    return events[0]


def feed(rule: Rule, lines: Sequence[str], year: int = YEAR) -> List[Finding]:
    for event in parse_log("\n".join(lines), year=year):
        rule.feed(event)
    rule.finish()
    return rule.findings()


# --- line builders -------------------------------------------------------

def ssh_failed(count: int, ip: str = "203.0.113.7", user: str = "deploy",
               step: int = 20, start: int = 0, invalid: bool = False) -> List[str]:
    prefix = "invalid user " if invalid else ""
    return [
        line(
            "Failed password for {}{} from {} port {} ssh2".format(
                prefix, user, ip, 40000 + index
            ),
            offset_seconds=start + index * step,
        )
        for index in range(count)
    ]


def ssh_failed_variants(count: int, ip: str = "203.0.113.7", step: int = 20,
                        start: int = 0) -> List[str]:
    users = ["deploy", "admin", "backup", "git", "monitoring", "svc-ci",
             "oracle", "postgres", "www-data", "ubuntu"]
    return [
        line(
            "Failed password for {} from {} port {} ssh2".format(
                users[index % len(users)], ip, 41000 + index
            ),
            offset_seconds=start + index * step,
        )
        for index in range(count)
    ]


def ssh_failed_from_ips(count: int, user: str = "deploy", step: int = 30,
                        start: int = 0) -> List[str]:
    return [
        line(
            "Failed password for {} from 198.51.100.{} port {} ssh2".format(
                user, index + 1, 42000 + index
            ),
            offset_seconds=start + index * step,
        )
        for index in range(count)
    ]


def ssh_invalid_users(count: int, ip: str = "203.0.113.7", step: int = 15,
                      start: int = 0) -> List[str]:
    names = ["root", "test", "oracle", "postgres", "jenkins", "ftp", "guest"]
    lines = []
    for index in range(count):
        name = names[index % len(names)]
        lines.append(line(
            "Invalid user {} from {} port {} ".format(name, ip, 43000 + index),
            offset_seconds=start + index * step,
        ))
    return lines


def ssh_accepted(user: str = "deploy", ip: str = "203.0.113.7", offset: int = 0,
                 method: str = "password") -> str:
    if method == "publickey":
        return line(
            "Accepted publickey for {} from {} port 44000 ssh2: RSA "
            "SHA256:abcdefghijklmnopqrstuvwxyz0123456789".format(user, ip),
            offset_seconds=offset,
        )
    return line(
        "Accepted password for {} from {} port 44000 ssh2".format(user, ip),
        offset_seconds=offset,
    )


def sudo_command(user: str = "deploy", command: str = "/usr/bin/apt-get update",
                 target: str = "root", offset: int = 0) -> str:
    return line(
        "  {} : TTY=pts/0 ; PWD=/home/{} ; USER={} ; COMMAND={}".format(
            user, user, target, command
        ),
        offset_seconds=offset,
        process="sudo",
        pid=9911,
    )


def sudo_failure(user: str = "deploy", attempts: int = 1, command: str = "/bin/bash",
                 offset: int = 0) -> str:
    return line(
        "  {} : {} incorrect password attempt ; TTY=pts/0 ; PWD=/home/{} ; USER=root ; "
        "COMMAND={}".format(user, attempts, user, command),
        offset_seconds=offset,
        process="sudo",
        pid=9912,
    )


def su_to_root(user: str = "deploy", offset: int = 0) -> str:
    return line(
        "pam_unix(su:session): session opened for user root(uid=0) by {}(uid=1000)".format(user),
        offset_seconds=offset,
        process="su",
        pid=2050,
    )


def user_created(user: str = "mallory", offset: int = 0) -> str:
    return line(
        "new user: name={}, UID=1002, GID=1002, home=/home/{}, shell=/bin/bash, "
        "from=/dev/pts/0".format(user, user),
        offset_seconds=offset,
        process="useradd",
        pid=3311,
    )


def group_membership(user: str = "mallory", group: str = "sudo", offset: int = 0) -> str:
    return line(
        "add '{}' to group '{}'".format(user, group),
        offset_seconds=offset,
        process="usermod",
        pid=3320,
    )


def password_changed(user: str = "mallory", offset: int = 0) -> str:
    return line(
        "pam_unix(passwd:chauthtok): password changed for {}".format(user),
        offset_seconds=offset,
        process="passwd",
        pid=3399,
    )


def cron_command(user: str = "root", command: str = "/usr/local/bin/backup.sh",
                 offset: int = 0) -> str:
    return line(
        "({}) CMD ({})".format(user, command),
        offset_seconds=offset,
        process="CRON",
        pid=4400,
    )
