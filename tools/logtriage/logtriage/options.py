"""Detection settings, all in one object.

Everything a rule can be tuned by lives here, so an analyst reading a report can
see the thresholds that produced it, and so a test can construct the exact
configuration it wants without touching module globals.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass

__all__ = ["Options", "parse_duration", "format_duration"]

_DURATION = re.compile(r"^(?P<value>\d+)(?P<unit>s|m|h|d)?$", re.IGNORECASE)

_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str) -> datetime.timedelta:
    """``30s``, ``10m``, ``2h``, ``1d``. A bare number means seconds."""
    match = _DURATION.match(text.strip())
    if not match:
        raise ValueError("cannot read duration: {!r} (try 30s, 10m, 2h, 1d)".format(text))
    value = int(match.group("value"))
    unit = (match.group("unit") or "s").lower()
    return datetime.timedelta(seconds=value * _UNIT_SECONDS[unit])


def format_duration(delta: datetime.timedelta) -> str:
    """Round-trip back to the short form, so a report can be read as arguments."""
    seconds = int(delta.total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0 and seconds >= size:
            return "{}{}".format(seconds // size, unit)
    return "{}s".format(seconds)


@dataclass
class Options:
    """Thresholds for the detection rules.

    Defaults are chosen to be noisy-but-not-useless on a small host: five failed
    logins from one address inside ten minutes is already abnormal on a machine
    with password authentication disabled, and it is far below what a real
    dictionary attack produces, so the escalation steps have room to work.
    """

    window: datetime.timedelta = datetime.timedelta(minutes=10)
    fail_threshold: int = 5
    spray_users: int = 5
    enum_users: int = 5
    distributed_sources: int = 5
    sudo_fail_threshold: int = 3
    off_hours_start: int = 22
    off_hours_end: int = 6
    max_evidence: int = 5
    max_per_rule: int = 20
