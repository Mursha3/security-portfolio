"""logtriage - authentication log triage with an auditable rule set.

Reads syslog-style authentication logs and reports the handful of events worth
a human's attention: brute force, spraying, successful logins after failures,
privilege escalation through sudo, account creation and other persistence.

Design mirrors webaudit, deliberately:

* ``parser.py`` turns text into Events and is the only module that knows about
  log formats.
* ``rules.py`` holds every detection decision as a pure state machine with no
  I/O, which is why the detection surface is testable with hand-written lines.
* ``engine.py`` runs rules and builds a report; ``report.py`` only renders it.
* ``cli.py`` is the only place that touches files or arguments.
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
