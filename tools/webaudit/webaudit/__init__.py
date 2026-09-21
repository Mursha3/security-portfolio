"""webaudit — a passive, zero-dependency web security auditor.

The package is split so that every security decision lives in pure functions:

* :mod:`webaudit.fetch`   — network I/O, transport metadata, TLS details
* :mod:`webaudit.checks`  — pure analysis: raw data in, findings out
* :mod:`webaudit.report`  — console, JSON and Markdown rendering
* :mod:`webaudit.cli`     — argument parsing and wiring

Nothing in ``checks`` touches the network, which is what makes the whole
scoring layer unit-testable without a fixture server.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
