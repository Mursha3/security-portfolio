# Security portfolio

[![CI](https://github.com/Mursha3/security-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/Mursha3/security-portfolio/actions/workflows/ci.yml)

Practical security work, built and tested in the open. Everything here is
read-only or runs against infrastructure I own — no scanning of systems I am not
authorised to touch.

## Projects

### [webaudit](tools/webaudit) — passive web security posture auditor

Python, zero runtime dependencies, 38 checks, 76 tests, CI on GitHub Actions.

Takes a hostname, walks the redirect chain, captures TLS and certificate
metadata, then analyses security headers, cookie flags, page content and policy
artefacts (`security.txt`, `robots.txt`, `OPTIONS`). Findings carry a stable id,
a severity, the evidence they fired on and a concrete remediation, and roll up
into a 0–100 score so runs are comparable between deploys.

```
webaudit example.com --json out.json --md report.md --fail-on medium
```

Design notes worth a read: [`checks.py`](tools/webaudit/webaudit/checks.py) holds
every security decision as a pure function with no I/O, which is why the whole
detection surface is testable with hand-built data; the network lives entirely in
[`fetch.py`](tools/webaudit/webaudit/fetch.py). When a certificate fails
validation the auditor retries unverified so the report can still describe the
certificate *and* explain why validation failed.

See the [tool README](tools/webaudit/README.md) for the check catalogue and
build instructions.

## Writeups

Vulnerability disclosures and lab walkthroughs live in [`writeups/`](writeups).
Template: [`writeups/TEMPLATE.md`](writeups/TEMPLATE.md) — reproduction steps,
root cause, impact, fix, and a dated disclosure timeline.

## How this repository grows

The next steps are deliberate: more checks in `webaudit`, a baseline diff mode so
runs can be compared between deploys, writeups in `writeups/` as disclosures are
coordinated, and a detection lab wired up so the same lab can be shown from both
sides — how it breaks and how it gets caught.

## Ground rules I hold myself to

- Test only systems I own or have explicit written permission to assess.
- Report through coordinated disclosure, give vendors a reasonable window, and
  never publish before a fix is available or the window has expired.
- No data exfiltration, no persistence, no denial of service — proof of impact
  stops at the demonstration.

## Contact

Open an issue on this repository.
