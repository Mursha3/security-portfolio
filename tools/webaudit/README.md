# webaudit

A passive web security posture auditor. One command, a scored report, and no
runtime dependencies — it runs on a bare Python install.

```
$ webaudit example.com

webaudit  https://example.com
  final   : https://example.com  (HTTP 200)
  resolved: 104.20.23.154, 172.66.147.243
  tls     : TLSv1.3 / TLS_AES_256_GCM_SHA384 / expires in 74d
  scanned : 2026-09-21T16:33:42Z

  score 67/100  grade D  (9 finding(s))

  MED (3)
    - Missing HTTP Strict-Transport-Security  [hsts]
      Without HSTS the first request over HTTP is unprotected and an attacker on
      the network can strip the redirect to HTTPS.
      fix      : Send Strict-Transport-Security: max-age=31536000; includeSubDomains
    ...
  PASSED (14)
    + Subresource Integrity on third-party scripts  [sri]
```

## What it checks

38 checks across six areas. Every check has a stable id, a severity, the
evidence it fired on and a concrete remediation.

| Area | Examples |
| --- | --- |
| Transport | HTTPS availability, redirect downgrades, certificate validity, TLS version, key size, expiry |
| Headers | HSTS (including max-age and includeSubDomains), CSP (wildcards, `unsafe-inline`, `object-src`, `base-uri`), framing, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP |
| Cookies | `Secure`, `HttpOnly`, `SameSite`, and the `SameSite=None`-without-`Secure` trap |
| Content | Mixed content, plaintext form actions, inline scripts, Subresource Integrity, `target=_blank`, sensitive HTML comments, generator tags |
| Policy artefacts | `/.well-known/security.txt` completeness, sensitive paths published in `robots.txt` |
| Methods | `TRACE` enabled, write methods advertised over `OPTIONS` |

Findings are weighted (critical 40, high 20, medium 8, low 3, info 0) into a
0–100 score and a letter grade, so a run is comparable between deploys.

## Install

```bash
cd tools/webaudit
python -m pip install -e ".[dev]"   # dev extra pulls in pytest
```

Optional: `pip install -e ".[deep]"` pulls in `cryptography` so the TLS check can
also report public key size. Everything else works without it.

## Usage

```bash
webaudit example.com                       # https:// is assumed
webaudit https://example.com --json out.json --md report.md
webaudit example.com --fail-on medium       # exit 1 for CI gating
webaudit example.com --no-wellknown         # skip security.txt, robots.txt, OPTIONS
webaudit example.com --no-color --timeout 5
```

Exit codes: `0` nothing at or above `--fail-on`, `1` threshold breached,
`2` target unreachable.

Three output formats: colour console for a human, JSON for diffing between
deploys (stable check ids), Markdown for a ticket, a PR or a writeup.

## Design

```
webaudit/
  fetch.py    network I/O: redirect chain, TLS metadata, certificate details
  checks.py   pure analysis - raw data in, findings out (no I/O at all)
  models.py   Finding type plus the scoring and grading model
  report.py   console / JSON / Markdown renderers
  cli.py      argument parsing and wiring
tests/
  test_checks.py   the analysis layer, driven with hand-built data - no socket
  test_fetch.py    integration against a local fixture server on 127.0.0.1
```

The split matters: because no check touches the network, the entire security
decision surface is testable with plain data. The fixture server in
`tests/test_fetch.py` binds to an ephemeral port, so the integration tests never
leave the machine and never depend on a third-party host being up.

A detail worth calling out: when a certificate fails validation, the auditor
retries the request without verification so the report can still describe the
certificate **and** state exactly why validation failed. Failing closed would
hide the finding.

## Safety boundaries

Only read-only traffic: a `GET` for the page, a `GET` of `/.well-known/security.txt`,
a `GET` of `/robots.txt`, and a single `OPTIONS`. No authentication, no payloads,
no form submissions, nothing that mutates remote state.

Point it at hosts you own or are authorised to assess. A tool being passive does
not make unauthorised access authorised.

## Tests

```bash
cd tools/webaudit
python -m pytest -q
```

## License

MIT
