# logtriage

Reads authentication logs and reports the handful of events worth a human's
attention: brute force, password spraying, a successful login after failures,
privilege escalation through `sudo`/`su`, account creation and persistence.

Python, **zero runtime dependencies**, 16 detection rules, 130 tests, CI on
GitHub Actions. Read-only: it parses files you hand it and never touches the host
it reads them from.

```
$ logtriage /var/log/auth.log --fail-on high
logtriage - authentication log triage
inputs: 1 file(s), 56 event(s) parsed
         /var/log/auth.log
window 10m  |  failed-logins threshold 5  |  spray 5 users  |  sudo failures 3  |  quiet hours 22:00-06:00

CRITICAL (1)
  ssh-failed-then-accepted  -  source 45.155.205.9
    'deploy' authenticated from 45.155.205.9 over password after 38 failed attempt(s) in the same window (38 in total)
    38 in window, 38 in total, 2026-09-21 18:06:20 -> 2026-09-21 18:06:20
    accounts: deploy, admin, backup, git
    MITRE: T1078 (Valid Accounts), following T1110 (Brute Force)
    evidence:
      | Sep 21 18:02:00 web01 sshd[12345]: Failed password for deploy from 45.155.205.9 port 41000 ssh2
      ...
    fix: Treat the session as compromised until proven otherwise: rotate the
         account's credentials and keys, review what the session did, and check
         whether it installed persistence.
...
score 0/100  grade F  (12 finding(s) across 9 rule(s))  |  1 critical  8 high  2 medium  1 info
```

## Install and run

No dependencies, so there is nothing to install:

```bash
python -m logtriage.cli /var/log/auth.log
python -m logtriage.cli auth.log auth.log.1 --window 30m --md report.md
zgrep sshd /var/log/auth.log.*.gz | python -m logtriage.cli - --fail-on medium
python -m logtriage.cli --list-rules
```

Or install the console script:

```bash
pip install -e ".[dev]"     # pytest included
logtriage /var/log/auth.log
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | ran, nothing at or above `--fail-on` |
| `2` | ran, findings at or above `--fail-on` (`--fail-on none` disables) |
| `3` | could not read the input, or a bad flag value |

`3` exists so a pipeline can tell "clean host" apart from "the tool never ran" —
without it, a typo in a path looks exactly like a quiet night.

### Flags worth knowing

| Flag | Default | What it does |
| --- | --- | --- |
| `--window` | `10m` | sliding window for every rate rule (`30s`, `10m`, `2h`, `1d`) |
| `--fail-threshold` | `5` | failed SSH logins from one address that count as brute force |
| `--spray-users` | `5` | distinct accounts one address may try |
| `--distributed-sources` | `5` | distinct addresses attacking one account |
| `--sudo-fail-threshold` | `3` | failed `sudo`/`su` authentications |
| `--off-hours` | `22-6` | hours considered outside working time |
| `--min-severity` | `info` | hide findings below this level; the score follows what is shown |
| `--year` | current | year for logs whose timestamps do not carry one |
| `--max-per-rule` | `20` | cap on findings kept per rule, worst first |
| `--json` / `--md` | – | write the full result as JSON or Markdown |

## Detection catalogue

| Rule | Severity | What it looks for | MITRE ATT&CK |
| --- | --- | --- | --- |
| `ssh-failed-then-accepted` | high → critical | a login succeeding from an address that was just guessing passwords | T1078, following T1110 |
| `ssh-bruteforce-single-source` | medium → critical | failed logins per address, escalated by rate | T1110.001 |
| `ssh-password-spray` | high → critical | one address trying many different accounts | T1110.003 |
| `ssh-distributed-bruteforce` | high → critical | one account attacked from many addresses | T1110.003 |
| `ssh-user-enumeration` | medium | non-existent usernames being probed | T1087.001 |
| `ssh-root-login` | high | direct login as `root` over SSH | T1078.003 |
| `sudo-shell-escape` | high | `sudo` used to start a shell or interpreter | T1548.003 |
| `sudo-sensitive-command` | high | root commands touching credentials, SSH keys, sudoers, audit or firewall | T1098, T1562.001 |
| `sudo-payload-fetch` | medium → high | `sudo` downloading content (`\| bash` escalates it) | T1105 |
| `sudo-failed-attempts` | medium → critical | repeated failed `sudo`/`su` authentication | T1548.003 |
| `su-to-root` | medium | a root shell opened through `su` | T1548.003 |
| `account-created` | high | a new local account | T1136.001 |
| `privileged-group-change` | low → high | account added to `sudo`, `wheel`, `adm`, `docker`, `lxd`… | T1098 |
| `password-changed` | medium | local password change | T1098 |
| `suspicious-cron-command` | high | cron job running a shell, interpreter or download | T1053.003 |
| `off-hours-login` | info | interactive login outside working hours (correlation, not a problem by itself) | – |

Thresholds escalate rather than fire once: five failures is a medium, a
threshold's worth followed by a successful login is a critical.

## Output formats

- **console** — grouped by severity, with evidence, remediation and a coverage
  list of the rules that ran but matched nothing.
- **JSON** (`--json`) — everything, including every rule's name, thresholds used
  and per-rule event counts, so a run can be diffed or fed to a SIEM.
- **Markdown** (`--md`) — a report with a summary table, per-finding sections and
  a rule coverage table, ready to attach to an incident ticket.

## Design

The same split as [webaudit](../webaudit), for the same reason:

| Module | Responsibility |
| --- | --- |
| `parser.py` | text → `Event`; the only module that knows about log formats |
| `rules.py` | every detection decision, as a state machine with no I/O |
| `engine.py` | runs the rules, aggregates, caps; builds a `Report` |
| `report.py` | renders a `Report` as console, JSON or Markdown |
| `cli.py` | the only module that touches files, arguments or exit codes |

Because rules take events and return findings, the entire detection surface is
tested by handing it six lines of text — no daemon, no filesystem, no clock. The
130 tests are mostly hand-written log lines from real Debian/Ubuntu hosts, plus a
suite that runs the CLI end to end and checks exit codes.

Four details that are deliberate, and that a reviewer will ask about:

- **Findings aggregate.** One finding per rule per source, updated as evidence
  arrives. A 12,000-attempt brute force produces one finding with a rate, a
  total, a timeline and five sample lines — not 12,000 findings nobody reads. The
  per-rule cap keeps a scan of 2,000 addresses from burying the one critical hit.
- **`count` and `total` are different numbers.** `count` is the rate inside the
  window, `total` is everything seen for that source. A slow, quiet grind and a
  loud burst are different problems and need to read differently.
- **Quiet rules are reported.** The console ends with the rules that ran and
  matched nothing, and how many events each considered. A report that only lists
  hits cannot be told apart from a report where a check crashed.
- **The rate rules count tool-specific lines only.** Debian logs a failed `sudo`
  both as a `pam_unix` failure and as a "N incorrect password attempt" line, and
  a failed SSH login both as `Failed password` and as a `pam_unix` failure.
  Counting both would silently halve every threshold, so `pam_unix` lines are
  parsed for context and deliberately excluded from the rates.

## Gotchas that are handled

- **`auth.log` has no year.** A parser that assumes "this year" sorts last
  December as if it were this month. `logtriage` takes a year and rolls it
  forward on its own when the month goes backwards.
- **Rotation.** `--md` plus `auth.log.1.gz` works: `.gz` inputs are read
  directly (`gzip` from the standard library), and line numbers restart per file.
- **Timestamps with an offset.** ISO-8601 lines from rsyslog are accepted; the
  offset is dropped so that comparisons inside a window are consistent, and the
  wall clock the host wrote is what the report shows.
- **A daemon that is not `sshd`.** Lines are matched by message *and* process, so
  a message containing "Failed password" logged by some other program is not
  reported as SSH activity.
- **Lines with no syslog header.** Appliances and `journalctl -o cat` output ship
  the message alone; those lines are still parsed rather than silently dropped.

## Limitations

- It reads text logs. If your host logs only to journald, export first:
  `journalctl -u ssh --since -1d -o short > auth.log`.
- It does not know your environment. A `cron` job that fetches a script from the
  internet is a high finding here and a Tuesday in your infrastructure — the
  finding carries the command so a human can judge.
- No baseline yet. The next step is remembering previous runs and reporting only
  what changed, so a weekly report is readable by a human instead of a diff.
- Correlation lives in the log only: `sudo` lines and `sshd` lines are linked by
  account, not by session id, so a tool that assumes more would be guessing.

## Tests

```bash
cd tools/logtriage
pip install -e ".[dev]"
pytest -q          # 130 tests
```
