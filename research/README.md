# Research log

How I look for vulnerabilities in open source, in the open. The log records the
method and the candidates; a finding is published only in `writeups/`, and only
after the vendor has been notified and the disclosure window has run.

## Why these targets

Parser and extractor code that consumes **hostile input by design** is the best
first target. Two reasons:

1. The threat model is explicit. A file-extraction path traversal in a tool built
   to process untrusted archives is a real vulnerability, not a "hardening
   suggestion" — the maintainer has already decided that malicious input is in
   scope.
2. Impact is easy to demonstrate and easy to explain. "An archive in my sandbox
   wrote outside the sandbox" needs no threat-model debate.

What I avoid for a first report: crashes without impact, denial of service on a
component whose whole job is to process untrusted data, and anything already
labelled in the issue tracker.

## Method

1. **Pick a class, not a target.** One class per pass — path traversal in
   extraction, unsafe deserialization, argument injection in process spawning,
   SSRF in URL fetchers. One class at a time is what makes a pass finishable.
2. **Find the sinks.** Search code for the calls that matter for that class,
   then filter by reachability: does the value come from an untrusted input, or
   from a hardcoded path?
3. **Find the sanitiser.** If input is validated, read the validator, not the
   call site. Broken validation is where the real findings live: a `..` filter
   that runs before URL decoding, an absolute-path check that forgets Windows
   drive letters, a symlink check that follows links before checking them.
4. **Check the tracker before spending time.** Duplicates cost a maintainer's
   attention, which is the scarcest resource in open source.
5. **Prove it.** A minimal reproduction that runs on a clean checkout, with the
   exact output, before anything is written up. No proof means no report.
6. **Report through the project's channel**, in the shape of
   [`writeups/TEMPLATE.md`](../writeups/TEMPLATE.md): reproduction, root cause,
   impact, fix.
7. **Give a window, then publish.** 90 days is the default; the vendor's own
   policy wins if they publish one.

## Candidate log

A project is named here only after its report has been sent and the disclosure
window has closed. Naming an unfixed target would disclose the vulnerability
faster than the maintainer can fix it, which is the opposite of the point.

| Target | Class under review | Reachability | Status |
| --- | --- | --- | --- |
| Archive-extraction code in a Python distribution-analysis tool | tar member names that escape the extraction directory | the tool unpacks a distribution it was pointed at; the names come from the archive | report drafted, not yet sent |
| An archive-library candidate | link handling during extraction | parses user-supplied archives | not yet examined |
| A firmware-extraction candidate | path traversal during extraction | hostile input by design | checkout blocked locally by fixture filenames; revisit |

Once a report is sent, the status changes to "reported" with the date, and the
writeup lands in [`writeups/`](../writeups) when the window closes.

## Rules I keep

- Only public source, read locally. No traffic against anyone's service, no
  scanning, no authenticated testing.
- Report before publishing, always.
- No proof-of-concept beyond what demonstrates the finding: no payload that
  destroys data, no persistence, no lateral movement.
- If a maintainer asks me to hold publication, I hold it and say so.
