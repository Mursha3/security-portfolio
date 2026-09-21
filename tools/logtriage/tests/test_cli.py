"""CLI tests: exit codes, report files and the flags a pipeline depends on."""

import gzip
import io
import json
import sys

from _util import ssh_accepted, ssh_failed, sudo_command, user_created

from logtriage.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main

BENIGN_LOG = "\n".join([ssh_accepted(user="deploy", offset=0)]) + "\n"

INCIDENT_LOG = "\n".join(
    ssh_failed(6, ip="203.0.113.7", user="deploy")
    + [ssh_accepted(user="deploy", ip="203.0.113.7", offset=200)]
    + [sudo_command("deploy", "/bin/bash", offset=260)]
    + [user_created("mallory", offset=300)]
) + "\n"


def write_log(tmp_path, text, name="auth.log"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_benign_log_exits_zero(tmp_path, capsys):
    code = main([write_log(tmp_path, BENIGN_LOG), "--no-color"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "No findings." in out
    assert "score 100/100" in out


def test_incident_log_exits_two(tmp_path, capsys):
    code = main([write_log(tmp_path, INCIDENT_LOG), "--no-color"])
    out = capsys.readouterr().out
    assert code == EXIT_FINDINGS
    assert "CRITICAL" in out or "HIGH" in out
    assert "ssh-failed-then-accepted" in out


def test_fail_on_none_never_fails_the_run(tmp_path, capsys):
    code = main([write_log(tmp_path, INCIDENT_LOG), "--no-color", "--fail-on", "none"])
    capsys.readouterr()
    assert code == EXIT_OK


def test_fail_on_critical_ignores_medium_findings(tmp_path, capsys):
    log = write_log(tmp_path, "\n".join(ssh_failed(6)) + "\n")
    code = main([log, "--no-color", "--fail-on", "critical"])
    capsys.readouterr()
    assert code == EXIT_OK


def test_min_severity_hides_findings_and_says_so(tmp_path, capsys):
    log = write_log(tmp_path, "\n".join(ssh_failed(6)) + "\n")
    code = main([log, "--no-color", "--min-severity", "critical"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "hidden by --min-severity" in out


def test_json_output_is_written_and_parsable(tmp_path, capsys):
    target = tmp_path / "out.json"
    code = main([write_log(tmp_path, INCIDENT_LOG), "--no-color", "--json", str(target)])
    capsys.readouterr()
    data = json.loads(target.read_text(encoding="utf-8"))
    assert code == EXIT_FINDINGS
    assert data["tool"] == "logtriage"
    assert data["findings_count"] == len(data["findings"])
    assert data["score"] < 100
    assert data["rules"]


def test_markdown_report_has_the_rule_coverage_table(tmp_path, capsys):
    target = tmp_path / "report.md"
    main([write_log(tmp_path, INCIDENT_LOG), "--no-color", "--md", str(target)])
    text = target.read_text(encoding="utf-8")
    capsys.readouterr()
    assert "## Rule coverage" in text
    assert "| Severity | Rule | Source |" in text
    assert "Remediation" in text


def test_thresholds_are_configurable_from_the_command_line(tmp_path, capsys):
    log = write_log(tmp_path, "\n".join(ssh_failed(3)) + "\n")
    quiet = main([log, "--no-color", "--fail-threshold", "10"])
    capsys.readouterr()
    loud = main([log, "--no-color", "--fail-threshold", "3"])
    out = capsys.readouterr().out
    assert quiet == EXIT_OK
    assert loud == EXIT_OK
    assert "ssh-bruteforce-single-source" in out


def test_bad_duration_is_a_usage_error(tmp_path, capsys):
    code = main([write_log(tmp_path, BENIGN_LOG), "--window", "ten minutes"])
    captured = capsys.readouterr()
    assert code == EXIT_USAGE
    assert "cannot read duration" in captured.err


def test_bad_off_hours_range_is_a_usage_error(tmp_path, capsys):
    code = main([write_log(tmp_path, BENIGN_LOG), "--off-hours", "22"])
    captured = capsys.readouterr()
    assert code == EXIT_USAGE
    assert "expected START-END" in captured.err


def test_out_of_range_off_hours_is_a_usage_error(tmp_path, capsys):
    code = main([write_log(tmp_path, BENIGN_LOG), "--off-hours", "25-6"])
    captured = capsys.readouterr()
    assert code == EXIT_USAGE
    assert "between 0 and 23" in captured.err


def test_missing_file_is_a_usage_error(tmp_path, capsys):
    code = main([str(tmp_path / "nope.log"), "--no-color"])
    captured = capsys.readouterr()
    assert code == EXIT_USAGE
    assert "cannot read input" in captured.err


def test_no_arguments_is_a_usage_error(capsys):
    try:
        main([])
    except SystemExit as exit_code:
        assert exit_code.code != 0
    else:
        raise AssertionError("expected a usage error")
    capsys.readouterr()


def test_list_rules_prints_the_catalogue(capsys):
    code = main(["--list-rules"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "Detection catalogue" in out
    assert "ssh-bruteforce-single-source" in out
    assert "T1110" in out


def test_version_flag_exits_cleanly(capsys):
    try:
        main(["--version"])
    except SystemExit as exit_code:
        assert exit_code.code == 0
    else:
        raise AssertionError("--version should exit")
    assert "logtriage" in capsys.readouterr().out


def test_gzipped_logs_are_read_directly(tmp_path, capsys):
    path = tmp_path / "auth.log.1.gz"
    with gzip.open(str(path), "wt", encoding="utf-8") as handle:
        handle.write(INCIDENT_LOG)
    code = main([str(path), "--no-color"])
    out = capsys.readouterr().out
    assert code == EXIT_FINDINGS
    assert "auth.log.1.gz" in out


def test_stdin_dash_reads_a_pipe(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(INCIDENT_LOG))
    code = main(["-", "--no-color"])
    out = capsys.readouterr().out
    assert code == EXIT_FINDINGS
    assert "findings" in out or "CRITICAL" in out


def test_two_files_are_combined(tmp_path, capsys):
    first = write_log(tmp_path, "\n".join(ssh_failed(3)) + "\n", "a.log")
    second = write_log(tmp_path, "\n".join(ssh_failed(3, start=100)) + "\n", "b.log")
    code = main([first, second, "--no-color"])
    out = capsys.readouterr().out
    # Six failures spread over two rotated files are one attack, and one burst.
    assert code == EXIT_OK
    assert "2 file(s)" in out
    assert "a.log" in out and "b.log" in out
    assert "6 failed SSH logins" in out


def test_year_flag_is_applied_to_timestamps(tmp_path, capsys):
    log = write_log(tmp_path, "\n".join(ssh_failed(6)) + "\n")
    main([log, "--no-color", "--year", "2024"])
    out = capsys.readouterr().out
    assert "2024-09-21" in out


def test_window_flag_changes_what_counts_as_a_burst(tmp_path, capsys):
    # Ten attempts, one a minute: a burst to a one-hour window, background noise
    # to a two-minute one. This is the difference between a tool that reports and
    # a tool that pages somebody at three in the morning.
    log = write_log(tmp_path, "\n".join(ssh_failed(10, step=60)) + "\n")
    wide = main([log, "--no-color", "--window", "1h"])
    wide_out = capsys.readouterr().out
    narrow = main([log, "--no-color", "--window", "2m"])
    narrow_out = capsys.readouterr().out
    assert "failed SSH logins from" in wide_out
    assert "failed SSH logins from" not in narrow_out
    assert wide == EXIT_OK
    assert narrow == EXIT_OK
