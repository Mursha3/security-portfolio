"""Threshold and duration handling - small surface, but the CLI lives on it."""

import datetime

from logtriage.options import Options, format_duration, parse_duration


def test_bare_number_means_seconds():
    assert parse_duration("45") == datetime.timedelta(seconds=45)


def test_units_are_understood():
    assert parse_duration("30s") == datetime.timedelta(seconds=30)
    assert parse_duration("10m") == datetime.timedelta(minutes=10)
    assert parse_duration("2h") == datetime.timedelta(hours=2)
    assert parse_duration("1d") == datetime.timedelta(days=1)


def test_whitespace_and_case_do_not_matter():
    assert parse_duration(" 15M ") == datetime.timedelta(minutes=15)


def test_nonsense_durations_are_rejected():
    for text in ("", "ten minutes", "-5m", "5m30s", "m"):
        try:
            parse_duration(text)
        except ValueError as error:
            assert "cannot read duration" in str(error)
        else:
            raise AssertionError("expected {!r} to be rejected".format(text))


def test_format_duration_round_trips():
    for text in ("30s", "10m", "2h", "1d"):
        assert format_duration(parse_duration(text)) == text


def test_format_duration_picks_the_largest_whole_unit():
    assert format_duration(datetime.timedelta(minutes=90)) == "90m"
    assert format_duration(datetime.timedelta(seconds=90)) == "90s"


def test_defaults_are_the_documented_ones():
    options = Options()
    assert options.window == datetime.timedelta(minutes=10)
    assert options.fail_threshold == 5
    assert options.spray_users == 5
    assert options.distributed_sources == 5
    assert options.sudo_fail_threshold == 3
    assert (options.off_hours_start, options.off_hours_end) == (22, 6)
    assert options.max_evidence == 5
