from datetime import UTC, datetime, timedelta

import pytest

from cfms_pki.crl.inference import (
    calculate_retention_boundary,
    parse_duration,
    resolve_cutoff,
    resolve_last_success,
    should_exclude_revocation,
)


class TestParseDuration:
    def test_empty_string(self):
        assert parse_duration("") == timedelta(0)
        assert parse_duration("   ") == timedelta(0)

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("10", timedelta(seconds=10)),
            ("300s", timedelta(seconds=300)),
            ("5m", timedelta(minutes=5)),
            ("10min", timedelta(minutes=10)),
            ("1h", timedelta(hours=1)),
            ("24hours", timedelta(hours=24)),
            ("1d", timedelta(days=1)),
            ("3.5d", timedelta(days=3.5)),
            ("1w", timedelta(weeks=1)),
        ],
    )
    def test_valid_durations(self, raw, expected):
        assert parse_duration(raw) == expected

    def test_invalid_duration_format(self):
        with pytest.raises(ValueError, match="Invalid duration format"):
            parse_duration("invalid")
        with pytest.raises(ValueError, match="Invalid duration format"):
            parse_duration("5xyz")


class TestCalculateRetentionBoundary:
    def test_s_is_none_returns_none(self):
        now = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
        assert calculate_retention_boundary(now=now, last_success=None) is None

    def test_s_greater_than_t_returns_none(self):
        now = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
        future_s = datetime(2026, 11, 5, 0, 0, 0, tzinfo=UTC)
        assert calculate_retention_boundary(now=now, last_success=future_s) is None

    def test_default_h_calculation(self):
        # T = 2026-11-04 12:00, S = 2026-11-01 00:00, C defaults to T, G=0, eps=5m
        now = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
        s = datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)
        h = calculate_retention_boundary(now=now, last_success=s)
        expected = s - timedelta(minutes=5)
        assert h == expected
        assert h == datetime(2026, 10, 31, 23, 55, 0, tzinfo=UTC)

    def test_h_calculation_with_grace_period(self):
        now = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
        s = datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)
        grace = timedelta(days=1)
        tol = timedelta(minutes=10)
        h = calculate_retention_boundary(
            now=now,
            last_success=s,
            grace_period=grace,
            clock_tolerance=tol,
        )
        expected = s - timedelta(days=1) - timedelta(minutes=10)
        assert h == expected

    def test_h_calculation_when_c_is_earliest(self):
        # When user cutoff C is earlier than S - G - eps
        now = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
        s = datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)
        c = datetime(2026, 10, 15, 0, 0, 0, tzinfo=UTC)
        h = calculate_retention_boundary(now=now, last_success=s, cutoff=c)
        assert h == c

    def test_s_equals_t(self):
        now = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
        h = calculate_retention_boundary(now=now, last_success=now)
        assert h == now - timedelta(minutes=5)


class TestShouldExcludeRevocation:
    def test_boundary_is_none(self):
        entry = {"serial": "123", "not_after": "2026-10-01T00:00:00Z"}
        assert not should_exclude_revocation(entry, boundary=None)

    def test_missing_not_after(self):
        boundary = datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)
        entry = {"serial": "123"}
        assert not should_exclude_revocation(entry, boundary=boundary)

    def test_not_after_earlier_than_boundary(self):
        boundary = datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)
        entry = {"serial": "123", "not_after": "2026-10-31T23:59:59Z"}
        assert should_exclude_revocation(entry, boundary=boundary)

    def test_not_after_equal_boundary_retained(self):
        # Strict < boundary rule (E < H): equal to boundary must be retained
        boundary = datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)
        entry = {"serial": "123", "not_after": "2026-11-01T00:00:00Z"}
        assert not should_exclude_revocation(entry, boundary=boundary)

    def test_not_after_later_than_boundary(self):
        boundary = datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)
        entry = {"serial": "123", "not_after": "2026-11-01T00:00:01Z"}
        assert not should_exclude_revocation(entry, boundary=boundary)

    def test_invalid_not_after_format_raises(self):
        boundary = datetime(2026, 11, 1, 0, 0, 0, tzinfo=UTC)
        entry = {"serial": "123", "not_after": "invalid-datetime"}
        with pytest.raises(ValueError, match="Invalid not_after format"):
            should_exclude_revocation(entry, boundary=boundary)


class TestResolveLastSuccessAndCutoff:
    def test_resolve_last_success_values(self):
        assert resolve_last_success(None) is None
        assert resolve_last_success("none") is None
        assert resolve_last_success("null") is None
        assert resolve_last_success("false") is None
        assert resolve_last_success("") is None

        dt = resolve_last_success("2026-11-01T12:00:00Z")
        assert dt == datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)

        with pytest.raises(ValueError, match="Invalid --last-success timestamp"):
            resolve_last_success("invalid-time")

        with pytest.raises(ValueError, match="Invalid --last-success timestamp"):
            resolve_last_success("auto")

    def test_resolve_cutoff_values(self):
        now = datetime(2026, 11, 4, 12, 0, 0, tzinfo=UTC)
        assert resolve_cutoff(None, now) == now
        assert resolve_cutoff("now", now) == now
        assert resolve_cutoff("", now) == now
        assert resolve_cutoff("none", now) is None
        assert resolve_cutoff("null", now) is None

        dt = resolve_cutoff("2026-10-15T00:00:00Z", now)
        assert dt == datetime(2026, 10, 15, 0, 0, 0, tzinfo=UTC)

        with pytest.raises(ValueError, match="Invalid --expired-before timestamp"):
            resolve_cutoff("invalid-time", now)
