"""Retention model and cutoff inference for certificate revocations in CRLs."""

import re
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

DURATION_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]+)?$")

DURATION_UNITS: dict[str, float] = {
    "s": 1.0,
    "sec": 1.0,
    "secs": 1.0,
    "second": 1.0,
    "seconds": 1.0,
    "m": 60.0,
    "min": 60.0,
    "mins": 60.0,
    "minute": 60.0,
    "minutes": 60.0,
    "h": 3600.0,
    "hr": 3600.0,
    "hrs": 3600.0,
    "hour": 3600.0,
    "hours": 3600.0,
    "d": 86400.0,
    "day": 86400.0,
    "days": 86400.0,
    "w": 604800.0,
    "week": 604800.0,
    "weeks": 604800.0,
}


def parse_duration(value: str) -> timedelta:
    """Parse a human-readable duration string into a timedelta.

    Supports formats like '5m', '300s', '1h', '2d', '3.5d', or pure seconds.
    """
    raw = value.strip().lower()
    if not raw:
        return timedelta(0)

    match = DURATION_RE.match(raw)
    if not match:
        raise ValueError(
            f"Invalid duration format '{value}'. Expected format like '5m', '1h', '2d', or seconds."
        )

    number_str, unit = match.groups()
    number = float(number_str)
    if unit:
        if unit not in DURATION_UNITS:
            raise ValueError(
                f"Invalid duration format '{value}'. Unknown unit '{unit}'."
            )
        multiplier = DURATION_UNITS[unit]
    else:
        multiplier = 1.0
    return timedelta(seconds=number * multiplier)


def calculate_retention_boundary(
    now: datetime,
    last_success: datetime | None,
    cutoff: datetime | None = None,
    grace_period: timedelta = timedelta(0),
    clock_tolerance: timedelta = timedelta(minutes=5),
) -> datetime | None:
    """Calculate effective retention boundary H = min(C, T, S - G - epsilon).

    Variables:
      T: Current UTC time (now)
      S: Start time of last successful regular CRL issuing run (last_success)
      C: User-specified cutoff timestamp (cutoff, defaults to T)
      G: Extra grace period (grace_period, defaults to 0)
      epsilon: Clock skew safety margin (clock_tolerance, defaults to 5 minutes)

    Rule:
      Only when S and E both exist and S <= T is a boundary established.
      If S does not exist (None) or S > T, returns None to ensure all records
      are retained per RFC 5280 §3.3.
    """
    if last_success is None:
        return None

    t = now.astimezone(UTC)
    s = last_success.astimezone(UTC)

    if s > t:
        print(
            f"Warning: Last success timestamp S ({s.isoformat()}) is in the future relative to T ({t.isoformat()}). "
            "Safeguard triggered: retaining all revocations.",
            file=sys.stderr,
        )
        return None

    c = cutoff.astimezone(UTC) if cutoff is not None else t
    s_adjusted = s - grace_period - clock_tolerance
    return min(c, t, s_adjusted)


def should_exclude_revocation(
    entry: dict[str, Any],
    boundary: datetime | None,
) -> bool:
    """Determine whether a revocation entry should be excluded from CRL.

    Rule: Exclude = (E < H), provided S and E exist and S <= T.
    When boundary H is None, returns False (record is retained).
    When entry has no 'not_after' (E is None), returns False (record is retained).
    """
    if boundary is None:
        return False

    not_after_str = entry.get("not_after")
    if not not_after_str:
        return False

    try:
        e = datetime.fromisoformat(not_after_str).astimezone(UTC)
    except ValueError as exc:
        raise ValueError(
            f"Invalid not_after format '{not_after_str}' in revocation entry: {exc}"
        ) from exc

    return e < boundary


def resolve_last_success(
    last_success_arg: str | None,
) -> datetime | None:
    """Resolve the S parameter from CLI argument (exact ISO 8601 timestamp)."""
    if last_success_arg is None:
        return None

    val = last_success_arg.strip()
    if val.lower() in ("none", "null", "false", ""):
        return None

    try:
        return datetime.fromisoformat(last_success_arg).astimezone(UTC)
    except ValueError as exc:
        raise ValueError(
            f"Invalid --last-success timestamp '{last_success_arg}'. Expected ISO 8601 format."
        ) from exc


def resolve_cutoff(
    cutoff_arg: str | None,
    now: datetime,
) -> datetime | None:
    """Resolve the C parameter (user-specified cutoff). Defaults to T (now)."""
    if cutoff_arg is None:
        return now

    val = cutoff_arg.strip().lower()
    if val in ("now", ""):
        return now
    if val in ("none", "null", "false"):
        return None

    try:
        return datetime.fromisoformat(cutoff_arg).astimezone(UTC)
    except ValueError as exc:
        raise ValueError(
            f"Invalid --expired-before timestamp '{cutoff_arg}'. Expected ISO 8601 or 'now'/'none'."
        ) from exc
