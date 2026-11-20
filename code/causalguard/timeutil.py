"""Times are kept as whole milliseconds, so comparisons with windows and gaps are exact."""
from __future__ import annotations

from datetime import datetime, timedelta

_EPOCH = datetime(1970, 1, 1)
_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S")


def parse_ms(value) -> int:
    """'2000-01-01 09:41:05.200' (or a datetime) -> milliseconds since 1970-01-01, no time zone."""
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        for fmt in _FORMATS:
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            raise ValueError(f"Cannot read the time {value!r}; expected YYYY-MM-DD HH:MM:SS[.fff]")
    delta = dt - _EPOCH
    return delta.days * 86_400_000 + delta.seconds * 1000 + delta.microseconds // 1000


def fmt_ms(ms: int) -> str:
    dt = _EPOCH + timedelta(milliseconds=int(ms))
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def clock(ms: int) -> str:
    """Short form for reports: 09:41:05 or 09:39:50.2"""
    dt = _EPOCH + timedelta(milliseconds=int(ms))
    milli = dt.microsecond // 1000
    base = dt.strftime("%H:%M:%S")
    return base if milli == 0 else f"{base}.{milli:03d}".rstrip("0")


def seconds(ms: int) -> float | int:
    """Milliseconds -> seconds; a whole number stays an int so CSV files read cleanly."""
    return ms // 1000 if ms % 1000 == 0 else ms / 1000
