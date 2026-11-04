"""Lenient ``SimpleDateFormat("dd-MM-yyyy").parse`` (used by the Expires analyzer)."""
from __future__ import annotations

import re
from datetime import date

# Leading spaces/tabs are skipped before each numeric field; a '-' sign is accepted, '+' is not;
# trailing text is ignored (prefix parse).
_DD_MM_YYYY = re.compile(r"[ \t]*(-?[0-9]+)-[ \t]*(-?[0-9]+)-[ \t]*(-?[0-9]+)")


def _java_int_value(value: int) -> int:
    """``DecimalFormat`` result ``.intValue()``: a Long wraps to 32 bits, a larger Double saturates."""
    if -(1 << 63) <= value < (1 << 63):
        value &= 0xFFFFFFFF
        return value - (1 << 32) if value >= 1 << 31 else value
    return 2147483647 if value > 0 else -2147483648


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Proleptic Gregorian day number (any year, astronomical numbering)."""
    year -= month <= 2
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe


def parse_dd_mm_yyyy(text: str) -> int:
    """Day number of the leniently parsed date; raises ``ValueError`` where Java throws ``ParseException``."""
    match = _DD_MM_YYYY.match(text)
    if match is None:
        raise ValueError(f'Unparseable date: "{text}"')
    day, month, year = (_java_int_value(int(group)) for group in match.groups())
    months = year * 12 + (month - 1)
    return _days_from_civil(months // 12, months % 12 + 1, 1) + (day - 1)


def day_number(value: date) -> int:
    return _days_from_civil(value.year, value.month, value.day)
