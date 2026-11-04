"""Column auto-size like POI 4.0.1 ``SheetUtil.getColumnWidth`` with JDK AWT Calibri 11 metrics (spec section 7).

POI lays out ``line + "0"`` with ``TextLayout`` (fractional metrics, no kerning) and takes the right ink edge, i.e. the
linear advances of the line plus the snapped ``xMax`` of the trailing '0', divided by the default char width (5).
Advances come from the installed Calibri fonts through PIL; without them the embedded tables below are used
(ASCII and Latin-1 exact, other characters approximated by the missing-glyph advance).
"""
from __future__ import annotations

import threading

from PIL import ImageFont

CAP = 12000                     # ak: autosized columns wider than 12000/256 chars are set to 12000
_UNITS_PER_EM = 2048
_POINTS = 11
_DEFAULT_CHAR_WIDTH = 5         # (int) advance of '0' in Calibri 11pt
_ZERO_EDGE = {False: 5.1875, True: 5.28125}   # xMax of '0' snapped to 1/64 pt, Calibri / Calibri Bold
_MISSING_GLYPH = 1038

# Characters AWT lays out with zero advance (measured on JDK 25 with Calibri, identical for bold).
_ZERO_WIDTH = (
    (0x0000, 0x0000), (0x0009, 0x0009), (0x000B, 0x000D), (0x0085, 0x0085), (0x00AD, 0x00AD), (0x02DA, 0x02DA),
    (0x02DE, 0x02DE), (0x0300, 0x036F), (0x0483, 0x0487), (0x055F, 0x055F), (0x0591, 0x05BD), (0x05BF, 0x05BF),
    (0x05C1, 0x05C2), (0x05C4, 0x05C5), (0x05C7, 0x05C7), (0x0605, 0x0605), (0x0610, 0x061A), (0x061C, 0x061C),
    (0x064B, 0x065F), (0x0670, 0x0670), (0x06D6, 0x06DC), (0x06DF, 0x06E4), (0x06E7, 0x06E8), (0x06EA, 0x06ED),
    (0x08D4, 0x08E1), (0x08E3, 0x08FF), (0x17B4, 0x17B5), (0x180B, 0x180E), (0x1DC0, 0x1DCA), (0x1DFE, 0x1DFF),
    (0x200B, 0x200F), (0x2028, 0x202D), (0x2060, 0x206F), (0xA66F, 0xA66F), (0xA674, 0xA67D), (0xA69F, 0xA69F),
    (0xFB1E, 0xFB1E), (0xFC5E, 0xFC63), (0xFE00, 0xFE0F), (0xFE20, 0xFE23), (0xFEFF, 0xFEFF), (0xFFF0, 0xFFF8),
)

# Calibri / Calibri Bold advances (font units) for U+0020..U+007E and U+00A0..U+00FF.
_REGULAR_TABLE = (
    [463, 667, 821, 1020, 1038, 1464, 1397, 452, 621, 621, 1020, 1020, 511, 627, 517, 791, 1038, 1038, 1038, 1038,
     1038, 1038, 1038, 1038, 1038, 1038, 548, 548, 1020, 1020, 1020, 949, 1831, 1185, 1114, 1092, 1260, 1000, 941,
     1292, 1276, 516, 653, 1064, 861, 1751, 1322, 1356, 1058, 1378, 1112, 941, 998, 1314, 1162, 1822, 1063, 998, 959,
     628, 791, 628, 1020, 1020, 596, 981, 1076, 866, 1076, 1019, 625, 964, 1076, 470, 490, 931, 470, 1636, 1076, 1080,
     1076, 1076, 714, 801, 686, 1076, 925, 1464, 887, 927, 809, 644, 943, 644, 1020],
    [463, 667, 1020, 1038, 1020, 1038, 1020, 1020, 804, 1709, 824, 1049, 1020, 627, 1038, 807, 694, 1020, 688, 685,
     598, 1126, 1200, 517, 629, 504, 865, 1049, 1303, 1375, 1383, 949, 1185, 1185, 1185, 1185, 1185, 1185, 1563, 1092,
     1000, 1000, 1000, 1000, 516, 516, 516, 516, 1279, 1322, 1356, 1356, 1356, 1356, 1356, 1020, 1359, 1314, 1314,
     1314, 1314, 998, 1058, 1080, 981, 981, 981, 981, 981, 981, 1583, 866, 1019, 1019, 1019, 1019, 470, 470, 470, 470,
     1076, 1076, 1080, 1080, 1080, 1080, 1080, 1020, 1084, 1076, 1076, 1076, 1076, 927, 1076, 927],
)
_BOLD_TABLE = (
    [463, 667, 898, 1020, 1038, 1493, 1443, 478, 638, 638, 1020, 1020, 528, 627, 547, 880, 1038, 1038, 1038, 1038,
     1038, 1038, 1038, 1038, 1038, 1038, 565, 565, 1020, 1020, 1020, 949, 1840, 1241, 1148, 1084, 1291, 999, 940,
     1305, 1292, 546, 678, 1120, 866, 1790, 1349, 1385, 1090, 1405, 1153, 968, 1014, 1337, 1211, 1856, 1128, 1064,
     979, 665, 880, 665, 1020, 1020, 615, 1011, 1099, 857, 1099, 1031, 648, 971, 1099, 503, 523, 983, 503, 1666, 1099,
     1101, 1099, 1099, 728, 817, 710, 1099, 969, 1526, 941, 970, 814, 704, 973, 704, 1020],
    [463, 667, 1020, 1038, 1020, 1038, 1020, 1020, 849, 1709, 852, 1103, 1020, 627, 1038, 799, 701, 1020, 692, 688,
     616, 1154, 1224, 548, 621, 517, 891, 1103, 1347, 1415, 1437, 949, 1241, 1241, 1241, 1241, 1241, 1241, 1588, 1084,
     999, 999, 999, 999, 546, 546, 546, 546, 1309, 1349, 1385, 1385, 1385, 1385, 1385, 1020, 1394, 1337, 1337, 1337,
     1337, 1064, 1090, 1136, 1011, 1011, 1011, 1011, 1011, 1011, 1587, 857, 1031, 1031, 1031, 1031, 503, 503, 503, 503,
     1099, 1099, 1101, 1101, 1101, 1101, 1101, 1020, 1114, 1099, 1099, 1099, 1099, 970, 1099, 970],
)


def _is_zero_width(code: int) -> bool:
    return any(low <= code <= high for low, high in _ZERO_WIDTH)


class _Advances(dict):
    """Lazy per-character advance cache (font units) for one Calibri weight."""

    def __init__(self, font_file: str, table: tuple[list[int], list[int]]):
        super().__init__()
        self._lock = threading.Lock()
        self._table = table
        try:
            self._font = ImageFont.truetype(font_file, _UNITS_PER_EM, layout_engine=ImageFont.Layout.BASIC)
        except OSError:
            self._font = None

    def __missing__(self, char: str) -> float:
        code = ord(char)
        if _is_zero_width(code):
            advance = 0.0
        elif self._font is not None:
            with self._lock:
                advance = self._font.getlength(char)
        elif 0x20 <= code <= 0x7E:
            advance = self._table[0][code - 0x20]
        elif 0xA0 <= code <= 0xFF:
            advance = self._table[1][code - 0xA0]
        else:
            advance = _MISSING_GLYPH
        self[char] = advance
        return advance


_ADVANCES = {False: _Advances("calibri.ttf", _REGULAR_TABLE), True: _Advances("calibrib.ttf", _BOLD_TABLE)}
_CAP_CHARS = CAP / 256
_LIMIT_UNITS = {bold: (_CAP_CHARS * _DEFAULT_CHAR_WIDTH - edge) * _UNITS_PER_EM / _POINTS
                for bold, edge in _ZERO_EDGE.items()}


def java_lines(text: str) -> list[str]:
    """Java ``text.split("\\n")``: trailing empty strings are dropped, but ``""`` gives ``[""]``."""
    lines = text.split("\n")
    if text:
        while lines and not lines[-1]:
            lines.pop()
    return lines


def text_width(text: str, bold: bool = False) -> float:
    """Width of one cell in characters (``-1`` when Java's split yields no line).

    Exact up to the autosize cap; once a line is wider than the cap, measuring stops and a value above the cap is
    returned (every autosized column of the tool is capped, so the result is the same).
    """
    advances = _ADVANCES[bold]
    limit = _LIMIT_UNITS[bold]
    edge = _ZERO_EDGE[bold]
    best = -1.0
    for line in java_lines(text):
        units = 0.0
        for char in line:
            units += advances[char]
            if units > limit:
                break
        best = max(best, (units * _POINTS / _UNITS_PER_EM + edge) / _DEFAULT_CHAR_WIDTH)
        if units > limit:
            break
    return best


def is_capped(width: float) -> bool:
    return width > _CAP_CHARS


def column_width(best: float) -> float | None:
    """POI ``autoSizeColumn`` + the 12000 cap, as the ``<col width>`` value; ``None`` when the column has no cells."""
    if best < 0:
        return None
    width = int(min(best * 256, 255 * 256))
    return min(width, CAP) / 256
