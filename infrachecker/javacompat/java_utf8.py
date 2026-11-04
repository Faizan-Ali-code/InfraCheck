"""Java-compatible UTF-8 decoding (sun.nio.cs.UTF_8 with CodingErrorAction.REPLACE),
plus the BufferedReader.lines() + join("") newline stripping used by InfraChecker's ax.b().

Returns a Python str whose code points correspond to Java's UTF-16 string (supplementary
chars are single code points in Python; Java length = len(s.encode('utf-16-le')) // 2).
"""
from __future__ import annotations

REPL = "�"


def _cont(b: int) -> bool:
    return (b & 0xC0) == 0x80


def java_utf8_decode(data: bytes) -> str:
    out = []
    i = 0
    n = len(data)
    while i < n:
        b1 = data[i]
        if b1 < 0x80:
            out.append(chr(b1)); i += 1; continue
        if 0xC2 <= b1 <= 0xDF:                      # 2-byte lead
            if i + 1 >= n:                           # truncated at EOF
                out.append(REPL); i = n; continue
            b2 = data[i + 1]
            if not _cont(b2):
                out.append(REPL); i += 1; continue
            out.append(chr(((b1 & 0x1F) << 6) | (b2 & 0x3F))); i += 2; continue
        if 0xE0 <= b1 <= 0xEF:                      # 3-byte lead
            rem = n - i
            if rem < 3:                              # truncated: check prefix validity like Java
                if rem > 1:
                    b2 = data[i + 1]
                    if (b1 == 0xE0 and (b2 & 0xE0) == 0x80) or not _cont(b2):
                        out.append(REPL); i += 1; continue
                out.append(REPL); i = n; continue    # malformedForLength(remaining) at EOF
            b2, b3 = data[i + 1], data[i + 2]
            if (b1 == 0xE0 and (b2 & 0xE0) == 0x80) or not _cont(b2) or not _cont(b3):
                # malformedN(3)
                ln = 1 if ((b1 == 0xE0 and (b2 & 0xE0) == 0x80) or not _cont(b2)) else 2
                out.append(REPL); i += ln; continue
            cp = ((b1 & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F)
            if 0xD800 <= cp <= 0xDFFF:               # surrogate -> one REPL for 3 bytes
                out.append(REPL); i += 3; continue
            out.append(chr(cp)); i += 3; continue
        if 0xF0 <= b1 <= 0xF4:                      # 4-byte lead
            rem = n - i
            if rem < 4:
                if rem > 1:
                    b2 = data[i + 1]
                    if (b1 == 0xF0 and (b2 < 0x90 or b2 > 0xBF)) or (b1 == 0xF4 and (b2 & 0xF0) != 0x80) or not _cont(b2):
                        out.append(REPL); i += 1; continue
                if rem > 2 and not _cont(data[i + 2]):
                    out.append(REPL); i += 2; continue
                out.append(REPL); i = n; continue
            b2, b3, b4 = data[i + 1], data[i + 2], data[i + 3]
            if (b1 == 0xF0 and (b2 < 0x90 or b2 > 0xBF)) or (b1 == 0xF4 and (b2 & 0xF0) != 0x80) or not _cont(b2):
                out.append(REPL); i += 1; continue
            if not _cont(b3):
                out.append(REPL); i += 2; continue
            if not _cont(b4):
                out.append(REPL); i += 3; continue
            cp = ((b1 & 0x07) << 18) | ((b2 & 0x3F) << 12) | ((b3 & 0x3F) << 6) | (b4 & 0x3F)
            out.append(chr(cp)); i += 4; continue
        out.append(REPL); i += 1                     # 0x80..0xC1, 0xF5..0xFF
    return "".join(out)


def java_body_text(data: bytes) -> str:
    """InputStreamReader(UTF-8) -> BufferedReader.lines() -> join(""): drop every CR and LF."""
    return java_utf8_decode(data).replace("\r", "").replace("\n", "")
