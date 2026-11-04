"""Java ``String`` lengths are counted in UTF-16 code units."""
from __future__ import annotations


def java_length(text: str) -> int:
    """``String.length()``: supplementary characters count twice."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2
