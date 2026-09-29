"""Small helpers for text a non-technical reader sees.

"0.35 h" and "2 broad scope(s) across 1 user(s)" are correct and unreadable.
Everything client-facing goes through these instead.
"""

from __future__ import annotations

_SMALL = {1: "One", 2: "Two", 3: "Three", 4: "Four", 5: "Five", 6: "Six", 7: "Seven", 8: "Eight", 9: "Nine"}


def duration(hours: float) -> str:
    """0.35 -> "about 20 minutes"; 1.0 -> "about an hour"; 7.3 -> "about 7 hours"."""
    minutes = max(15, round(hours * 60 / 5) * 5)
    if minutes < 55:
        return f"about {minutes} minutes"
    if minutes <= 75:
        return "about an hour"
    half_hours = round(hours * 2) / 2
    return f"about {half_hours:g} hours"


def count(n: int, singular: str, plural: str | None = None, *, start: bool = False) -> str:
    """count(3, "account") -> "3 accounts"; count(1, "account", start=True) -> "One account"."""
    noun = singular if n == 1 else (plural or f"{singular}s")
    number = _SMALL.get(n, str(n)) if start else str(n)
    return f"{number} {noun}"


def verb(n: int, singular: str, plural: str) -> str:
    """verb(1, "has", "have") -> "has"."""
    return singular if n == 1 else plural


def lower_first(text: str) -> str:
    return text[:1].lower() + text[1:] if text else text
