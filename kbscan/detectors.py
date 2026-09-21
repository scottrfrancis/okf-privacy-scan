"""Content detectors.

One rule governs this module: a finding never carries the value that produced it.
A scanner that prints what it found is a second copy of the problem, with a report
attached. Findings carry a salted fingerprint instead, which is enough to count how
many places hold the same identifier and useless to anyone who reads the report.
"""

from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from hashlib import sha256

__all__ = ["Finding", "scan_text", "DETECTOR_NAMES"]


@dataclass(frozen=True)
class Finding:
    detector: str
    line: int
    fingerprint: str
    hint: str
    confidence: str = "high"


DETECTOR_NAMES = (
    "gov-id",
    "payment-card",
    "private-key",
    "connection-string",
    "roster-name",
    "declared-sensitive",
)

_GOV_ID = re.compile(r"\b(\d{3})[- ](\d{2})[- ](\d{4})\b")
_DIGIT_RUN = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
_CONN_STRING = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:@/]+:[^\s:@/]+@[^\s/]+", re.I)
_FRONT_MATTER = re.compile(r"\A---\r?\n(.*?)\r?\n---\s*$", re.S | re.M)
_DECLARED = re.compile(r"^\s*(?:visibility\s*:\s*sensitive|processing\s*:\s*controlled)\s*$", re.M)


def _fingerprint(salt: bytes, normalised: str) -> str:
    return hmac.new(salt, normalised.encode("utf-8"), sha256).hexdigest()[:12]


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _valid_gov_id(area: str, group: str, serial: str) -> bool:
    """Structural validity only. Cuts the obvious false positives, nothing more."""
    if area in ("000", "666") or area[0] == "9":
        return False
    return group != "00" and serial != "0000"


def scan_text(text: str, salt: bytes, roster: list[str] | None = None) -> list[Finding]:
    """Return findings for one document. Never returns the matched text."""
    found: list[Finding] = []
    claimed: list[tuple[int, int]] = []

    def claim(start: int, end: int) -> bool:
        if any(start < e and s < end for s, e in claimed):
            return False
        claimed.append((start, end))
        return True

    for m in _GOV_ID.finditer(text):
        area, group, serial = m.groups()
        if not _valid_gov_id(area, group, serial) or not claim(*m.span()):
            continue
        found.append(
            Finding("gov-id", _line_of(text, m.start()),
                    _fingerprint(salt, area + group + serial),
                    "government identifier, 9 digits")
        )

    for m in _DIGIT_RUN.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if not (13 <= len(digits) <= 19) or not _luhn_ok(digits) or not claim(*m.span()):
            continue
        found.append(
            Finding("payment-card", _line_of(text, m.start()),
                    _fingerprint(salt, digits),
                    f"payment card, {len(digits)} digits, passes Luhn")
        )

    for m in _PRIVATE_KEY.finditer(text):
        if claim(*m.span()):
            found.append(
                Finding("private-key", _line_of(text, m.start()),
                        _fingerprint(salt, m.group()), "private key block header")
            )

    for m in _CONN_STRING.finditer(text):
        if claim(*m.span()):
            scheme = m.group().split("://", 1)[0].lower()
            found.append(
                Finding("connection-string", _line_of(text, m.start()),
                        _fingerprint(salt, m.group()),
                        f"{scheme} URI with an inline password")
            )

    for name in roster or []:
        needle = name.strip()
        if not needle:
            continue
        for m in re.finditer(re.escape(needle), text, re.I):
            if claim(*m.span()):
                found.append(
                    Finding("roster-name", _line_of(text, m.start()),
                            _fingerprint(salt, needle.casefold()),
                            f"roster name, {len(needle)} characters", "medium")
                )

    fm = _FRONT_MATTER.search(text)
    if fm and _DECLARED.search(fm.group(1)):
        found.append(
            Finding("declared-sensitive", 1, _fingerprint(salt, "declared"),
                    "front matter declares this sensitive")
        )

    found.sort(key=lambda f: (f.line, f.detector))
    return found
