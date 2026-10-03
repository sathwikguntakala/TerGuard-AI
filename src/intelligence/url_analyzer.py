"""
URL Threat Analyzer — extracts URLs from text and performs multi-signal
threat analysis: Shannon entropy, homoglyph/punycode detection, suspicious
TLD flagging, and IP-URL detection.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel

try:
    import tldextract
except ImportError:
    tldextract = None  # type: ignore[assignment]


# ── Pydantic models ──────────────────────────────────────────────────────

class URLReport(BaseModel):
    """Threat intelligence report for a single URL."""
    url: str
    domain: str
    entropy: float
    has_homoglyphs: bool
    homoglyph_details: list[str]
    is_punycode: bool
    suspicious_tld: bool
    tld: str
    is_ip_url: bool
    risk_score: float
    flags: list[str]


# ── Constants ────────────────────────────────────────────────────────────

_SUSPICIOUS_TLDS: set[str] = {
    "xyz", "top", "club", "work", "click", "link", "info", "buzz",
    "loan", "win", "gq", "ml", "cf", "tk", "ga", "rest", "icu",
}

# Mapping of confusable Unicode characters to the Latin letters they mimic.
_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a",   # Cyrillic а
    "\u0435": "e",   # Cyrillic е
    "\u043e": "o",   # Cyrillic о
    "\u0440": "p",   # Cyrillic р
    "\u0441": "c",   # Cyrillic с
    "\u0443": "y",   # Cyrillic у
    "\u0456": "i",   # Cyrillic і
    "\u0261": "g",   # Latin small script g
    "\u03bd": "v",   # Greek nu ν
    "\u03b9": "i",   # Greek iota ι
    "\u03bf": "o",   # Greek omicron ο
    "\u0501": "d",   # Cyrillic komi de
    "\u051b": "q",   # Cyrillic ha with descender
    "\u04bb": "h",   # Cyrillic shha
    "\u0455": "s",   # Cyrillic dze
    "\u0458": "j",   # Cyrillic je
    "\u043a": "k",   # Cyrillic ka (close match)
    "\u043c": "m",   # Cyrillic em (visual match in sans-serif)
    "\u0445": "x",   # Cyrillic kha
    "\u0432": "b",   # Cyrillic ve (partial visual)
    "\u043d": "h",   # Cyrillic en (partial visual)
}

# Regex for extracting URLs (http/https/ftp).
_URL_PATTERN = re.compile(
    r"(?:https?|ftp)://[^\s<>\"')\]]+",
    re.IGNORECASE,
)

_IP_PATTERN = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)


# ── Analyzer class ───────────────────────────────────────────────────────

class URLThreatAnalyzer:
    """Extracts and analyses URLs for phishing/threat indicators."""

    # ── public API ───────────────────────────────────────────────────────

    def analyze_url(self, url: str) -> URLReport:
        """Analyse a single URL and return a threat report."""
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc or ""

        # Domain extraction via tldextract (if available)
        if tldextract is not None:
            ext = tldextract.extract(url)
            registered = getattr(ext, 'top_domain_under_public_suffix', None) or getattr(ext, 'registered_domain', None)
            domain = registered or ext.domain or hostname
            tld = ext.suffix or ""
        else:
            domain = hostname
            parts = hostname.rsplit(".", 1)
            tld = parts[-1] if len(parts) > 1 else ""

        # --- signals ---
        entropy = self._shannon_entropy(domain)
        has_homoglyphs, homoglyph_details = self._detect_homoglyphs(hostname)
        is_punycode = self._detect_punycode(hostname)
        suspicious_tld = tld.lower() in _SUSPICIOUS_TLDS
        is_ip = bool(_IP_PATTERN.match(hostname))

        # --- flags ---
        flags: list[str] = []
        if entropy > 3.5:
            flags.append(f"High domain entropy ({entropy:.2f}) — possible DGA")
        if has_homoglyphs:
            flags.append("Homoglyph characters detected — possible IDN spoofing")
        if is_punycode:
            flags.append("Punycode/IDN domain detected")
        if suspicious_tld:
            flags.append(f"Suspicious TLD: .{tld}")
        if is_ip:
            flags.append("IP-based URL — no domain name resolution")

        # --- composite risk score (0.0–1.0) ---
        entropy_score = min(entropy / 5.0, 1.0) if entropy > 3.5 else entropy / 10.0
        homoglyph_score = 1.0 if has_homoglyphs else 0.0
        tld_score = 1.0 if suspicious_tld else 0.0
        other_score = max(
            1.0 if is_ip else 0.0,
            1.0 if is_punycode else 0.0,
        )

        risk_score = (
            entropy_score * 0.3
            + homoglyph_score * 0.3
            + tld_score * 0.2
            + other_score * 0.2
        )
        risk_score = min(risk_score, 1.0)

        return URLReport(
            url=url,
            domain=domain,
            entropy=entropy,
            has_homoglyphs=has_homoglyphs,
            homoglyph_details=homoglyph_details,
            is_punycode=is_punycode,
            suspicious_tld=suspicious_tld,
            tld=tld,
            is_ip_url=is_ip,
            risk_score=risk_score,
            flags=flags,
        )

    def extract_and_analyze(self, text: str) -> list[URLReport]:
        """Extract all URLs from *text* and analyse each one."""
        urls = _URL_PATTERN.findall(text)
        # Strip trailing punctuation that the regex may have captured
        cleaned: list[str] = []
        for u in urls:
            u = u.rstrip(".,;:!?)>")
            if u:
                cleaned.append(u)
        return [self.analyze_url(u) for u in cleaned]

    # ── private helpers ──────────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Compute Shannon entropy H(X) = -Σ P(x) log₂ P(x) for *s*."""
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )

    @staticmethod
    def _detect_homoglyphs(hostname: str) -> tuple[bool, list[str]]:
        """Check *hostname* for confusable Unicode characters."""
        details: list[str] = []
        for char in hostname:
            if char in _HOMOGLYPH_MAP:
                latin = _HOMOGLYPH_MAP[char]
                details.append(
                    f"U+{ord(char):04X} '{char}' mimics Latin '{latin}'"
                )
        return bool(details), details

    @staticmethod
    def _detect_punycode(hostname: str) -> bool:
        """Return True if *hostname* encodes to an ``xn--`` punycode label."""
        if hostname.startswith("xn--"):
            return True
        try:
            encoded = hostname.encode("idna").decode("ascii")
            return encoded.startswith("xn--") or ".xn--" in encoded
        except (UnicodeError, UnicodeDecodeError):
            return False
