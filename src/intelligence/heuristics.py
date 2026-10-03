"""
Heuristic Social Engineering Pre-Screener — rule-based detection of
urgency language, credential theft attempts, financial manipulation,
and authority impersonation patterns in text communications.
"""
from __future__ import annotations

import re
from pydantic import BaseModel


# ── Pydantic model ───────────────────────────────────────────────────────

class HeuristicResult(BaseModel):
    """Results from heuristic social engineering analysis."""
    triggered_rules: list[str]
    urgency_score: float
    credential_theft_score: float
    financial_score: float
    authority_score: float
    composite_heuristic_score: float
    details: dict[str, list[str]]


# ── Pattern banks ────────────────────────────────────────────────────────

_URGENCY_PATTERNS: list[str] = [
    r"\bimmediately\b",
    r"\burgent\b",
    r"\bexpire[sd]?\b",
    r"\bsuspended\b",
    r"\bwithin\s+24\s+hours\b",
    r"\bact\s+now\b",
    r"\blimited\s+time\b",
    r"\baccount\s+will\s+be\s+closed\b",
    r"\byour\s+account\s+has\s+been\b",
    r"\bfailure\s+to\b",
    r"\bunauthorized\s+access\s+detected\b",
    r"\btime[- ]?sensitive\b",
    r"\bdon'?t\s+delay\b",
    r"\brespond\s+immediately\b",
    r"\baccount\s+suspension\b",
    r"\bexpiration\b",
    r"\blast\s+chance\b",
    r"\bfinal\s+warning\b",
    r"\bdeadline\b",
]

_CREDENTIAL_PATTERNS: list[str] = [
    r"\bverify\s+your\b",
    r"\bconfirm\s+your\s+identity\b",
    r"\bupdate\s+your\s+password\b",
    r"\blogin\s+credentials?\b",
    r"\bsocial\s+security\b",
    r"\bssn\b",
    r"\benter\s+your\b",
    r"\bclick\s+here\s+to\s+verify\b",
    r"\bsecurity\s+alert\b",
    r"\bunusual\s+sign[- ]?in\b",
    r"\breset\s+your\s+password\b",
    r"\bverify\s+your\s+identity\b",
    r"\bconfirm\s+your\s+account\b",
    r"\bpin\s+number\b",
    r"\bsecret\s+question\b",
    r"\btwo[- ]?factor\b",
    r"\bauthentication\s+code\b",
]

_FINANCIAL_PATTERNS: list[str] = [
    r"\bwire\s+transfer\b",
    r"\bbank\s+account\b",
    r"\brouting\s+number\b",
    r"\bpayment\b",
    r"\binvoice\s+attached\b",
    r"\bpurchase\s+order\b",
    r"\bbitcoin\b",
    r"\bcryptocurrency\b",
    r"\bgift\s+cards?\b",
    r"\btax\s+refund\b",
    r"\birs\b",
    r"\bunclaimed\s+funds?\b",
    r"\brefund\b",
    r"\bmoney\s+transfer\b",
    r"\baccount\s+number\b",
    r"\bpaypal\b",
    r"\bvenmo\b",
    r"\bzelle\b",
]

_AUTHORITY_PATTERNS: list[str] = [
    r"\bceo\b",
    r"\bcfo\b",
    r"\bcto\b",
    r"\bit\s+department\b",
    r"\bhelp\s*desk\b",
    r"\bmicrosoft\s+support\b",
    r"\bgoogle\s+security\b",
    r"\bpaypal\b",
    r"\bapple\b",
    r"\bamazon\b",
    r"\btechnical\s+support\b",
    r"\bsystem\s+administrator\b",
    r"\bhr\s+department\b",
    r"\bcompliance\s+team\b",
    r"\blegal\s+department\b",
    r"\bmanagement\b",
]


# ── Analyzer class ───────────────────────────────────────────────────────

class HeuristicAnalyzer:
    """Rule-based social engineering pre-screener."""

    def __init__(self) -> None:
        # Pre-compile all patterns for speed
        self._urgency = [re.compile(p, re.IGNORECASE) for p in _URGENCY_PATTERNS]
        self._credential = [re.compile(p, re.IGNORECASE) for p in _CREDENTIAL_PATTERNS]
        self._financial = [re.compile(p, re.IGNORECASE) for p in _FINANCIAL_PATTERNS]
        self._authority = [re.compile(p, re.IGNORECASE) for p in _AUTHORITY_PATTERNS]

    # ── public API ───────────────────────────────────────────────────────

    def analyze(self, text: str) -> HeuristicResult:
        """Analyse *text* for social engineering indicators.

        Returns:
            HeuristicResult with per-category scores (0–1), composite
            score, triggered rules, and matched detail strings.
        """
        urgency_matches = self._match_category(text, self._urgency, _URGENCY_PATTERNS)
        credential_matches = self._match_category(text, self._credential, _CREDENTIAL_PATTERNS)
        financial_matches = self._match_category(text, self._financial, _FINANCIAL_PATTERNS)
        authority_matches = self._match_category(text, self._authority, _AUTHORITY_PATTERNS)

        urgency_score = self._score(urgency_matches)
        credential_score = self._score(credential_matches)
        financial_score = self._score(financial_matches)
        authority_score = self._score(authority_matches)

        composite = (
            urgency_score * 0.25
            + credential_score * 0.30
            + financial_score * 0.25
            + authority_score * 0.20
        )

        # Build triggered rules descriptions
        triggered_rules: list[str] = []
        if urgency_matches:
            triggered_rules.append(
                f"Urgency language detected: {', '.join(urgency_matches)}"
            )
        if credential_matches:
            triggered_rules.append(
                f"Credential theft indicators: {', '.join(credential_matches)}"
            )
        if financial_matches:
            triggered_rules.append(
                f"Financial manipulation signals: {', '.join(financial_matches)}"
            )
        if authority_matches:
            triggered_rules.append(
                f"Authority impersonation detected: {', '.join(authority_matches)}"
            )

        details: dict[str, list[str]] = {
            "urgency": urgency_matches,
            "credential_theft": credential_matches,
            "financial": financial_matches,
            "authority": authority_matches,
        }

        return HeuristicResult(
            triggered_rules=triggered_rules,
            urgency_score=urgency_score,
            credential_theft_score=credential_score,
            financial_score=financial_score,
            authority_score=authority_score,
            composite_heuristic_score=composite,
            details=details,
        )

    # ── private helpers ──────────────────────────────────────────────────

    @staticmethod
    def _match_category(
        text: str,
        compiled: list[re.Pattern[str]],
        raw_patterns: list[str],
    ) -> list[str]:
        """Return human-readable match strings for all patterns that fire."""
        matches: list[str] = []
        for pat in compiled:
            m = pat.search(text)
            if m:
                matches.append(m.group().strip())
        return matches

    @staticmethod
    def _score(matches: list[str]) -> float:
        """Convert a list of matches into a 0–1 score (capped)."""
        if not matches:
            return 0.0
        # Each match contributes 0.25; cap at 1.0
        return min(len(matches) * 0.25, 1.0)
