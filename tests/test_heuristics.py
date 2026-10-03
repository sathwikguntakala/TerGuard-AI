"""Tests for the heuristic social engineering pre-screener."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from src.intelligence.heuristics import HeuristicAnalyzer, HeuristicResult


@pytest.fixture
def analyzer() -> HeuristicAnalyzer:
    return HeuristicAnalyzer()


class TestUrgencyDetection:
    """Verify urgency language is detected and scored."""

    def test_urgency_keywords_flagged(self, analyzer: HeuristicAnalyzer) -> None:
        text = "Your account will be suspended immediately if you do not act now!"
        result = analyzer.analyze(text)
        assert result.urgency_score > 0.0
        assert any("urgency" in rule.lower() or "urgent" in rule.lower() for rule in result.triggered_rules)

    def test_no_urgency_in_benign(self, analyzer: HeuristicAnalyzer) -> None:
        text = "Meeting scheduled for next Thursday to discuss Q3 results."
        result = analyzer.analyze(text)
        assert result.urgency_score < 0.3


class TestCredentialTheft:
    """Verify credential theft pattern detection."""

    def test_verify_credentials_detected(self, analyzer: HeuristicAnalyzer) -> None:
        text = "Please verify your identity and update your password at this link."
        result = analyzer.analyze(text)
        assert result.credential_theft_score > 0.0

    def test_ssn_request_detected(self, analyzer: HeuristicAnalyzer) -> None:
        text = "We need your social security number to process your claim."
        result = analyzer.analyze(text)
        assert result.credential_theft_score > 0.0

    def test_clean_text_low_credential_score(self, analyzer: HeuristicAnalyzer) -> None:
        text = "The quarterly financial report is attached for your review."
        result = analyzer.analyze(text)
        assert result.credential_theft_score < 0.3


class TestFinancialManipulation:
    """Verify financial manipulation pattern detection."""

    def test_wire_transfer_flagged(self, analyzer: HeuristicAnalyzer) -> None:
        text = "Please complete this wire transfer of $50,000 to the following bank account."
        result = analyzer.analyze(text)
        assert result.financial_score > 0.0

    def test_crypto_flagged(self, analyzer: HeuristicAnalyzer) -> None:
        text = "Send 2 bitcoin to this wallet address to unlock your files."
        result = analyzer.analyze(text)
        assert result.financial_score > 0.0

    def test_gift_card_flagged(self, analyzer: HeuristicAnalyzer) -> None:
        text = "Buy 5 Amazon gift cards and send me the codes immediately."
        result = analyzer.analyze(text)
        assert result.financial_score > 0.0


class TestAuthorityImpersonation:
    """Verify authority impersonation patterns."""

    def test_ceo_impersonation(self, analyzer: HeuristicAnalyzer) -> None:
        text = "This is from the CEO. I need you to process this payment right away."
        result = analyzer.analyze(text)
        assert result.authority_score > 0.0

    def test_it_department_impersonation(self, analyzer: HeuristicAnalyzer) -> None:
        text = "IT Department notice: Your system administrator has flagged your account."
        result = analyzer.analyze(text)
        assert result.authority_score > 0.0


class TestCompositeScore:
    """Verify composite heuristic scoring."""

    def test_composite_between_zero_and_one(self, analyzer: HeuristicAnalyzer) -> None:
        text = "Normal business communication about the upcoming project deadline."
        result = analyzer.analyze(text)
        assert 0.0 <= result.composite_heuristic_score <= 1.0

    def test_multi_category_phishing_high_score(self, analyzer: HeuristicAnalyzer) -> None:
        text = (
            "URGENT: Your CEO needs you to wire transfer $25,000 immediately. "
            "Verify your credentials and confirm your identity to proceed. "
            "Failure to act within 24 hours will result in account suspension."
        )
        result = analyzer.analyze(text)
        assert result.composite_heuristic_score > 0.3
        assert len(result.triggered_rules) >= 2

    def test_benign_text_low_composite(self, analyzer: HeuristicAnalyzer) -> None:
        text = "Reminder: Team lunch tomorrow at noon in the main conference room."
        result = analyzer.analyze(text)
        assert result.composite_heuristic_score < 0.3


class TestHeuristicResultStructure:
    """Ensure HeuristicResult has all expected fields."""

    def test_result_fields(self, analyzer: HeuristicAnalyzer) -> None:
        result = analyzer.analyze("Test message")
        assert isinstance(result.triggered_rules, list)
        assert isinstance(result.urgency_score, float)
        assert isinstance(result.credential_theft_score, float)
        assert isinstance(result.financial_score, float)
        assert isinstance(result.authority_score, float)
        assert isinstance(result.composite_heuristic_score, float)
        assert isinstance(result.details, dict)
