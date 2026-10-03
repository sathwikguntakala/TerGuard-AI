"""Tests for the NLP classifier module."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from src.nlp.classifier import TerGuardClassifier, ClassificationResult


@pytest.fixture
def classifier() -> TerGuardClassifier:
    """Create a classifier instance (will use fallback mode without a downloaded model)."""
    return TerGuardClassifier.create_with_fallback()


class TestClassifierCreation:
    """Verify classifier instantiation and fallback handling."""

    def test_create_with_fallback_succeeds(self) -> None:
        clf = TerGuardClassifier.create_with_fallback()
        assert clf is not None

    def test_invalid_model_falls_back(self) -> None:
        clf = TerGuardClassifier.create_with_fallback(model_name="nonexistent/model-xyz-999")
        assert clf.fallback_mode is True
        assert clf.model_name == "fallback-heuristic"

    def test_fallback_mode_flag(self, classifier: TerGuardClassifier) -> None:
        # Without a downloaded model, fallback should be active
        # This test is lenient — either real model or fallback is fine
        assert isinstance(classifier.fallback_mode, bool)


class TestClassification:
    """Verify classification inference."""

    def test_classify_returns_result(self, classifier: TerGuardClassifier) -> None:
        result = classifier.classify("Hello, this is a normal email.")
        assert isinstance(result, ClassificationResult)

    def test_result_has_required_fields(self, classifier: TerGuardClassifier) -> None:
        result = classifier.classify("Test message")
        assert isinstance(result.label, str)
        assert result.label in ("BENIGN", "SUSPICIOUS", "MALICIOUS")
        assert isinstance(result.confidence, float)
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.probabilities, dict)
        assert isinstance(result.latency_ms, float)
        assert isinstance(result.model_name, str)
        assert isinstance(result.used_onnx, bool)

    def test_probabilities_contain_expected_keys(self, classifier: TerGuardClassifier) -> None:
        result = classifier.classify("Test input")
        for key in ("BENIGN", "MALICIOUS"):
            assert key in result.probabilities


class TestLatencyTracking:
    """Verify latency is measured and reported."""

    def test_latency_is_positive(self, classifier: TerGuardClassifier) -> None:
        result = classifier.classify("Timing test")
        assert result.latency_ms > 0.0

    def test_latency_is_reasonable(self, classifier: TerGuardClassifier) -> None:
        """Fallback mode should be extremely fast."""
        result = classifier.classify("Quick test")
        # Even with a real model, sub-5000ms is expected on CPU
        assert result.latency_ms < 5000.0


class TestFallbackClassification:
    """Verify fallback keyword-based classification produces reasonable results."""

    def test_phishing_keywords_trigger_malicious(self) -> None:
        clf = TerGuardClassifier.create_with_fallback(model_name="nonexistent/x")
        assert clf.fallback_mode is True
        result = clf.classify("Verify your account or it will be suspended. Click here immediately.")
        assert result.label in ("MALICIOUS", "SUSPICIOUS")
        assert result.probabilities.get("MALICIOUS", 0) > 0.0

    def test_single_keyword_triggers_suspicious(self) -> None:
        clf = TerGuardClassifier.create_with_fallback(model_name="nonexistent/x")
        result = clf.classify("Please verify the attached document.")
        assert result.label in ("SUSPICIOUS", "MALICIOUS")

    def test_clean_text_classified_benign(self) -> None:
        clf = TerGuardClassifier.create_with_fallback(model_name="nonexistent/x")
        result = clf.classify("The quarterly meeting is scheduled for Monday at 10am.")
        assert result.label == "BENIGN"
        assert result.probabilities.get("BENIGN", 0) > 0.5

    def test_empty_text(self, classifier: TerGuardClassifier) -> None:
        result = classifier.classify("")
        assert isinstance(result, ClassificationResult)
        assert result.label in ("BENIGN", "SUSPICIOUS", "MALICIOUS")
