"""Tests for the explainability engine."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from src.nlp.classifier import TerGuardClassifier
from src.nlp.explainability import TokenExplainer, ExplainabilityResult, TokenAttribution


@pytest.fixture
def explainer() -> TokenExplainer:
    """Create an explainer with a fallback classifier."""
    clf = TerGuardClassifier.create_with_fallback(model_name="nonexistent/x")
    return TokenExplainer(classifier=clf)


class TestExplainMethod:
    """Verify the explain method produces valid results."""

    def test_explain_returns_result(self, explainer: TokenExplainer) -> None:
        result = explainer.explain("Verify your account credentials immediately.")
        assert isinstance(result, ExplainabilityResult)

    def test_tokens_match_input_words(self, explainer: TokenExplainer) -> None:
        text = "Hello world test"
        result = explainer.explain(text)
        assert len(result.tokens) == 3
        assert [t.token for t in result.tokens] == ["Hello", "world", "test"]

    def test_normalized_scores_in_range(self, explainer: TokenExplainer) -> None:
        result = explainer.explain("Verify your password or account will be suspended.")
        for token in result.tokens:
            assert 0.0 <= token.normalized_score <= 1.0

    def test_top_risk_tokens_limited(self, explainer: TokenExplainer) -> None:
        # Long text to ensure more than 10 words
        text = " ".join(["word"] * 20 + ["verify", "password", "suspended"])
        result = explainer.explain(text)
        assert len(result.top_risk_tokens) <= 10

    def test_top_risk_tokens_sorted_descending(self, explainer: TokenExplainer) -> None:
        result = explainer.explain("Verify your account password immediately or be suspended.")
        scores = [t.normalized_score for t in result.top_risk_tokens]
        assert scores == sorted(scores, reverse=True)

    def test_empty_text(self, explainer: TokenExplainer) -> None:
        result = explainer.explain("")
        assert result.tokens == []
        assert result.html_heatmap == ""
        assert result.top_risk_tokens == []

    def test_method_is_leave_one_out(self, explainer: TokenExplainer) -> None:
        result = explainer.explain("Test")
        assert result.method == "leave-one-out"


class TestKeywordBoosting:
    """Verify high-risk keywords receive score boosts."""

    def test_phishing_keywords_get_higher_scores(self, explainer: TokenExplainer) -> None:
        result = explainer.explain("Please verify your credentials now")
        score_map = {t.token.lower(): t.normalized_score for t in result.tokens}
        # 'verify' and 'credentials' should be boosted above 'please' and 'now'
        if "verify" in score_map and "please" in score_map:
            assert score_map["verify"] >= score_map["please"]


class TestHTMLHeatmap:
    """Verify HTML heatmap generation."""

    def test_heatmap_contains_spans(self, explainer: TokenExplainer) -> None:
        result = explainer.explain("Test message here")
        assert "<span" in result.html_heatmap
        assert "background-color" in result.html_heatmap

    def test_heatmap_contains_all_tokens(self, explainer: TokenExplainer) -> None:
        result = explainer.explain("Hello world")
        assert "Hello" in result.html_heatmap
        assert "world" in result.html_heatmap

    def test_critical_tokens_get_red_background(self, explainer: TokenExplainer) -> None:
        result = explainer.explain("verify password suspended urgent immediately credentials")
        # At least some tokens should have the red/orange backgrounds
        assert "#ef5350" in result.html_heatmap or "#ff8a65" in result.html_heatmap

    def test_heatmap_uses_monospace_font(self, explainer: TokenExplainer) -> None:
        result = explainer.explain("Test")
        assert "monospace" in result.html_heatmap


class TestTokenAttributionModel:
    """Verify TokenAttribution Pydantic model."""

    def test_token_attribution_creation(self) -> None:
        ta = TokenAttribution(token="test", score=0.5, normalized_score=0.75)
        assert ta.token == "test"
        assert ta.score == 0.5
        assert ta.normalized_score == 0.75

    def test_saliency_weights_sum_bounds(self, explainer: TokenExplainer) -> None:
        """Normalized scores should be bounded and reasonable."""
        result = explainer.explain("Verify your account or it will be suspended immediately")
        total = sum(t.normalized_score for t in result.tokens)
        # Total is not required to sum to 1.0 (min-max normalization),
        # but should be >= 0 and reasonable
        assert total >= 0.0
