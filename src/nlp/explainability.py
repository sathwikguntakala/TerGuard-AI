from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from pydantic import BaseModel

if TYPE_CHECKING:
    # Using Any for classifier to avoid circular imports if TerGuardClassifier is not strictly needed at runtime
    pass

logger = logging.getLogger(__name__)

class TokenAttribution(BaseModel):
    """Represents the explainability attribution score for a single token."""
    token: str
    score: float
    normalized_score: float

class ExplainabilityResult(BaseModel):
    """The result of an explainability analysis on a text."""
    tokens: list[TokenAttribution]
    html_heatmap: str
    top_risk_tokens: list[TokenAttribution]
    method: str

class TokenExplainer:
    """
    Computes token-level saliency/attribution scores for explainability using
    leave-one-out perturbation.
    """
    def __init__(self, classifier: Any) -> None:
        """
        Initializes the explainer with a classifier instance.
        
        Args:
            classifier: An instance of TerGuardClassifier.
        """
        self.classifier = classifier
        self.high_risk_keywords = {
            'verify', 'password', 'suspended', 'urgent', 'immediately', 
            'wire transfer', 'click here', 'account', 'credentials', 'expire', 
            'unauthorized', 'bitcoin', 'gift card', 'ssn', 'social security', 
            'confirm your identity', 'bank account'
        }

    def _get_malicious_probability(self, text: str) -> float:
        """
        Helper to extract malicious probability from the classifier result.

        The classifier returns a ``ClassificationResult`` whose ``probabilities``
        dict maps label names ('BENIGN', 'SUSPICIOUS', 'MALICIOUS') to floats.
        """
        try:
            result = self.classifier.classify(text)
            # ClassificationResult from TerGuardClassifier
            if hasattr(result, 'probabilities') and isinstance(result.probabilities, dict):
                return float(result.probabilities.get('MALICIOUS', 0.0))
            return 0.0
        except Exception as e:
            logger.warning("Failed to get malicious probability, falling back to 0.0: %s", e)
            return 0.0

    def explain(self, text: str) -> ExplainabilityResult:
        """
        Explains the model's prediction on the given text using leave-one-out perturbation.
        
        Args:
            text: The text to explain.
            
        Returns:
            ExplainabilityResult containing token-level attributions and a heatmap.
        """
        logger.info("Explaining text with length %d", len(text))
        baseline_prob = self._get_malicious_probability(text)
        
        words = text.split()
        if not words:
            return ExplainabilityResult(
                tokens=[],
                html_heatmap="",
                top_risk_tokens=[],
                method="leave-one-out"
            )
            
        raw_scores = []
        tokens = []
        is_fallback = getattr(self.classifier, 'fallback_mode', False)
        
        for i, word in enumerate(words):
            # a & b. Leave-one-out perturbation
            reduced_text = " ".join(words[:i] + words[i+1:])
            reduced_prob = self._get_malicious_probability(reduced_text)
            
            # The attribution score = baseline_malicious_prob - reduced_malicious_prob
            score = baseline_prob - reduced_prob
            
            # c. Boost scores for high-risk keywords
            w_lower = word.lower()
            is_keyword = any(kw in w_lower for kw in self.high_risk_keywords)
            
            if is_keyword:
                score += 0.15
            elif is_fallback:
                # Assign base score of 0.05 to non-keyword tokens in fallback mode
                score += 0.05
                
            raw_scores.append(score)
            
        # d. Min-max normalization
        min_score = min(raw_scores) if raw_scores else 0.0
        max_score = max(raw_scores) if raw_scores else 0.0
        score_range = max_score - min_score
        
        for i, word in enumerate(words):
            score = raw_scores[i]
            if score_range > 0:
                normalized_score = (score - min_score) / score_range
            elif max_score > 0:
                # All scores are identical and positive — assign based on
                # absolute magnitude so keyword-only inputs still highlight.
                normalized_score = min(max_score / 0.20, 1.0)
            else:
                # All scores are zero or negative — nothing to highlight.
                normalized_score = 0.0
                
            tokens.append(TokenAttribution(
                token=word,
                score=score,
                normalized_score=normalized_score,
            ))
            
        # e. Sort and pick top 10 tokens as top_risk_tokens
        sorted_tokens = sorted(tokens, key=lambda t: t.normalized_score, reverse=True)
        top_risk_tokens = sorted_tokens[:10]
        
        # Generate HTML heatmap
        html_heatmap = self.generate_html_heatmap(tokens)
        
        return ExplainabilityResult(
            tokens=tokens,
            html_heatmap=html_heatmap,
            top_risk_tokens=top_risk_tokens,
            method="leave-one-out"
        )

    def generate_html_heatmap(self, tokens: list[TokenAttribution]) -> str:
        """
        Generates an HTML representation of the token attributions.
        
        Args:
            tokens: A list of TokenAttribution objects.
            
        Returns:
            A string containing the HTML heatmap.
        """
        html_parts = []
        for t in tokens:
            score = t.normalized_score
            if score < 0.2:
                bg_color = "#c8e6c9"  # pale green - safe
                text_color = "black"
            elif score < 0.4:
                bg_color = "#fff9c4"  # pale yellow - low risk
                text_color = "black"
            elif score < 0.6:
                bg_color = "#ffe0b2"  # orange - medium risk
                text_color = "black"
            elif score < 0.8:
                bg_color = "#ff8a65"  # dark orange - high risk
                text_color = "black"
            else:
                bg_color = "#ef5350"  # dark red - critical
                text_color = "white"
                
            style = (
                f"background-color: {bg_color}; color: {text_color}; "
                "padding: 2px 4px; margin: 1px; border-radius: 3px; "
                "display: inline-block; font-family: monospace;"
            )
            html_parts.append(f'<span style="{style}">{t.token}</span>')
            
        return "".join(html_parts)
