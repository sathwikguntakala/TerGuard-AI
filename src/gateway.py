from __future__ import annotations

import logging
import re
import time
from typing import List

from pydantic import BaseModel

from src.nlp.classifier import TerGuardClassifier, ClassificationResult
from src.nlp.explainability import TokenExplainer, ExplainabilityResult
from src.intelligence.url_analyzer import URLThreatAnalyzer, URLReport
from src.intelligence.heuristics import HeuristicAnalyzer, HeuristicResult

logger = logging.getLogger(__name__)

class ThreatEvaluationResult(BaseModel):
    """Result of a comprehensive threat evaluation."""
    composite_score: float
    threat_level: str
    classification: ClassificationResult
    explainability: ExplainabilityResult
    url_reports: List[URLReport]
    heuristic_result: HeuristicResult
    total_latency_ms: float
    remediation: str
    summary: str


class TerGuardGateway:
    """Unified gateway that orchestrates all analysis components."""
    
    def __init__(self, model_name: str = 'distilbert-base-uncased', use_onnx: bool = False) -> None:
        """Initialize all analysis components."""
        logger.info("Initializing TerGuardGateway components...")
        
        self.classifier = TerGuardClassifier.create_with_fallback(
            model_name=model_name,
            use_onnx=use_onnx
        )
        self.explainer = TokenExplainer(classifier=self.classifier)
        self.url_analyzer = URLThreatAnalyzer()
        self.heuristic_analyzer = HeuristicAnalyzer()
        
        # Simple regex for extracting URLs
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        
        logger.info("TerGuardGateway initialized successfully.")

    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text."""
        return self.url_pattern.findall(text)

    def evaluate_message(self, raw_text: str) -> ThreatEvaluationResult:
        """
        Evaluate a message for threats using all components and produce a final result.
        
        Args:
            raw_text: The raw input message text to evaluate.
            
        Returns:
            ThreatEvaluationResult containing the full analysis and remediation guidance.
        """
        start_time = time.perf_counter()
        
        # 1. NLP Classification
        classification = self.classifier.classify(raw_text)
        
        # 2. Explainability
        explainability = self.explainer.explain(raw_text)
        
        # 3. URL Extraction and Analysis
        extracted_urls = self._extract_urls(raw_text)
        url_reports = []
        for url in extracted_urls:
            try:
                report = self.url_analyzer.analyze_url(url)
                url_reports.append(report)
            except Exception as e:
                logger.error(f"Error analyzing URL {url}: {e}")
                
        # 4. Heuristics Analysis
        heuristic_result = self.heuristic_analyzer.analyze(raw_text)
        
        # 5. Composite Score Calculation
        nlp_score = classification.probabilities.get('MALICIOUS', 0.0) * 100
        url_score = max((r.risk_score for r in url_reports), default=0.0) * 100 if url_reports else 0.0
        heuristic_score_val = heuristic_result.composite_heuristic_score * 100
        
        composite_score = (nlp_score * 0.40) + (url_score * 0.30) + (heuristic_score_val * 0.30)
        
        # 6. Threat Level Mapping
        if composite_score >= 80:
            threat_level = 'CRITICAL'
        elif composite_score >= 60:
            threat_level = 'HIGH'
        elif composite_score >= 40:
            threat_level = 'MEDIUM'
        elif composite_score >= 20:
            threat_level = 'LOW'
        else:
            threat_level = 'SAFE'
            
        # 7. Remediation Guidance
        if threat_level == 'CRITICAL':
            remediation = 'BLOCK immediately. Quarantine message. Alert SOC team. Do not interact with any links.'
        elif threat_level == 'HIGH':
            remediation = 'Flag for manual review. Warn recipient. Block embedded URLs.'
        elif threat_level == 'MEDIUM':
            remediation = 'Add warning banner. Log for analysis. Monitor sender reputation.'
        elif threat_level == 'LOW':
            remediation = 'Log event. No immediate action required. Continue monitoring.'
        else:
            remediation = 'No threats detected. Message cleared for delivery.'
            
        # 8. Generate Summary
        summary = (
            f"Evaluated message as {threat_level} (Score: {composite_score:.2f}/100).\n"
            f"NLP Score: {nlp_score:.2f}, Max URL Score: {url_score:.2f}, Heuristic Score: {heuristic_score_val:.2f}.\n"
            f"Classification: {classification.label} (Conf: {classification.confidence:.2f}). "
            f"Found {len(url_reports)} URLs."
        )
        
        # Calculate Latency
        end_time = time.perf_counter()
        total_latency_ms = (end_time - start_time) * 1000
        
        return ThreatEvaluationResult(
            composite_score=composite_score,
            threat_level=threat_level,
            classification=classification,
            explainability=explainability,
            url_reports=url_reports,
            heuristic_result=heuristic_result,
            total_latency_ms=total_latency_ms,
            remediation=remediation,
            summary=summary
        )
