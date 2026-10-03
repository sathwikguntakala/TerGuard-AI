"""Tests for the URL threat analyzer module."""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from src.intelligence.url_analyzer import URLThreatAnalyzer, URLReport


@pytest.fixture
def analyzer() -> URLThreatAnalyzer:
    return URLThreatAnalyzer()


class TestShannonEntropy:
    """Verify Shannon entropy calculation flags randomised domains."""

    def test_low_entropy_domain(self, analyzer: URLThreatAnalyzer) -> None:
        """Common words produce low entropy."""
        report = analyzer.analyze_url("http://google.com")
        # 'google' has relatively low entropy
        assert report.entropy < 4.0

    def test_high_entropy_domain(self, analyzer: URLThreatAnalyzer) -> None:
        """Random-looking strings have high entropy → flagged."""
        report = analyzer.analyze_url("http://a8k3xz9qm4.xyz/login")
        assert report.entropy > 3.0
        assert any("entropy" in f.lower() for f in report.flags)

    def test_entropy_is_non_negative(self, analyzer: URLThreatAnalyzer) -> None:
        report = analyzer.analyze_url("http://a.com")
        assert report.entropy >= 0.0


class TestHomoglyphDetection:
    """Verify homoglyph / IDN spoofing detection."""

    def test_cyrillic_o_detected(self, analyzer: URLThreatAnalyzer) -> None:
        """Cyrillic 'о' (U+043E) in 'microsoft' should be flagged."""
        # Replace the 'o' in microsoft with Cyrillic о
        spoofed = "http://micros\u043eft.com/login"
        report = analyzer.analyze_url(spoofed)
        assert report.has_homoglyphs is True
        assert len(report.homoglyph_details) > 0

    def test_clean_domain_no_homoglyphs(self, analyzer: URLThreatAnalyzer) -> None:
        report = analyzer.analyze_url("http://example.com")
        assert report.has_homoglyphs is False


class TestSuspiciousTLD:
    """Verify suspicious TLD flagging."""

    def test_xyz_flagged(self, analyzer: URLThreatAnalyzer) -> None:
        report = analyzer.analyze_url("http://secure-login.xyz")
        assert report.suspicious_tld is True

    def test_com_not_flagged(self, analyzer: URLThreatAnalyzer) -> None:
        report = analyzer.analyze_url("http://example.com")
        assert report.suspicious_tld is False

    def test_tk_flagged(self, analyzer: URLThreatAnalyzer) -> None:
        report = analyzer.analyze_url("http://free-prize.tk")
        assert report.suspicious_tld is True


class TestIPDetection:
    """Verify IP-based URL detection."""

    def test_ip_url_detected(self, analyzer: URLThreatAnalyzer) -> None:
        report = analyzer.analyze_url("http://192.168.1.1/admin")
        assert report.is_ip_url is True
        assert any("ip" in f.lower() for f in report.flags)

    def test_domain_not_ip(self, analyzer: URLThreatAnalyzer) -> None:
        report = analyzer.analyze_url("http://example.com")
        assert report.is_ip_url is False


class TestURLExtraction:
    """Verify URL extraction from message bodies."""

    def test_extracts_multiple_urls(self, analyzer: URLThreatAnalyzer) -> None:
        text = (
            "Please click http://phish.xyz/login or "
            "visit https://legit.com/dashboard for details."
        )
        reports = analyzer.extract_and_analyze(text)
        assert len(reports) >= 2

    def test_no_urls_returns_empty(self, analyzer: URLThreatAnalyzer) -> None:
        reports = analyzer.extract_and_analyze("Hello, no links here!")
        assert reports == []


class TestRiskScore:
    """Verify composite risk scoring."""

    def test_risk_between_zero_and_one(self, analyzer: URLThreatAnalyzer) -> None:
        report = analyzer.analyze_url("http://example.com")
        assert 0.0 <= report.risk_score <= 1.0

    def test_suspicious_url_higher_risk(self, analyzer: URLThreatAnalyzer) -> None:
        safe = analyzer.analyze_url("http://google.com")
        risky = analyzer.analyze_url("http://a8k3x-verify.xyz/secure-login")
        assert risky.risk_score > safe.risk_score


class TestURLReportStructure:
    """Ensure URLReport has all required fields."""

    def test_report_fields(self, analyzer: URLThreatAnalyzer) -> None:
        report = analyzer.analyze_url("http://example.com")
        assert isinstance(report.url, str)
        assert isinstance(report.domain, str)
        assert isinstance(report.entropy, float)
        assert isinstance(report.has_homoglyphs, bool)
        assert isinstance(report.homoglyph_details, list)
        assert isinstance(report.is_punycode, bool)
        assert isinstance(report.suspicious_tld, bool)
        assert isinstance(report.tld, str)
        assert isinstance(report.is_ip_url, bool)
        assert isinstance(report.risk_score, float)
        assert isinstance(report.flags, list)
