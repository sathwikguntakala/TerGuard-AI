# 🛡️ TerGuard AI – Real-Time Threat Intelligence & Social Engineering Gateway

> **High-throughput, explainable phishing and social engineering detection engine** with sub-30ms inference, token-level XAI heatmaps, and an interactive SOC analyst dashboard.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     TerGuard Gateway (src/gateway.py)           │
│   Orchestrates all layers → Composite Risk Score (0–100)        │
├────────────────┬──────────────────┬─────────────────────────────┤
│  NLP Inference │  URL Intelligence │  Heuristic Engine          │
│  (DistilBERT)  │  (Entropy + IDN)  │  (Rule-based Screener)    │
│  src/nlp/      │  src/intelligence/│  src/intelligence/         │
│  classifier.py │  url_analyzer.py  │  heuristics.py             │
├────────────────┴──────────────────┴─────────────────────────────┤
│              Explainability Engine (src/nlp/explainability.py)  │
│     Token-level saliency → Color-coded risk heatmaps           │
├─────────────────────────────────────────────────────────────────┤
│              SOC Dashboard (app/ui.py – Streamlit)              │
│     Dark theme · Telemetry HUD · URL Ledger · Export            │
└─────────────────────────────────────────────────────────────────┘
```

### Detection Layers

| Layer | Module | Purpose |
|-------|--------|---------|
| **NLP Inference** | `src/nlp/classifier.py` | DistilBERT transformer with PyTorch/ONNX Runtime pipeline. Sub-30ms latency target. Falls back to keyword-based heuristic if model unavailable. |
| **Explainability** | `src/nlp/explainability.py` | Leave-one-out perturbation + keyword boosting. Produces per-token risk attribution scores (0–1) and HTML heatmaps. |
| **URL Analysis** | `src/intelligence/url_analyzer.py` | Shannon entropy for DGA detection, homoglyph/punycode spoofing, suspicious TLD flagging, IP-URL detection. |
| **Heuristic Rules** | `src/intelligence/heuristics.py` | Urgency language, credential theft, financial manipulation, and authority impersonation pattern matching. |
| **Gateway** | `src/gateway.py` | Composite scoring: NLP (40%) + URL threat (30%) + Heuristics (30%). Maps to CRITICAL/HIGH/MEDIUM/LOW/SAFE with remediation guidance. |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- 4 GB RAM minimum (8 GB recommended for transformer model)

### Setup

```bash
# Clone and enter the project
cd "TerGuard AI"

# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (Linux/macOS)
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment config
cp .env.example .env
```

### Run Tests

```bash
pytest -v
```

### Launch Dashboard

```bash
streamlit run app/ui.py --server.port 8501 --server.headless true
```

Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 📁 Project Structure

```
TerGuard AI/
├── src/
│   ├── nlp/
│   │   ├── classifier.py          # DistilBERT + ONNX/PyTorch pipeline
│   │   └── explainability.py      # Token saliency & attribution
│   ├── intelligence/
│   │   ├── url_analyzer.py        # URL entropy, homoglyphs, TLD checks
│   │   └── heuristics.py          # Social engineering rule engine
│   ├── utils/
│   │   └── samples.py             # Curated test dataset
│   └── gateway.py                 # Unified orchestrator
├── app/
│   └── ui.py                      # Streamlit SOC dashboard
├── tests/
│   ├── test_classifier.py
│   ├── test_explainability.py
│   ├── test_url_analyzer.py
│   └── test_heuristics.py
├── requirements.txt
├── .env.example
└── README.md
```

---

## 🔌 Key Interfaces

### TerGuardClassifier

```python
from src.nlp.classifier import TerGuardClassifier

clf = TerGuardClassifier(model_name="distilbert-base-uncased", use_onnx=False)
result = clf.classify("Verify your account immediately!")
# result.label → 'MALICIOUS'
# result.confidence → 0.7
# result.latency_ms → 12.3
```

### TokenExplainer

```python
from src.nlp.explainability import TokenExplainer

explainer = TokenExplainer(classifier=clf)
result = explainer.explain("Click here to verify your password")
# result.html_heatmap → color-coded HTML string
# result.top_risk_tokens → [TokenAttribution(token='verify', ...)]
```

### URLThreatAnalyzer

```python
from src.intelligence.url_analyzer import URLThreatAnalyzer

analyzer = URLThreatAnalyzer()
report = analyzer.analyze_url("http://secure-login.xyz/auth")
# report.entropy → 3.87
# report.suspicious_tld → True
# report.risk_score → 0.65
```

### TerGuardGateway

```python
from src.gateway import TerGuardGateway

gateway = TerGuardGateway()
result = gateway.evaluate_message("Your account is suspended. Verify at http://phish.xyz")
# result.threat_level → 'HIGH'
# result.composite_score → 67.5
# result.remediation → 'Flag for manual review...'
```

---

## ⚙️ Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_NAME` | `distilbert-base-uncased` | Hugging Face model ID |
| `INFERENCE_DEVICE` | `cpu` | `cpu` or `cuda` |
| `ENABLE_ONNX` | `false` | Use ONNX Runtime for inference |
| `HIGH_RISK_THRESHOLD` | `0.75` | Score threshold for CRITICAL/HIGH |
| `SUSPICIOUS_THRESHOLD` | `0.45` | Score threshold for SUSPICIOUS |

---

## 🧮 Composite Risk Formula

$$\text{Score} = 0.40 \times \text{NLP}_{malicious} + 0.30 \times \max(\text{URL}_{risk}) + 0.30 \times \text{Heuristic}_{composite}$$

**Threat Levels:**

| Score Range | Level | Action |
|-------------|-------|--------|
| ≥ 80 | 🔴 CRITICAL | Block & quarantine immediately |
| ≥ 60 | 🟠 HIGH | Flag for manual review |
| ≥ 40 | 🟡 MEDIUM | Add warning banner |
| ≥ 20 | 🟢 LOW | Log event, continue monitoring |
| < 20 | 🔵 SAFE | Cleared for delivery |

---

## 🧪 Testing

The test suite runs completely offline with no external API dependencies:

```bash
# Run all tests
pytest -v

# Run specific test module
pytest tests/test_url_analyzer.py -v

# Run with coverage
pytest --tb=short -q
```

---

## 📜 License

MIT License — See LICENSE file for details.

---

<p align="center">
  Built with 🛡️ by TerGuard AI
</p>
