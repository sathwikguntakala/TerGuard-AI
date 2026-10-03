from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Union

from pydantic import BaseModel

try:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    import numpy as np
except ImportError:
    torch = None
    AutoModelForSequenceClassification = None
    AutoTokenizer = None
    np = None

try:
    import onnxruntime as ort
except ImportError:
    ort = None

logger = logging.getLogger(__name__)

class ClassificationResult(BaseModel):
    label: str
    confidence: float
    probabilities: dict[str, float]
    latency_ms: float
    model_name: str
    used_onnx: bool


class TerGuardClassifier:
    def __init__(self, model_name: str = 'distilbert-base-uncased', use_onnx: bool = False):
        self.model_name = model_name
        self.use_onnx = use_onnx
        self.used_onnx = False
        self.tokenizer = None
        self.model = None
        self.ort_session = None
        self.fallback_mode = False

        if AutoTokenizer is None or AutoModelForSequenceClassification is None or torch is None:
            logger.warning("Required ML libraries (torch, transformers) not found. Forcing fallback mode.")
            self.fallback_mode = True
            self.model_name = 'fallback-heuristic'
            return

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
            self.model.eval()
            
            if use_onnx:
                if ort is None:
                    logger.warning("onnxruntime not installed. Falling back to PyTorch.")
                else:
                    # In a full implementation we would export the model to ONNX or load a pre-exported file.
                    logger.warning("Dynamic ONNX export in init not fully supported here. Falling back to PyTorch.")
        except Exception as e:
            logger.warning(f"Failed to load model {model_name}: {e}. Enabling fallback mode.")
            self.fallback_mode = True
            self.model_name = 'fallback-heuristic'
            self.tokenizer = None
            self.model = None
            self.ort_session = None

    @classmethod
    def create_with_fallback(cls, model_name: str = 'distilbert-base-uncased', use_onnx: bool = False) -> TerGuardClassifier:
        """
        Creates a TerGuardClassifier safely. If any exception occurs during initialization,
        returns a classifier forced into fallback mode.
        """
        try:
            return cls(model_name=model_name, use_onnx=use_onnx)
        except Exception as e:
            logger.error(f"Unexpected error creating classifier: {e}")
            instance = cls.__new__(cls)
            instance.model_name = 'fallback-heuristic'
            instance.use_onnx = use_onnx
            instance.used_onnx = False
            instance.tokenizer = None
            instance.model = None
            instance.ort_session = None
            instance.fallback_mode = True
            return instance

    def get_model(self) -> Any:
        return self.model

    def get_tokenizer(self) -> Any:
        return self.tokenizer

    def classify(self, text: str) -> ClassificationResult:
        start_time = time.perf_counter()

        if self.fallback_mode:
            keywords = ['verify', 'account', 'suspended', 'urgent', 'password', 'click here', 'wire transfer']
            text_lower = text.lower()
            match_count = sum(1 for kw in keywords if kw in text_lower)
            
            if match_count >= 2:
                label = 'MALICIOUS'
                probs = {'BENIGN': 0.1, 'SUSPICIOUS': 0.2, 'MALICIOUS': 0.7}
                conf = 0.7
            elif match_count == 1:
                label = 'SUSPICIOUS'
                probs = {'BENIGN': 0.3, 'SUSPICIOUS': 0.6, 'MALICIOUS': 0.1}
                conf = 0.6
            else:
                label = 'BENIGN'
                probs = {'BENIGN': 0.8, 'SUSPICIOUS': 0.1, 'MALICIOUS': 0.1}
                conf = 0.8
                
            latency_ms = (time.perf_counter() - start_time) * 1000
            
            return ClassificationResult(
                label=label,
                confidence=conf,
                probabilities=probs,
                latency_ms=latency_ms,
                model_name=self.model_name,
                used_onnx=False
            )

        try:
            inputs = self.tokenizer(text, return_tensors='pt', padding=True, truncation=True, max_length=512)
            
            if self.used_onnx and self.ort_session is not None:
                # Placeholder for ONNX inference logic if session were loaded
                pass 
            else:
                with torch.no_grad():
                    outputs = self.model(**inputs)
                
                logits = outputs.logits
                probs_tensor = torch.nn.functional.softmax(logits, dim=-1)
                probs_list = probs_tensor.squeeze().tolist()
                
                if isinstance(probs_list, float):
                    probs_list = [1.0 - probs_list, probs_list]
                
                if len(probs_list) >= 2:
                    p_benign = probs_list[0]
                    p_malicious = probs_list[1]
                    
                    if p_malicious > 0.8:
                        label = 'MALICIOUS'
                        conf = p_malicious
                        probs = {'BENIGN': p_benign, 'SUSPICIOUS': 0.0, 'MALICIOUS': p_malicious}
                    elif p_malicious > 0.5:
                        label = 'SUSPICIOUS'
                        conf = p_malicious
                        probs = {'BENIGN': p_benign, 'SUSPICIOUS': p_malicious, 'MALICIOUS': 0.0}
                    else:
                        label = 'BENIGN'
                        conf = p_benign
                        probs = {'BENIGN': p_benign, 'SUSPICIOUS': 0.0, 'MALICIOUS': p_malicious}
                else:
                    label = 'BENIGN'
                    conf = 1.0
                    probs = {'BENIGN': 1.0}
                    
            latency_ms = (time.perf_counter() - start_time) * 1000
            
            return ClassificationResult(
                label=label,
                confidence=conf,
                probabilities=probs,
                latency_ms=latency_ms,
                model_name=self.model_name,
                used_onnx=self.used_onnx
            )
            
        except Exception as e:
            logger.error(f"Inference failed: {e}. Using fallback for this request.")
            latency_ms = (time.perf_counter() - start_time) * 1000
            return ClassificationResult(
                label='SUSPICIOUS',
                confidence=0.5,
                probabilities={'BENIGN': 0.25, 'SUSPICIOUS': 0.5, 'MALICIOUS': 0.25},
                latency_ms=latency_ms,
                model_name='fallback-heuristic-error',
                used_onnx=False
            )
