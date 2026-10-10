"""Machine Learning Anomaly Classifier supporting Random Forest and Isolation Forest.

Extracts numeric feature vectors and performs inference against pre-trained
models to produce anomaly probability scores.
"""

from typing import List, Dict, Any, Optional, Union
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest

from backend.app.config import get_config, get_project_root
from backend.app.analytics.feature_extractor import FEATURE_COLUMNS
from backend.app.analytics.detectors import is_allowlisted_domain

MODEL_PATH = get_project_root() / "models" / "trained_rf_dns.joblib"


class MLAnomalyClassifier:
    """Machine learning classifier for DNS tunneling & anomaly detection."""

    def __init__(self, model_path: Union[str, Path] = None):
        self.model_path = Path(model_path) if model_path else MODEL_PATH
        self.rf_model: Optional[RandomForestClassifier] = None
        self.if_model: Optional[IsolationForest] = None
        self.model_type: str = "random_forest"
        self._load_or_create_default_model()

    def _extract_feature_matrix(self, records: List[Dict[str, Any]]) -> np.ndarray:
        """Convert list of enriched records into a 2D numpy feature matrix using FEATURE_COLUMNS."""
        if not records:
            return np.empty((0, len(FEATURE_COLUMNS)))

        matrix = []
        for r in records:
            row = [float(r.get(col, 0.0)) for col in FEATURE_COLUMNS]
            matrix.append(row)
        return np.array(matrix)

    def _load_or_create_default_model(self):
        """Load trained model from disk or fit a lightweight fallback model."""
        if self.model_path.exists():
            try:
                saved = joblib.load(self.model_path)
                if isinstance(saved, dict):
                    self.rf_model = saved.get("rf_model")
                    self.if_model = saved.get("if_model")
                    self.model_type = saved.get("model_type", "random_forest")
                elif isinstance(saved, RandomForestClassifier):
                    self.rf_model = saved
                    self.model_type = "random_forest"
                return
            except Exception:
                pass

        self._fit_default_fallback()

    def _fit_default_fallback(self):
        """Fit a simple default Random Forest & Isolation Forest model for cold start."""
        np.random.seed(42)
        n_features = len(FEATURE_COLUMNS)
        benign_X = np.random.uniform(0.0, 1.0, size=(200, n_features))
        tunneled_X = np.random.uniform(0.5, 2.0, size=(200, n_features))

        X = np.vstack([benign_X, tunneled_X])
        y = np.array([0] * 200 + [1] * 200)

        self.rf_model = RandomForestClassifier(n_estimators=50, max_depth=8, random_state=42)
        self.rf_model.fit(X, y)

        self.if_model = IsolationForest(contamination=0.2, random_state=42)
        self.if_model.fit(X)

    def predict_record(self, record: Dict[str, Any]) -> float:
        """Predict anomaly probability for a single record."""
        probs = self.predict_batch([record])
        return probs[0] if probs else 0.0

    def predict_batch(self, records: List[Dict[str, Any]]) -> List[float]:
        """Predict anomaly probabilities for a list of records."""
        if not records:
            return []
        X = self._extract_feature_matrix(records)
        if X.shape[0] == 0:
            return [0.0] * len(records)

        raw_probas: List[float] = []
        if self.rf_model is not None:
            proba_matrix = self.rf_model.predict_proba(X)
            classes = list(self.rf_model.classes_)
            if 1 in classes:
                pos_idx = classes.index(1)
                raw_probas = [float(p) for p in proba_matrix[:, pos_idx]]
            else:
                raw_probas = [0.0] * X.shape[0]
        elif self.if_model is not None:
            raw_scores = -self.if_model.score_samples(X)
            probas = 1.0 / (1.0 + np.exp(-raw_scores * 5.0))
            raw_probas = [float(p) for p in probas]
        else:
            raw_probas = [0.0] * len(records)

        final_probs = []
        for idx, rec in enumerate(records):
            bdom = rec.get("base_domain", "")
            qname = rec.get("qname", "")
            if rec.get("is_allowlisted") or is_allowlisted_domain(bdom) or is_allowlisted_domain(qname):
                final_probs.append(0.0)
            else:
                p = raw_probas[idx] if idx < len(raw_probas) else 0.0
                final_probs.append(round(p, 4))
        return final_probs
