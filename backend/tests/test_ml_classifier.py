"""Unit tests for ml_classifier.py Random Forest & Isolation Forest predictions."""

from backend.app.analytics.ml_classifier import MLAnomalyClassifier


def test_ml_classifier_predict():
    clf = MLAnomalyClassifier()

    benign_rec = {
        "subdomain_len": 3,
        "qname_len": 15,
        "subdomain_depth": 1,
        "entropy": 1.5,
        "digit_ratio": 0.0,
        "hex_ratio": 0.0,
        "uppercase_ratio": 0.0,
        "consonant_vowel_ratio": 1.0,
    }

    anomalous_rec = {
        "subdomain_len": 50,
        "qname_len": 75,
        "subdomain_depth": 4,
        "entropy": 4.5,
        "digit_ratio": 0.4,
        "hex_ratio": 0.7,
        "uppercase_ratio": 0.2,
        "consonant_vowel_ratio": 4.0,
    }

    p_benign = clf.predict_record(benign_rec)
    p_anomalous = clf.predict_record(anomalous_rec)

    assert p_benign < 0.5
    assert p_anomalous > 0.5
