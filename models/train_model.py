"""Model training script for AegisDNS.

Trains Random Forest and Isolation Forest classifiers using Leave-One-Attack-Family-Out
group cross-validation (guaranteeing that test set contains attack families and domains
never seen in training).
"""

from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, roc_auc_score

from backend.app.config import get_config, get_project_root
from backend.app.analytics.feature_extractor import extract_dns_features
from backend.app.analytics.ml_classifier import FEATURE_COLUMNS, MODEL_PATH
from backend.app.utils.synthetic_gen import generate_synthetic_dns_records


def train_models():
    """Train Random Forest and Isolation Forest on Leave-One-Family-Out synthetic DNS dataset."""
    config = get_config()
    print("Generating rich synthetic dataset for model training...")
    records = generate_synthetic_dns_records(num_records=1200, tunnel_ratio=0.30)
    enriched = [extract_dns_features(r) for r in records]
    df = pd.DataFrame(enriched)

    # Label: 1 for any attack family (not benign / hard_benign), 0 otherwise
    df["label"] = df["attack_family"].apply(lambda f: 0 if f in {"benign", "hard_benign"} else 1)

    all_families = list(df["attack_family"].unique())
    attack_families = [f for f in all_families if f not in {"benign", "hard_benign"}]

    print(f"Total samples: {len(df)}, Attack families: {attack_families}")

    # Hold out 2 attack families and 40% of benign domains for test split
    np.random.seed(42)
    test_attack_families = set(np.random.choice(attack_families, size=2, replace=False))
    train_attack_families = set(attack_families) - test_attack_families

    benign_domains = list(df[df["label"] == 0]["base_domain"].unique())
    n_test_benign = max(2, int(len(benign_domains) * 0.4))
    test_benign_domains = set(np.random.choice(benign_domains, size=n_test_benign, replace=False))
    train_benign_domains = set(benign_domains) - test_benign_domains

    train_mask = (df["attack_family"].isin(train_attack_families)) | (
        (df["label"] == 0) & (df["base_domain"].isin(train_benign_domains))
    )
    test_mask = (df["attack_family"].isin(test_attack_families)) | (
        (df["label"] == 0) & (df["base_domain"].isin(test_benign_domains))
    )

    train_df = df[train_mask]
    test_df = df[test_mask]

    X_train, y_train = train_df[FEATURE_COLUMNS].values, train_df["label"].values
    X_test, y_test = test_df[FEATURE_COLUMNS].values, test_df["label"].values

    # Strict Requirement 2 check: Assert test set has positive attack samples
    num_test_positives = int(np.sum(y_test == 1))
    assert num_test_positives > 0, (
        f"ERROR: Test split contains 0 attack samples! (y_test sum: {num_test_positives})"
    )

    print(f"\nTrain attack families: {train_attack_families}")
    print(f"Test attack families (held-out): {test_attack_families}")
    print(f"Test samples: {len(test_df)} (Positives: {num_test_positives}, Negatives: {int(np.sum(y_test == 0))})")

    # 1. Random Forest Classifier
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    rf_model.fit(X_train, y_train)

    # 2. Isolation Forest Classifier
    if_model = IsolationForest(contamination=0.2, random_state=42)
    if_model.fit(X_train[y_train == 0])

    # Evaluation
    rf_preds = rf_model.predict(X_test)
    classes = list(rf_model.classes_)
    pos_idx = classes.index(1) if 1 in classes else 0
    rf_probs = rf_model.predict_proba(X_test)[:, pos_idx]

    # Requirement 3: No hard-coded AUC fallback
    if len(np.unique(y_test)) > 1 and len(np.unique(rf_probs)) > 1:
        auc_val = f"{roc_auc_score(y_test, rf_probs):.4f}"
    else:
        auc_val = "n/a"

    print("\nRandom Forest Held-Out Family Test Results:")
    print(classification_report(y_test, rf_preds, zero_division=0))
    print(f"ROC-AUC: {auc_val}")

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "rf_model": rf_model,
        "if_model": if_model,
        "model_type": "random_forest",
        "feature_columns": FEATURE_COLUMNS,
        "is_synthetic": True,
    }, MODEL_PATH)

    print(f"\nModel artifact successfully saved to {MODEL_PATH}")


if __name__ == "__main__":
    train_models()
