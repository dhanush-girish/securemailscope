"""
train_models.py

Trains:
  1. A RandomForestClassifier for risk classification (Low/Medium/High/Critical).
     Since we have no human-labeled real data yet, labels are generated with a
     transparent rule-based scoring function (weak supervision). This is
     documented clearly -- swap `rule_based_risk_label` for real analyst
     labels the moment you have them, everything else stays the same.
  2. An IsolationForest for unsupervised anomaly detection on the same
     feature space, to flag sessions that look unusual even if they don't
     trip the rule-based labels.

Saves:
  pipeline/saved_models/preprocessor.pkl
  pipeline/saved_models/rf_model.pkl
  pipeline/saved_models/iso_model.pkl
  pipeline/saved_models/label_encoder.pkl
  pipeline/saved_models/metadata.json
"""

import json
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline.preprocessing import (
    records_to_feature_df, NUMERIC_FEATURES, CATEGORICAL_FEATURES,
    SecureMailPreprocessor, normalize_record,
)

SAVE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_models")
os.makedirs(SAVE_DIR, exist_ok=True)


def rule_based_risk_label(norm_record: dict) -> str:
    """
    Weak-supervision labeling function used as a FALLBACK when a record has
    no real "label" field (e.g. all of the synthetic data). Produces one of:
    Low, Medium, High, Critical.
    """
    from pipeline.preprocessing import (
        _is_deprecated_tls, _cipher_strength_score, _key_exchange_score,
        _key_length_score, _to_int_bool,
    )
    score = 0
    tls_version = norm_record.get("tls_version")
    cipher = norm_record.get("cipher_suite")
    expiry = norm_record.get("cert_expiry_days")

    if _is_deprecated_tls(tls_version):
        score += 3
    if tls_version is None:
        score += 1
    if _cipher_strength_score(cipher) == 0:
        score += 3
    if cipher is None:
        score += 1
    if _key_exchange_score(norm_record.get("key_exchange")) == 0:
        score += 1
    if _key_length_score(norm_record.get("key_length")) in (0, 1):
        score += 2
    if expiry is not None:
        try:
            expiry_f = float(expiry)
            if expiry_f < 0:
                score += 3
            elif expiry_f < 15:
                score += 1
        except (TypeError, ValueError):
            pass
    if _to_int_bool(norm_record.get("cert_self_signed"), default=0) == 1:
        score += 2
    if _to_int_bool(norm_record.get("downgrade_attack_detected"), default=0) == 1:
        score += 4
    if _to_int_bool(norm_record.get("mitm_indicators"), default=0) == 1:
        score += 5
    if norm_record.get("starttls_used") is False:
        score += 2

    if score >= 8:
        return "Critical"
    if score >= 5:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"


def build_preprocessor():
    numeric_pipe = Pipeline(steps=[
        ("impute", SimpleImputer(strategy="median")),
    ])
    categorical_pipe = Pipeline(steps=[
        ("impute", SimpleImputer(strategy="most_frequent")),
        ("onehot", OneHotEncoder(handle_unknown="ignore")),
    ])
    ct = ColumnTransformer(transformers=[
        ("num", numeric_pipe, NUMERIC_FEATURES),
        ("cat", categorical_pipe, CATEGORICAL_FEATURES),
    ])
    return ct


def get_label(norm_record: dict) -> str:
    """Use the real 'label' field when the record has one (real data from
    the Ubuntu tool); otherwise fall back to rule-based weak supervision
    (synthetic data)."""
    real_label = norm_record.get("label")
    if real_label is not None and str(real_label).strip():
        return str(real_label).strip()
    return rule_based_risk_label(norm_record)


def main():
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
    synthetic_path = os.path.join(data_dir, "synthetic_dataset.json")
    real_path = os.path.join(data_dir, "real_dataset.json")

    with open(synthetic_path) as f:
        raw_records = json.load(f)
    print(f"Loaded {len(raw_records)} synthetic records")

    # If you've run `python3 data/load_real_csv.py your_export.csv`, merge in
    # whatever real rows exist. Their genuine 'label' values are used as-is
    # (see get_label above) instead of the rule-based fallback.
    if os.path.exists(real_path):
        with open(real_path) as f:
            real_records = json.load(f)
        print(f"Loaded {len(real_records)} real records from {real_path}")
        raw_records = raw_records + real_records

    # Labels: real 'label' field when present, else rule-based weak supervision
    labels = [get_label(normalize_record(r)) for r in raw_records]
    distinct_labels = sorted(set(labels))
    print(f"\nLabel classes present: {distinct_labels}")
    if any(l not in ("Low", "Medium", "High", "Critical") for l in distinct_labels):
        print(
            "NOTE: some labels come from the real dataset's own vocabulary "
            "(e.g. 'vulnerable') rather than Low/Medium/High/Critical. "
            "If you want ONE consistent risk scale, either (a) ask your "
            "teammates what label taxonomy the real tool uses and map it "
            "onto Low/Medium/High/Critical before training, or (b) just "
            "train on whatever labels you have -- the code below doesn't "
            "care what the label strings are, it'll classify into whatever "
            "distinct values are present."
        )

    # Features
    df = records_to_feature_df(raw_records)

    ct = build_preprocessor()
    X = ct.fit_transform(df)
    if hasattr(X, "toarray"):
        X = X.toarray()

    feature_names_out = list(ct.get_feature_names_out())

    le = LabelEncoder()
    y = le.fit_transform(labels)

    print("Label distribution:", pd.Series(labels).value_counts().to_dict())

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42,
        stratify=y if min(np.bincount(y)) >= 2 else None,
    )

    rf = RandomForestClassifier(
        n_estimators=300, max_depth=12, random_state=42, class_weight="balanced_subsample"
    )
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    print("\n=== RandomForest classification report (held-out test set) ===")
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    print("Accuracy:", accuracy_score(y_test, y_pred))

    # IsolationForest: unsupervised anomaly detector trained on ALL features
    iso = IsolationForest(
        n_estimators=200, contamination=0.08, random_state=42
    )
    iso.fit(X)

    # Save everything
    preprocessor = SecureMailPreprocessor(column_transformer=ct, feature_names_out=feature_names_out)
    preprocessor.save(os.path.join(SAVE_DIR, "preprocessor.pkl"))
    joblib.dump(rf, os.path.join(SAVE_DIR, "rf_model.pkl"))
    joblib.dump(iso, os.path.join(SAVE_DIR, "iso_model.pkl"))
    joblib.dump(le, os.path.join(SAVE_DIR, "label_encoder.pkl"))

    metadata = {
        "n_training_records": len(raw_records),
        "label_classes": list(le.classes_),
        "numeric_features": NUMERIC_FEATURES,
        "categorical_features": CATEGORICAL_FEATURES,
        "feature_names_out": feature_names_out,
        "notes": "Labels generated via rule-based weak supervision (no real analyst "
                 "labels available yet). Replace data/synthetic_dataset.json + "
                 "rule_based_risk_label with real labeled data when available and "
                 "re-run this script; API/dashboard code needs no changes.",
    }
    with open(os.path.join(SAVE_DIR, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nSaved preprocessor + models to {SAVE_DIR}")


if __name__ == "__main__":
    main()
