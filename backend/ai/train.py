from __future__ import annotations

import os

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ai.feature_extractor import FEATURES

N_FEATURES = 21


def _class_samples(rng: np.random.Generator, n: int, label: int) -> tuple[np.ndarray, np.ndarray]:
    X = np.zeros((n, N_FEATURES), dtype=float)

    if label == 0:
        duration = rng.uniform(5, 30, size=n)
        cmd = rng.integers(1, 4, size=n)
        canary_triggered = 0.0
        canary_diff = 0.0
        canary_count = 0.0
        canary_cumulative = 0.0
    elif label == 1:
        duration = rng.uniform(30, 120, size=n)
        cmd = rng.integers(3, 11, size=n)
        canary_triggered = rng.binomial(1, 0.3, size=n).astype(float)
        canary_diff = canary_triggered * rng.integers(1, 3, size=n)
        canary_count = canary_triggered * rng.integers(1, 3, size=n)
        canary_cumulative = canary_triggered * rng.uniform(0.05, 0.25, size=n)
    elif label == 2:
        duration = rng.uniform(120, 300, size=n)
        cmd = rng.integers(10, 31, size=n)
        canary_triggered = rng.binomial(1, 0.6, size=n).astype(float)
        canary_diff = canary_triggered * rng.integers(1, 4, size=n)
        canary_count = canary_triggered * rng.integers(1, 5, size=n)
        canary_cumulative = canary_triggered * rng.uniform(0.15, 0.50, size=n)
    elif label == 3:
        duration = rng.uniform(300, 900, size=n)
        cmd = rng.integers(30, 81, size=n)
        canary_triggered = rng.binomial(1, 0.8, size=n).astype(float)
        canary_diff = canary_triggered * rng.integers(2, 5, size=n)
        canary_count = canary_triggered * rng.integers(2, 8, size=n)
        canary_cumulative = canary_triggered * rng.uniform(0.30, 0.80, size=n)
    else:
        duration = rng.uniform(900, 1800, size=n)
        cmd = rng.integers(80, 140, size=n)
        canary_triggered = 1.0
        canary_diff = rng.integers(3, 5, size=n).astype(float)
        canary_count = rng.integers(5, 20, size=n).astype(float)
        canary_cumulative = rng.uniform(0.60, 1.00, size=n)

    X[:, 0] = cmd
    X[:, 1] = rng.uniform(0.2, 1.0, size=n)
    X[:, 2] = float(label >= 2)
    X[:, 3] = float(label >= 3)
    X[:, 4] = float(label >= 2)
    X[:, 5] = duration
    X[:, 6] = rng.uniform(2, 30, size=n)
    X[:, 7] = rng.integers(0, 24, size=n).astype(float)
    X[:, 8] = rng.integers(0, 2, size=n).astype(float)
    X[:, 9] = rng.binomial(1, 0.1 + (0.15 * label), size=n).astype(float)
    X[:, 10] = rng.binomial(1, 0.05 + (0.1 * label), size=n).astype(float)
    X[:, 11] = rng.integers(0, 2 + label * 2, size=n).astype(float)
    X[:, 12] = rng.integers(0, max(1, label), size=n).astype(float)
    X[:, 13] = rng.integers(0, max(1, label), size=n).astype(float)
    X[:, 14] = rng.binomial(1, 0.02 + (0.2 * label), size=n).astype(float)
    X[:, 15] = rng.binomial(1, 0.05 + (0.1 * label), size=n).astype(float)
    X[:, 16] = canary_triggered
    X[:, 17] = canary_diff
    X[:, 18] = canary_count
    X[:, 19] = canary_cumulative
    X[:, 20] = rng.exponential(300.0 * (5 - label) / 5, size=n)

    X += rng.normal(0, 0.02, size=X.shape)
    X[:, 5] = np.clip(X[:, 5], 1.0, None)
    X[:, 6] = np.clip(X[:, 6], 0.0, None)
    X[:, 17] = np.clip(X[:, 17], 0.0, 4.0)
    X[:, 18] = np.clip(X[:, 18], 0.0, 50.0)
    X[:, 19] = np.clip(X[:, 19], 0.0, 1.0)
    X[:, 20] = np.clip(X[:, 20], 0.0, 86400.0)

    y = np.full((n,), label, dtype=int)
    return X, y


def generate_synthetic_data(seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    configs = {0: 400, 1: 600, 2: 500, 3: 300, 4: 200}

    X_parts = []
    y_parts = []
    for label, count in configs.items():
        X, y = _class_samples(rng, count, label)
        X_parts.append(X)
        y_parts.append(y)

    X_all = np.vstack(X_parts)
    y_all = np.concatenate(y_parts)

    idx = rng.permutation(len(y_all))
    return X_all[idx], y_all[idx]


def train_model() -> Pipeline:
    X, y = generate_synthetic_data()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    pipeline = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=300,
                    class_weight="balanced",
                    random_state=42,
                    max_depth=20,
                    min_samples_split=5,
                ),
            ),
        ]
    )

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    print(classification_report(y_test, y_pred, digits=3))

    clf = pipeline.named_steps["classifier"]
    importances = clf.feature_importances_
    for i, score in sorted(enumerate(importances), key=lambda x: x[1], reverse=True):
        print(f"{FEATURES[i]:<30s} {score:.4f}")

    cv_scores = cross_val_score(pipeline, X, y, cv=5)
    print(f"Cross-validation score: mean={cv_scores.mean():.4f} std={cv_scores.std():.4f}")

    model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
    joblib.dump(pipeline, model_path)
    print(f"Saved model to {model_path}")

    return pipeline


if __name__ == "__main__":
    train_model()
