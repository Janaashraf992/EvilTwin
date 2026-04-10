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


def _class_samples(rng: np.random.Generator, n: int, label: int) -> tuple[np.ndarray, np.ndarray]:
    X = np.zeros((n, 16), dtype=float)

    if label == 0:
        duration = rng.uniform(5, 30, size=n)
        cmd = rng.integers(1, 4, size=n)
    elif label == 1:
        duration = rng.uniform(30, 120, size=n)
        cmd = rng.integers(3, 11, size=n)
    elif label == 2:
        duration = rng.uniform(120, 300, size=n)
        cmd = rng.integers(10, 31, size=n)
    elif label == 3:
        duration = rng.uniform(300, 900, size=n)
        cmd = rng.integers(30, 81, size=n)
    else:
        duration = rng.uniform(900, 1800, size=n)
        cmd = rng.integers(80, 140, size=n)

    X[:, 0] = cmd
    X[:, 1] = rng.uniform(0.2, 1.0, size=n)
    X[:, 2] = (label >= 2).astype(float) if isinstance(label, np.ndarray) else float(label >= 2)
    X[:, 3] = float(label >= 3)
    X[:, 4] = float(label >= 2)
    X[:, 5] = duration
    X[:, 6] = cmd / (duration / 60.0)
    X[:, 7] = rng.integers(0, 24, size=n)
    X[:, 8] = rng.integers(0, 2, size=n)
    X[:, 9] = rng.binomial(1, 0.1 + (0.15 * label), size=n)
    X[:, 10] = rng.binomial(1, 0.05 + (0.1 * label), size=n)
    X[:, 11] = rng.integers(0, 2 + label * 2, size=n)
    X[:, 12] = rng.integers(0, max(1, label), size=n)
    X[:, 13] = rng.integers(0, max(1, label), size=n)
    X[:, 14] = rng.binomial(1, 0.02 + (0.2 * label), size=n)
    X[:, 15] = rng.binomial(1, 0.05 + (0.1 * label), size=n)

    X += rng.normal(0, 0.02, size=X.shape)
    X[:, 5] = np.clip(X[:, 5], 1.0, None)
    X[:, 6] = np.clip(X[:, 6], 0.0, None)

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
        print(f"{FEATURES[i]}: {score:.4f}")

    cv_scores = cross_val_score(pipeline, X, y, cv=5)
    print(f"Cross-validation score: mean={cv_scores.mean():.4f} std={cv_scores.std():.4f}")

    model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
    joblib.dump(pipeline, model_path)
    print(f"Saved model to {model_path}")

    return pipeline


if __name__ == "__main__":
    train_model()
