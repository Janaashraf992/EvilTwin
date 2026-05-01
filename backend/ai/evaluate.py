"""
Cross-validation and classification report for the EvilTwin threat model.
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_val_predict

from ai.feature_extractor import FEATURES
from ai.train import generate_synthetic_data, train_model


TARGET_NAMES = ["benign", "low", "medium", "high", "critical"]


def evaluate_model() -> None:
    """Run stratified 5-fold cross-validation and print detailed metrics."""
    X, y = generate_synthetic_data()

    pipeline = train_model()

    # Cross-validated predictions for unbiased evaluation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    y_pred = cross_val_predict(pipeline, X, y, cv=cv)

    print("=" * 60)
    print("CLASSIFICATION REPORT (5-fold cross-validated)")
    print("=" * 60)
    print(classification_report(y, y_pred, target_names=TARGET_NAMES, digits=3))

    print("=" * 60)
    print("CONFUSION MATRIX")
    print("=" * 60)
    cm = confusion_matrix(y, y_pred)
    header = "        " + "  ".join(f"{name:>8s}" for name in TARGET_NAMES)
    print(header)
    for i, row in enumerate(cm):
        cells = "  ".join(f"{v:8d}" for v in row)
        print(f"{TARGET_NAMES[i]:>8s}  {cells}")

    print("\n" + "=" * 60)
    print("FEATURE IMPORTANCES")
    print("=" * 60)
    clf = pipeline.named_steps["classifier"]
    importances = clf.feature_importances_
    for idx, score in sorted(enumerate(importances), key=lambda x: x[1], reverse=True):
        bar = "█" * int(score * 50)
        print(f"  {FEATURES[idx]:<25s} {score:.4f}  {bar}")

    # Per-class accuracy
    print("\n" + "=" * 60)
    print("PER-CLASS ACCURACY")
    print("=" * 60)
    for i, name in enumerate(TARGET_NAMES):
        mask = y == i
        acc = np.mean(y_pred[mask] == i) if mask.sum() > 0 else 0.0
        print(f"  {name:<10s}  {acc:.1%}  (n={mask.sum()})")


if __name__ == "__main__":
    evaluate_model()
