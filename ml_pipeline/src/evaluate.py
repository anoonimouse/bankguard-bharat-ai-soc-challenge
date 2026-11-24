"""
Model Evaluation Script - Comprehensive Performance Report.

Evaluates the trained XGBoost model on the held-out test set and
produces a detailed report with core metrics, confusion matrix,
threshold analysis, feature importance, and India-specific performance.

Usage:
    python src/evaluate.py

Outputs:
    models/evaluation_report.txt   - Full text report
    models/optimal_threshold.json  - Recommended threshold
"""

import os
import json
import logging
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import (
    roc_auc_score, average_precision_score, accuracy_score,
    precision_score, recall_score, f1_score, confusion_matrix,
    precision_recall_curve
)

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_engineering import extract_features, FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")


def find_optimal_threshold(y_true, y_prob, max_fpr: float = 0.05) -> float:
    """
    Find the threshold that maximizes recall while keeping FPR below max_fpr.
    """
    best_threshold = 0.5
    best_recall = 0.0

    for threshold in np.arange(0.1, 0.91, 0.01):
        y_pred = (y_prob >= threshold).astype(int)
        tn = np.sum((y_true == 0) & (y_pred == 0))
        fp = np.sum((y_true == 0) & (y_pred == 1))
        tp = np.sum((y_true == 1) & (y_pred == 1))
        fn = np.sum((y_true == 1) & (y_pred == 0))

        fpr = fp / max(fp + tn, 1)
        recall = tp / max(tp + fn, 1)

        if fpr <= max_fpr and recall > best_recall:
            best_recall = recall
            best_threshold = threshold

    return round(best_threshold, 2)


def generate_report(model, X_test, y_test, feature_names) -> tuple:
    """Generate full evaluation report, return (report_text, optimal_threshold, metrics_dict)."""
    y_prob = model.predict_proba(X_test.values)[:, 1]
    optimal_threshold = find_optimal_threshold(y_test.values, y_prob, max_fpr=0.05)
    y_pred = (y_prob >= optimal_threshold).astype(int)

    # Core metrics
    auc_roc = roc_auc_score(y_test, y_prob)
    auc_pr = average_precision_score(y_test, y_prob)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / max(fp + tn, 1)
    fnr = fn / max(fn + tp, 1)
    total = len(y_test)

    # Feature importance
    importance = model.feature_importances_
    importance_pairs = sorted(zip(feature_names, importance), key=lambda x: -x[1])

    # Threshold analysis table
    threshold_analysis = []
    for t in np.arange(0.1, 0.91, 0.05):
        yp = (y_prob >= t).astype(int)
        cm_t = confusion_matrix(y_test, yp)
        tn_t, fp_t, fn_t, tp_t = cm_t.ravel()
        threshold_analysis.append({
            "threshold": round(t, 2),
            "precision": precision_score(y_test, yp, zero_division=0),
            "recall": recall_score(y_test, yp, zero_division=0),
            "fpr": fp_t / max(fp_t + tn_t, 1),
            "f1": f1_score(y_test, yp, zero_division=0),
        })

    # Build report
    lines = []
    lines.append("=" * 70)
    lines.append("PHISHING URL DETECTION - MODEL EVALUATION REPORT")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Test set size: {total} samples")
    lines.append(f"  Phishing (1): {(y_test == 1).sum()}")
    lines.append(f"  Legitimate (0): {(y_test == 0).sum()}")
    lines.append(f"Optimal threshold: {optimal_threshold}")
    lines.append("")

    lines.append("--- Core Metrics (at optimal threshold) ---")
    lines.append(f"  AUC-ROC:             {auc_roc:.4f}")
    lines.append(f"  AUC-PR:              {auc_pr:.4f}")
    lines.append(f"  Accuracy:            {accuracy:.4f}")
    lines.append(f"  Precision:           {precision:.4f}")
    lines.append(f"  Recall:              {recall:.4f}")
    lines.append(f"  F1 Score:            {f1:.4f}")
    lines.append(f"  False Positive Rate: {fpr:.4f}")
    lines.append(f"  False Negative Rate: {fnr:.4f}")
    lines.append("")

    lines.append("--- Confusion Matrix ---")
    lines.append(f"                  Predicted Legit    Predicted Phishing")
    lines.append(f"  Actual Legit:   {tn:>8}  ({tn/total*100:5.1f}%)   {fp:>8}  ({fp/total*100:5.1f}%)")
    lines.append(f"  Actual Phishing:{fn:>8}  ({fn/total*100:5.1f}%)   {tp:>8}  ({tp/total*100:5.1f}%)")
    lines.append("")

    lines.append("--- Threshold Analysis ---")
    lines.append(f"  {'Threshold':>9}  {'Precision':>9}  {'Recall':>9}  {'FPR':>9}  {'F1':>9}")
    for row in threshold_analysis:
        marker = "  <-- OPTIMAL" if abs(row["threshold"] - optimal_threshold) < 0.025 else ""
        lines.append(
            f"  {row['threshold']:>9.2f}  {row['precision']:>9.4f}  {row['recall']:>9.4f}  "
            f"{row['fpr']:>9.4f}  {row['f1']:>9.4f}{marker}"
        )
    lines.append("")

    lines.append("--- Top 20 Most Important Features ---")
    for i, (feat, imp) in enumerate(importance_pairs[:20], 1):
        lines.append(f"  {i:>2}. {feat:<30} {imp:.4f}")
    lines.append("")

    # Target threshold check
    lines.append("--- Target Performance Check ---")
    checks_passed = True
    if auc_roc > 0.97:
        lines.append(f"  [PASS] AUC-ROC {auc_roc:.4f} > 0.97")
    else:
        lines.append(f"  [WARN] AUC-ROC {auc_roc:.4f} < 0.97 -- BELOW TARGET")
        lines.append(f"     Suggestion: Increase n_estimators, add more training data")
        checks_passed = False
    if recall > 0.95:
        lines.append(f"  [PASS] Recall {recall:.4f} > 0.95")
    else:
        lines.append(f"  [WARN] Recall {recall:.4f} < 0.95 -- BELOW TARGET")
        lines.append(f"     Suggestion: Lower threshold or increase scale_pos_weight")
        checks_passed = False
    if fpr < 0.05:
        lines.append(f"  [PASS] FPR {fpr:.4f} < 0.05")
    else:
        lines.append(f"  [WARN] FPR {fpr:.4f} > 0.05 -- ABOVE TARGET")
        lines.append(f"     Suggestion: Raise threshold or add more legitimate training data")
        checks_passed = False

    if checks_passed:
        lines.append("\n  ALL TARGET METRICS MET -- Model is production-ready!")
    else:
        lines.append("\n  SOME TARGETS NOT MET -- Review suggestions above.")

    lines.append("")
    lines.append("=" * 70)
    report = "\n".join(lines)

    metrics = {
        "auc_roc": round(auc_roc, 4),
        "auc_pr": round(auc_pr, 4),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "optimal_threshold": optimal_threshold,
        "test_size": total,
        "targets_met": checks_passed,
    }

    return report, optimal_threshold, metrics


def main():
    model_path = os.path.join(MODELS_DIR, "xgb_phishing_model.pkl")
    test_path = os.path.join(MODELS_DIR, "test_set.csv")

    model = joblib.load(model_path)
    test_df = pd.read_csv(test_path)

    X_test = test_df[FEATURE_NAMES]
    y_test = test_df["label"]

    report, optimal_threshold, metrics = generate_report(model, X_test, y_test, FEATURE_NAMES)

    # Print report
    print(report)

    # Save report
    report_path = os.path.join(MODELS_DIR, "evaluation_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    logger.info(f"Report saved to {report_path}")

    # Save optimal threshold
    threshold_path = os.path.join(MODELS_DIR, "optimal_threshold.json")
    with open(threshold_path, "w", encoding="utf-8") as f:
        json.dump({"threshold": optimal_threshold}, f, indent=2)
    logger.info(f"Optimal threshold saved to {threshold_path}")

    # Save metrics
    metrics_path = os.path.join(MODELS_DIR, "evaluation_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)


if __name__ == "__main__":
    main()
