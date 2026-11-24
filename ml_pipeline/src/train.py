"""
Model Training Script - XGBoost + Optuna Hyperparameter Tuning.

Trains an XGBoost classifier on the labeled URL dataset, using
Optuna for efficient hyperparameter search.

Usage:
    python src/train.py

Outputs:
    models/xgb_phishing_model.pkl   - Trained model
    models/best_params.json         - Best hyperparameters
"""

import os
import json
import logging
import numpy as np
import pandas as pd
import joblib
import optuna
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
from xgboost import XGBClassifier

# Local imports - add parent dir so this works standalone
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_engineering import extract_features, FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)
optuna.logging.set_verbosity(optuna.logging.WARNING)

# Reproducibility - fixed seed documented here
RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "processed", "labeled_urls.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")


def load_and_featurize(data_path: str) -> tuple:
    """Load CSV, extract features, return X (DataFrame) and y (Series)."""
    logger.info(f"Loading dataset from {data_path}...")
    df = pd.read_csv(data_path)
    logger.info(f"Dataset size: {len(df)} samples")

    logger.info("Extracting features (this may take a few minutes)...")
    feature_dicts = []
    for i, url in enumerate(df["url"]):
        if i % 10000 == 0 and i > 0:
            logger.info(f"  Processed {i}/{len(df)} URLs...")
        try:
            features = extract_features(str(url))
        except Exception:
            features = {name: 0.0 for name in FEATURE_NAMES}
        feature_dicts.append(features)

    X = pd.DataFrame(feature_dicts, columns=FEATURE_NAMES)
    y = df["label"].astype(int)

    logger.info(f"Feature matrix shape: {X.shape}")
    return X, y


def split_data(X, y):
    """Split into train (70%), validation (15%), test (15%) with stratification."""
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, random_state=RANDOM_SEED, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.1765,  # 0.1765 of 85% ≈ 15%
        random_state=RANDOM_SEED, stratify=y_train_val
    )
    logger.info(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
    return X_train, X_val, X_test, y_train, y_val, y_test


def run_optuna_tuning(X_train, y_train, X_val, y_val, n_trials: int = 50) -> dict:
    """Run Optuna hyperparameter search, return best params."""
    scale_pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
    logger.info(f"Calculated scale_pos_weight: {scale_pos_weight:.3f}")

    def objective(trial):
        params = {
            "n_estimators": trial.suggest_int("n_estimators", 100, 1000),
            "max_depth": trial.suggest_int("max_depth", 3, 10),
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
            "gamma": trial.suggest_float("gamma", 0, 5),
            "scale_pos_weight": scale_pos_weight,
            "eval_metric": "auc",
            "random_state": RANDOM_SEED,
            "verbosity": 0,
            "use_label_encoder": False,
        }
        model = XGBClassifier(**params)
        model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)
        y_pred_proba = model.predict_proba(X_val)[:, 1]
        return roc_auc_score(y_val, y_pred_proba)

    logger.info(f"Starting Optuna hyperparameter tuning ({n_trials} trials)...")
    study = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=RANDOM_SEED))
    study.optimize(objective, n_trials=n_trials, show_progress_bar=True)

    logger.info(f"Best AUC-ROC on validation: {study.best_value:.4f}")
    logger.info(f"Best params: {study.best_params}")

    best_params = study.best_params
    best_params["scale_pos_weight"] = scale_pos_weight
    best_params["random_state"] = RANDOM_SEED
    best_params["eval_metric"] = "auc"
    best_params["verbosity"] = 0
    best_params["use_label_encoder"] = False

    return best_params


def train_final_model(X_train, y_train, X_val, y_val, best_params: dict) -> XGBClassifier:
    """Retrain on combined train+val with best hyperparameters."""
    X_combined = pd.concat([X_train, X_val], ignore_index=True)
    y_combined = pd.concat([y_train, y_val], ignore_index=True)

    logger.info(f"Training final model on {len(X_combined)} samples...")
    model = XGBClassifier(**best_params)
    model.fit(X_combined, y_combined, verbose=False)
    logger.info("Final model trained successfully.")
    return model


def main(skip_tuning: bool = False):
    os.makedirs(MODELS_DIR, exist_ok=True)

    # Load and featurize
    X, y = load_and_featurize(DATA_PATH)

    # Split
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(X, y)

    # Save test set for evaluation
    test_data = X_test.copy()
    test_data["label"] = y_test.values
    test_data.to_csv(os.path.join(MODELS_DIR, "test_set.csv"), index=False)

    params_path = os.path.join(MODELS_DIR, "best_params.json")

    if skip_tuning and os.path.exists(params_path):
        # Load saved params but recalculate scale_pos_weight for the new data
        logger.info("Loading saved best params (--skip-tuning enabled)...")
        with open(params_path, "r", encoding="utf-8") as f:
            best_params = json.load(f)
        # recalc for new dataset ratio -- this matters since we added more legit data
        new_spw = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
        logger.info(f"Recalculated scale_pos_weight: {new_spw:.3f} (was {best_params.get('scale_pos_weight', 'N/A')})")
        best_params["scale_pos_weight"] = new_spw
    else:
        if skip_tuning:
            logger.warning("--skip-tuning was set but no best_params.json found, running Optuna anyway")
        # Optuna tuning
        best_params = run_optuna_tuning(X_train, y_train, X_val, y_val, n_trials=50)

    # Save best params
    with open(params_path, "w", encoding="utf-8") as f:
        json.dump(best_params, f, indent=2)
    logger.info(f"Best params saved to {params_path}")

    # Train final model on train+val
    model = train_final_model(X_train, y_train, X_val, y_val, best_params)

    # Save model
    model_path = os.path.join(MODELS_DIR, "xgb_phishing_model.pkl")
    joblib.dump(model, model_path)
    logger.info(f"Model saved to {model_path}")

    # Save feature names
    fn_path = os.path.join(MODELS_DIR, "feature_names.json")
    with open(fn_path, "w", encoding="utf-8") as f:
        json.dump(FEATURE_NAMES, f, indent=2)
    logger.info(f"Feature names saved to {fn_path}")

    # Quick stats
    y_pred_proba = model.predict_proba(X_test.values)[:, 1]
    test_auc = roc_auc_score(y_test, y_pred_proba)
    logger.info(f"Quick test AUC-ROC: {test_auc:.4f}")


if __name__ == "__main__":
    main()

