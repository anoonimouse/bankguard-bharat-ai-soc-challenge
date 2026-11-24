"""
Retrain Utility -- Run the full pipeline end to end.

Usage:
    python src/retrain.py --download-fresh-data --skip-tuning --evaluate --export --deploy

Flags:
    --download-fresh-data   Re-run data collection for latest phishing feeds
    --skip-tuning           Use saved best_params.json instead of running Optuna
    --evaluate              Run full evaluation and save report
    --export                Export model artifacts with validation gate
    --deploy                Copy artifacts to backend/ml/ directory
"""

import os
import sys
import shutil
import argparse
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_ML_DIR = os.path.join(BASE_DIR, "..", "backend", "ml")
MODELS_DIR = os.path.join(BASE_DIR, "models")

# Add src to path
sys.path.insert(0, os.path.join(BASE_DIR, "src"))


def main():
    parser = argparse.ArgumentParser(description="Retrain the phishing URL detection model")
    parser.add_argument("--download-fresh-data", action="store_true",
                        help="Re-download training data from public sources")
    parser.add_argument("--skip-tuning", action="store_true",
                        help="Use saved best_params.json instead of running Optuna (~11 min faster)")
    parser.add_argument("--evaluate", action="store_true",
                        help="Run full evaluation after training")
    parser.add_argument("--export", action="store_true",
                        help="Export model artifacts with validation")
    parser.add_argument("--deploy", action="store_true",
                        help="Copy artifacts to backend/ml/ directory")
    args = parser.parse_args()

    # Step 1: Data collection
    if args.download_fresh_data:
        logger.info("=" * 60)
        logger.info("STEP 1: Data Collection")
        logger.info("=" * 60)
        from data_collection import main as collect_data
        collect_data()
    else:
        logger.info("Skipping data collection (use --download-fresh-data to enable)")

    # Step 2: Training
    logger.info("=" * 60)
    logger.info("STEP 2: Model Training")
    logger.info("=" * 60)
    from train import main as train_model
    train_model(skip_tuning=args.skip_tuning)

    # Step 3: Evaluation
    if args.evaluate:
        logger.info("=" * 60)
        logger.info("STEP 3: Evaluation")
        logger.info("=" * 60)
        from evaluate import main as evaluate_model
        evaluate_model()
    else:
        logger.info("Skipping evaluation (use --evaluate to enable)")

    # Step 4: Export
    if args.export:
        logger.info("=" * 60)
        logger.info("STEP 4: Export & Validation")
        logger.info("=" * 60)
        from export import main as export_model
        export_model()
    else:
        logger.info("Skipping export (use --export to enable)")

    # Step 5: Deploy to backend
    if args.deploy:
        logger.info("=" * 60)
        logger.info("STEP 5: Deploy to Backend")
        logger.info("=" * 60)
        deploy_to_backend()


def deploy_to_backend():
    """Copy model artifacts to backend/ml/ directory."""
    os.makedirs(BACKEND_ML_DIR, exist_ok=True)

    artifacts = [
        "xgb_phishing_model.pkl",
        "feature_names.json",
        "optimal_threshold.json",
        "model_metadata.json",
        "feature_engineering.py",
        "whitelist.py",
    ]

    for artifact in artifacts:
        src = os.path.join(MODELS_DIR, artifact)
        dst = os.path.join(BACKEND_ML_DIR, artifact)
        if os.path.exists(src):
            shutil.copy2(src, dst)
            logger.info(f"  Copied {artifact} -> backend/ml/")
        else:
            logger.warning(f"  Missing {artifact} -- skipped")

    logger.info("Deployment complete!")


if __name__ == "__main__":
    main()
