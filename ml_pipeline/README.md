# BankGuard ML Phishing URL Detection Pipeline

## Overview

This pipeline trains an XGBoost classifier to detect phishing URLs using 41 engineered features - lexical analysis, domain structure, Shannon entropy, Levenshtein brand similarity, and suspicious keyword patterns. It replaces the backend's hardcoded heuristic keyword matching with a model that learns phishing patterns from real data.

**Why XGBoost?** Handles mixed feature types well, robust to outliers, provides native feature importance for explainability, trains fast (~15 min), and serializes to a small file (~1MB) suitable for production.

## Quick Start

```bash
# 1. Setup
cd ml_pipeline
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Full pipeline (single command)
python src/retrain.py --download-fresh-data --evaluate --export --deploy

# 3. Or run steps individually:
python src/data_collection.py      # Download datasets -> data/processed/labeled_urls.csv
python src/train.py                # Train + tune -> models/xgb_phishing_model.pkl
python src/evaluate.py             # Evaluate -> models/evaluation_report.txt
python src/export.py               # Validate -> "EXPORT VALIDATION PASSED"
```

## Data Sources

| Source | Type | ~Count |
|--------|------|--------|
| [PhishTank](http://data.phishtank.com) | Phishing | 50K+ verified |
| [OpenPhish](https://openphish.com/feed.txt) | Phishing | ~500 active |
| [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) | Phishing | 50K+ active |
| India-specific curated | Phishing | 250 SBI/YONO patterns |
| [Tranco Top 1M](https://tranco-list.eu) | Legitimate | 100K sampled |
| Indian banking/gov curated | Legitimate | 65 critical domains |

Final dataset is balanced to ~60% phishing / 40% legitimate.

## Features (41 total)

| Category | Features | Example |
|----------|----------|---------|
| Lexical (13) | url_length, digit_ratio, num_hyphens... | Long URLs with many digits -> phishing signal |
| Domain (7) | subdomain_count, tld_is_high_risk... | `.xyz` TLD -> high risk |
| Entropy (3) | url_entropy, domain_entropy, path_entropy | High entropy -> random/obfuscated domain |
| Brand Similarity (6) | lev_dist_sbi, contains_sbi_keyword... | Domain close to "sbi" + risky TLD -> impersonation |
| Suspicious Patterns (9) | contains_kyc_keyword, has_login_path... | KYC + urgency keywords -> social engineering |
| Statistical (3) | consonant_vowel_ratio, longest_word_length... | Random domain tokens -> DGA-generated |

## Target Metrics

| Metric | Target | Description |
|--------|--------|-------------|
| AUC-ROC | > 0.97 | Overall discrimination ability |
| Recall | > 0.95 | Catch 95%+ of phishing URLs |
| FPR | < 0.05 | Flag <5% of legitimate URLs |

## Backend Integration

The trained model slots into the backend at `backend/ml/`. At startup, `main.py` loads the classifier once and uses it for all `/api/check-url` requests. If the model file is missing, the backend falls back to heuristic keyword matching automatically.

The response includes an `ml_analysis` field with model confidence, raw probability, top 5 decision factors, and threshold used - providing full explainability.

## Retraining

Phishing patterns evolve. Retrain periodically:

```bash
python src/retrain.py --download-fresh-data --evaluate --export --deploy
```

## Known Limitations

- **No DNS/WHOIS features** - would improve accuracy but adds latency and external dependency
- **No real-time feed integration** - model is retrained offline, not continuously learning
- **Threshold sensitivity** - optimal threshold is dataset-dependent; review after retraining
- **URL shortener handling** - shortened URLs are flagged by `is_url_shortener` but not unshortened
