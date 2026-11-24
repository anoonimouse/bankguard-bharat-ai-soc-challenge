# BankGuard ML Training Pipeline

Fine-tune IndicBERT v2 to detect phishing/scam SMS messages written in **Romanized Indian languages** (Hinglish, Tanglish, Tenglish, Banglish, Marathlish, Kanglish, Manglish, Punglish).

> Native script detection (Hindi Devanagari, Tamil, Telugu, etc.) is already handled by IndicBERT v2's pre-trained vocabulary. This pipeline targets the gap: code-mixed Romanized text that neither pure English models nor native-script models handle well.

---

## Attack Categories Covered

Mapped directly from `ScamTriggers.kt`:

| # | Category | Example |
|---|---|---|
| 1 | urgency / KYC expiry | "aapka KYC expire ho gaya" |
| 2 | fear / security breach | "unauthorized transaction detected" |
| 3 | greed / lottery-reward | "aapne 50,000 jeeta hai" |
| 4 | authority / digital arrest | "CBI officer calling, illegal parcel" |
| 5 | utility / bill scam | "bijli cut ho jayegi aaj raat" |
| 6 | opportunity / job scam | "ghar baithe 5000 roz kamao" |
| 7 | scheme / govt subsidy | "PM Kisan installment link pe click karo" |
| 8 | challan / traffic fine | "e-challan pending hai turant pay karo" |
| 9 | migration / bank domain | "SBI ne naya portal launch kiya, migrate karo" |
| 10 | APK sideloading | "nayi YONO app download karo is link se" |
| 11 | remote access | "AnyDesk install karo, SBI agent help karega" |
| 12 | OTP harvesting | "OTP batao, account verify karna hai" |

---

## Romanized Language Variants Targeted

| Native Language | Romanized Name | Example |
|---|---|---|
| Hindi | Hinglish | "abhi click karo nahi toh band ho jayega" |
| Tamil | Tanglish | "ungal account block aaidum, click pannunga" |
| Telugu | Tenglish | "mee account block avutundi, click cheyandi" |
| Bengali | Banglish | "aapnar account bondho hoye jabe, click korun" |
| Marathi | Marathlish | "tumcha account band hoil, click kara" |
| Kannada | Kanglish | "nimma account block aguttade, click madi" |
| Malayalam | Manglish | "ningalude account block aakum, click cheyyuka" |
| Punjabi | Punglish | "tera account band ho javega, click kar" |

---

## Directory Structure

```
ml_training/
├── README.md                  # This file
├── generate_dataset.py        # Generates ~10,000 row labeled CSV
├── split_dataset.py           # Splits into train/val/test
├── finetune.py                # Fine-tunes IndicBERT v2 on generated CSV
├── export_onnx.py             # Exports quantized ONNX for Android ORT
└── data/                      # Output directory (git-ignored)
    ├── raw_dataset.csv
    ├── train.csv
    ├── val.csv
    └── test.csv
```

---

## Usage

### Step 1 — Generate dataset
```bash
python generate_dataset.py
# Outputs: data/raw_dataset.csv (~10,000 rows)
```

### Step 2 — Split
```bash
python split_dataset.py
# Outputs: data/train.csv (7000), data/val.csv (1500), data/test.csv (1500)
```

### Step 3 — Fine-tune
```bash
pip install transformers datasets torch scikit-learn
python finetune.py
# Outputs: models/indicbert_bankguard_finetuned/
```

### Step 4 — Export ONNX
```bash
pip install optimum onnx onnxruntime
python export_onnx.py
# Outputs: models/indicbert_bankguard_quantized.onnx (~18MB)
```

### Step 5 — Deploy to Android
Copy `indicbert_bankguard_quantized.onnx` and `sentencepiece.bpe.model` into:
```
bankguard_sdk/android/src/main/assets/
```
Then update `LocalPhishingTextAnalyzer.kt` to load the new model file.

---

## Notes

- Do NOT commit the `data/` directory — datasets can be regenerated
- Minimum recommended GPU: Any CUDA GPU with 8GB VRAM, or use Google Colab free tier
- CPU fine-tuning works but takes ~4-6 hours for 7000 rows vs ~20 minutes on GPU


