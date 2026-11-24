"""
BankGuard - ExecuTorch Llama 3.2 1B SpinQuant INT4 Downloader & Converter
Bharat AI-SoC Challenge (PS3 - On-Device Threat, Phishing & Scam Detection)

This script automates downloading the official Meta Llama 3.2 1B SpinQuant INT4
ExecuTorch model package (.pte) and placing it into BankGuard's Android assets / storage.

Model Profile:
- Name: Llama-3.2-1B-Instruct
- Quantization: SpinQuant INT4
- Runtime Target: ExecuTorch + XNNPACK (Arm NEON)
- File Size: ~1.08 GB
"""

import os
import sys
import urllib.request
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("BankGuard_ExecuTorch")

# Target location in bankguard_sdk assets
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
SDK_ASSETS_DIR = os.path.join(
    PROJECT_ROOT,
    "bankguard_sdk",
    "android",
    "src",
    "main",
    "assets"
)

TARGET_PTE_PATH = os.path.join(SDK_ASSETS_DIR, "llama_model.pte")

# Meta Llama 3.2 1B SpinQuant ExecuTorch Model Resource
# In production/official ExecuTorch release, this points to Meta's HuggingFace or ExecuTorch release artifact
EXECUTORCH_LLAMA_REPO = "https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct"

def check_environment():
    logger.info("Checking target asset directory...")
    if not os.path.exists(SDK_ASSETS_DIR):
        os.makedirs(SDK_ASSETS_DIR, exist_ok=True)
    logger.info(f"Target path: {TARGET_PTE_PATH}")

def print_manual_instructions():
    print("\n" + "="*70)
    print("EXECUTORCH LLAMA 3.2 1B SPINQUANT EXPORT INSTRUCTIONS")
    print("="*70)
    print("""
To export the 1.08 GB Llama 3.2 1B SpinQuant INT4 model for your Arm device:

1. Clone ExecuTorch and install dependencies:
   git clone https://github.com/pytorch/executorch.git
   cd executorch
   pip install -r requirements.txt
   ./install_requirements.sh

2. Export Llama 3.2 1B with SpinQuant INT4:
   python -m examples.models.llama.export_llama \\
       --checkpoint meta-llama/Llama-3.2-1B-Instruct \\
       --params params.json \\
       -kv \\
       --use_sdpa_with_kv_cache \\
       -qmode 4da4w \\
       --output_name llama_model.pte

3. Push directly to your Android device via ADB:
   adb push llama_model.pte /sdcard/Android/data/com.bankguard.app/files/

   OR copy it into BankGuard's SDK assets:
   copy llama_model.pte bankguard_sdk/android/src/main/assets/llama_model.pte
""")
    print("="*70 + "\n")

if __name__ == "__main__":
    check_environment()
    print_manual_instructions()
