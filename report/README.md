# BankGuard Technical Report (Bharat AI-SoC Challenge PS3)

This directory contains the academic technical report for Phase 1 of the **Bharat AI-SoC Challenge 2026–27**, addressing **Problem Statement 3 (PS3: On-Device Threat, Phishing & Scam Detection)**.

## Deliverables

- **Compiled PDF Deliverable**: [`report.pdf`](https://anoonimouse.github.io/bankguard-bharat-ai-soc-challenge/report/report.pdf) (8 pages, monochrome IEEE/ACM academic formatting)
- **LaTeX Source**: [`report.tex`](report.tex)
- **Architectural Diagrams**:
  - `fig_attack_flow.png`: Attack progression vs. BankGuard multi-tier intervention stages.
  - `fig_pipeline.jpg`: BankGuard ML detection pipeline (lexical, brand similarity, XGBoost, and ExecuTorch Llama delegation).

## Core Report Content & Structure

1. **Title & Abstract**: Executive summary of dual-stage decoupled edge AI on Arm SoC.
2. **Executive Summary & Threat Context**: The scale of look-alike YONO apps and phishing links in India, and why cloud-only verification fails.
3. **The SDK-First Paradigm**: Zero user adoption friction by embedding protection directly into existing banking apps.
4. **System Architecture & Methodology**: Mathematical formulation of Stage 1 detection ($<20$\,ms) and Stage 2 ExecuTorch Llama non-hallucinatory prompting.
5. **Target Hardware Setup & Execution Mapping**: Physical Google Pixel 6a (Tensor SoC / ARM64-v8a) core mapping (Cortex-X1 for Llama, Cortex-A55 for heuristics).
6. **Model Optimization & Edge Engineering**: Quantitative justification of Llama 3.2 1B SpinQuant INT4 over 3B variants (preventing Android LowMemoryKiller crashes).
7. **Experimental Results & Benchmarks**: Realistic detection metrics (93.8% accuracy, 93.6% F1, 0.00% official banking FPR) and SoC telemetry (14.2\,ms detection, 0.31\,s TTFT, 50.2 tok/s).
8. **Compliance with Challenge Guidelines**: Dr. Vijay Kumar's mentor principles (offline independence, strict role decoupling, zero cloud leakage, non-destructive remediation).
9. **Limitations & Phase 2 PoC Roadmap**: Hardware NPU delegation (HailoRT / Tensor TPU) and vernacular fine-tuning.
