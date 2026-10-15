# Verification and Evaluation Rebuild Log

**Project:** AI Investigator for Cybersecurity Threat Detection and Response  
**Status:** All fabricated and illustrative values removed. All artifacts rebuilt using verified test outputs.  
**Verification Source:** `results/reports/final_predictions.csv` and `results/models/best_model.joblib`.  

## Verified Test Benchmark Summary (LANL Days 13-14 Test Partition)
- **Total Test Windows:** 289 (Benign: 225, Red-Team Attack: 64)
- **Decision Threshold:** 0.9300 (High-Precision Alerting Mode)
- **True Positives (TP):** 32
- **True Negatives (TN):** 211
- **False Positives (FP):** 14
- **False Negatives (FN):** 32
- **Accuracy:** 84.08%
- **Precision:** 69.57%
- **Recall:** 50.00%
- **F1-Score:** 58.18%
- **Specificity:** 93.78%
- **False Positive Rate (FPR):** 6.22%
- **ROC-AUC:** 0.6874
- **Average Precision (PR-AUC):** 0.5670

All figures in `results/figures/verified/`, `results/figures/`, and `presentation_mockup/` now represent genuine experimental outputs.
