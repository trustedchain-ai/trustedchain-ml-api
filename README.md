# TrustedChain ML API

Certificate reputation scoring for malware detection. This repo contains:
- **HTTP API** for prediction
- **Model playground UI**
- **Training script** for a lightweight LightGBM model
- **Data sample** (anonymized, includes malicious labels)

## Dataset (from `trustedchain.ai/ml.html`)
- **Size:** 5M labeled certificates (benign / suspicious / malicious)
- **Sources:** crt.sh + malware telemetry feeds
- **Labels:**
  - **Benign**: trusted issuers, no malware association
  - **Suspicious**: mixed signals (unusual crypto, new issuers)
  - **Malicious**: confirmed malware signing

## Features (12 key signals)
- signature_hash_algo
- signature_key_algo
- public_key_algo
- public_key_size
- can_issue
- pathlen
- has_roca
- common_name
- issuer_dn
- not_after
- eku
- san

## Training Methods Evaluated (from `trustedchain.ai/ml.html`)
We benchmarked multiple models before selecting a lightweight LightGBM variant:
- Logistic Regression
- Random Forest
- Extra Trees
- Gradient Boosting (sklearn)
- HistGradientBoosting (sklearn)
- XGBoost
- LightGBM
- MLP (Neural Network)

## Reported Research Results
From the research page, gradient boosting methods achieve **~97.3% accuracy**.
Best-performing methods:
- **Gradient Boosting:** 97.32% accuracy
- **HistGradientBoosting:** 97.32% accuracy
- **XGBoost:** 97.31% accuracy
- **LightGBM:** 97.32% accuracy (train time ~4.14s)

## Quick Start (Local)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Start API
python server.py

# Visit UI
open http://localhost:4173/model.html
```

## Prediction API
`POST /api/predict`
```json
{
  "model": "lightgbm",
  "features": {
    "signature_hash_algo": "SHA-256",
    "signature_key_algo": "RSA",
    "public_key_algo": "RSA",
    "public_key_size": 2048,
    "can_issue": "f",
    "pathlen": 0,
    "has_roca": "f",
    "common_name": "google.com",
    "issuer_dn": "CN=Google Trust Services",
    "eku": "serverAuth",
    "san": "*.google.com"
  }
}
```

## Training
See `train_model.py` and `MODEL.md`.

## Data Sample
See `data/DATA_SAMPLE.csv` (anonymized).

## Notes
- No secrets in this repository.
- Configure environment variables via `.env` or systemd.
