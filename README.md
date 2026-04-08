# TrustedChain ML API

AI-powered certificate reputation scoring for malware detection.

This repository provides a lightweight, production-ready machine learning system for analyzing X.509 certificates and identifying malicious or suspicious activity.

---

## Overview

TrustedChain combines machine learning and threat intelligence to classify certificates into:

- **Benign**
- **Suspicious**
- **Malicious**

The system is designed to be:
- Fast (low-latency inference)
- Lightweight (efficient models)
- Explainable (clear feature signals)
- Easy to integrate (HTTP API)

---

## What’s Included

- **HTTP API** for real-time predictions
- **Model playground UI** for testing and experimentation
- **Training pipeline** (LightGBM-based)
- **Sample dataset** (anonymized with labels)

---

## Dataset

- **Size:** ~5M labeled certificates
- **Sources:** Certificate Transparency logs + malware telemetry feeds

### Labels

- **Benign** — trusted issuers with no known malicious association
- **Suspicious** — mixed signals (e.g., unusual cryptography, new or untrusted issuers)
- **Malicious** — confirmed association with malware infrastructure or abuse

---

## Features (Core Signals)

The model is trained on 12 key certificate features:

- `signature_hash_algo`
- `signature_key_algo`
- `public_key_algo`
- `public_key_size`
- `can_issue`
- `pathlen`
- `has_roca`
- `common_name`
- `issuer_dn`
- `not_after`
- `eku`
- `san`

These features capture both cryptographic properties and certificate structure patterns.

---

## Model Selection

Multiple models were evaluated before selecting LightGBM as the default due to its performance and efficiency.

### Evaluated Models

- Logistic Regression
- Random Forest
- Extra Trees
- Gradient Boosting (sklearn)
- HistGradientBoosting (sklearn)
- XGBoost
- LightGBM
- MLP (Neural Network)

---

## Performance (Internal Benchmark)

| Model                    | Accuracy |
|--------------------------|----------|
| Gradient Boosting        | 97.32%   |
| HistGradientBoosting     | 97.32%   |
| XGBoost                  | 97.31%   |
| LightGBM (selected)      | 97.32%   |

LightGBM was selected for:
- Fast training (~4 seconds)
- Low resource usage
- Strong performance on tabular data

---

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Start API
python server.py

# Open UI
open http://localhost:4173/model.html
```

---

## Prediction API

**Endpoint**

`POST /api/predict`

**Example Request**

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

**Example Response**

```json
{
  "model": "lightgbm",
  "label_id": 0,
  "label": "benign",
  "probabilities": {
    "benign": 0.91,
    "suspicious": 0.07,
    "malicious": 0.02
  }
}
```

---

## Training

Training scripts and configuration:
- `train_model.py`
- `MODEL.md`

Supports:
- Model retraining
- Feature experimentation
- Performance benchmarking

---

## Data Sample

See:

`data/DATA_SAMPLE.csv`

- Anonymized dataset
- Includes benign / suspicious / malicious rows
- Safe for testing and development

---

## Research Context & Contributions

TrustedChain is based on the idea that certificate-level signals can be used to predict malicious activity before execution. This work explores how cryptographic properties, issuer relationships, and certificate constraints correlate with abuse patterns at scale.

### Key Contributions

- **Early Detection Signal**  
  Shows that certificate reputation can serve as a practical early indicator for malware detection.

- **Model Performance**  
  Demonstrates that gradient boosting models consistently perform well on large-scale certificate data.

- **Efficient Feature Design**  
  Confirms that a compact set of features can achieve strong accuracy while keeping inference fast.

- **Practical Application**  
  Presents a deployable pipeline that connects research with real-world security use cases.

---

## Roadmap (Future Work)

- Explainable AI (feature-level insights)
- Certificate graph analysis
- Real-time threat intelligence ingestion
- API scaling & deployment
- Advanced model experimentation

---

## Contact

For research collaboration, partnerships, or integration requests:

**Assaf@trustedchain.ai**
