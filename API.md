# API Reference

## Authentication
Basic Auth using configured admin credentials.

## Endpoints

### POST /api/predict
Predict certificate label.

**Request**
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
    "not_after": "2026-12-31",
    "eku": "serverAuth",
    "san": "*.google.com"
  }
}
```

**Response**
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

### GET /api/models
Return available models and expected features.

## Errors
- 401 Unauthorized
- 400 Bad request
- 500 Internal server error
