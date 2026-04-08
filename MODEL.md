# Model Description

## Goal
Predict certificate reputation: **benign**, **suspicious**, **malicious**.

## Features (12)
1. signature_hash_algo
2. signature_key_algo
3. public_key_algo
4. public_key_size
5. can_issue
6. pathlen
7. has_roca
8. common_name
9. issuer_dn
10. not_after
11. eku
12. san

## Why these features
- Cover cryptographic strength (hash + key size)
- Capture CA authority risk (can_issue, pathlen)
- Detect known vulnerabilities (ROCA)
- Provide issuer + domain identity
- Include usage constraints (EKU/SAN)

## Training
Script: `train_model.py`
- Lightweight LightGBM
- 50 boosting rounds
- Small trees for fast CPU inference

### Metrics (sample run)
- Accuracy: **0.9969**
- Benign accuracy: **0.9983**
- Suspicious accuracy: **0.8964**

## Limitations
- Dataset is imbalanced (benign >> suspicious/malicious)
- Model should be retrained with class weights or balanced sampling for production

## Recommended Improvements
- Use class weights for minority classes
- Add more malicious samples
- Include time-based features derived from `not_before` / `not_after`
