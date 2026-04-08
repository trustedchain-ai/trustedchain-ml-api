#!/usr/bin/env python3
"""
Lightweight prediction server for TrustChain MacBook inference.
Runs on 192.168.1.200:5000
"""

from flask import Flask, request, jsonify
import joblib
import pandas as pd
import numpy as np
from pathlib import Path

app = Flask(__name__)

# Load model and encoders at startup
MODEL_PATH = Path("models/lightgbm_fast.joblib")
ENCODERS_PATH = Path("models/feature_encoders.joblib")
LABEL_MAP_PATH = Path("models/label_map.joblib")

print("Loading model...")
model = joblib.load(MODEL_PATH)
encoders = joblib.load(ENCODERS_PATH)
label_map = joblib.load(LABEL_MAP_PATH)
print(f"✓ Model loaded: {label_map}")

FEATURES = [
    "signature_hash_algo",
    "signature_key_algo",
    "public_key_algo",
    "public_key_size",
    "can_issue",
    "pathlen",
    "has_roca",
    "common_name",
    "issuer_dn",
    "not_after",
    "eku",
    "san",
]

@app.route('/predict', methods=['POST'])
def predict():
    """Handle prediction request"""
    try:
        data = request.get_json()
        features = data.get('features', {})
        
        # Build feature row
        row = {}
        for col in FEATURES:
            value = features.get(col, "")
            
            # Apply defaults
            if value == "" or value is None:
                if col == "public_key_size" or col == "pathlen":
                    value = 0
                else:
                    value = ""
            
            # Encode categorical features
            if col in encoders:
                encoder = encoders[col]
                value_str = str(value)
                if value_str not in encoder.classes_:
                    value = 0  # Unseen category
                else:
                    value = encoder.transform([value_str])[0]
            
            row[col] = value
        
        # Create DataFrame
        df = pd.DataFrame([row])[FEATURES]
        
        # Force numeric types
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
        
        # Predict
        pred_raw = model.predict(df)
        
        # Parse prediction
        if isinstance(pred_raw, np.ndarray):
            if len(pred_raw.shape) == 2:
                pred_vec = pred_raw[0]
                pred = int(np.argmax(pred_vec))
                probs = pred_vec
            else:
                pred = int(pred_raw[0])
                probs = None
        else:
            pred = int(pred_raw)
            probs = None
        
        # Build response
        response = {
            "label_id": pred,
            "label": label_map.get(pred, str(pred)),
        }
        
        if probs is not None:
            response["probabilities"] = {
                label_map.get(i, str(i)): float(p) for i, p in enumerate(probs)
            }
        
        return jsonify(response)
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok", "model": "lightgbm_fast"})

if __name__ == '__main__':
    print("\n" + "="*60)
    print("TrustChain Prediction Server")
    print("="*60)
    print(f"Model: {MODEL_PATH}")
    print(f"Labels: {label_map}")
    print(f"Features: {len(FEATURES)}")
    print("="*60)
    print("Starting server on http://0.0.0.0:5000")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
