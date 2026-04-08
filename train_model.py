#!/usr/bin/env python3
"""
Train lightweight LightGBM model for TrustChain certificate classification.
Uses only 12 key features for fast CPU inference.
"""

import pandas as pd
import numpy as np
from pathlib import Path
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import lightgbm as lgb

# Paths
DATA_PATH = Path("training_data/crtsh_5m_labeled.csv")
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)

# Features to use (12 total - balanced speed/accuracy)
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

LABEL_COL = "label"

def load_and_preprocess(sample_size=100000):
    """Load data and prepare for training"""
    print(f"Loading data from {DATA_PATH}...")
    
    # Read only needed columns + label
    cols_to_read = FEATURES + [LABEL_COL]
    df = pd.read_csv(DATA_PATH, usecols=cols_to_read, nrows=sample_size)
    
    print(f"Loaded {len(df):,} rows")
    print(f"Label distribution:\n{df[LABEL_COL].value_counts()}")
    
    # Handle missing values
    df = df.fillna({
        "signature_hash_algo": "unknown",
        "signature_key_algo": "unknown",
        "public_key_algo": "unknown",
        "public_key_size": 0,
        "can_issue": "f",
        "pathlen": 0,
        "has_roca": "f",
        "common_name": "",
        "issuer_dn": "",
        "not_after": "",
        "eku": "",
        "san": "",
    })
    
    # Encode categorical features
    categorical_features = [
        "signature_hash_algo",
        "signature_key_algo",
        "public_key_algo",
        "can_issue",
        "has_roca",
    ]
    
    # For text features, use simple label encoding (not one-hot to keep it small)
    text_features = ["common_name", "issuer_dn", "not_after", "eku", "san"]
    
    encoders = {}
    for col in categorical_features + text_features:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le
    
    # Encode labels
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df[LABEL_COL])
    
    # Save label mapping
    label_map = {i: label for i, label in enumerate(label_encoder.classes_)}
    joblib.dump(label_map, MODEL_DIR / "label_map.joblib")
    print(f"Label mapping: {label_map}")
    
    # Save encoders for later use
    joblib.dump(encoders, MODEL_DIR / "feature_encoders.joblib")
    
    X = df[FEATURES]
    
    return X, y, label_map

def train_model(X, y):
    """Train lightweight LightGBM model"""
    print("\nSplitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train):,} samples")
    print(f"Test set: {len(X_test):,} samples")
    
    print("\nTraining LightGBM (lightweight config)...")
    
    # Lightweight config for fast CPU inference
    params = {
        "objective": "multiclass",
        "num_class": len(np.unique(y)),
        "metric": "multi_logloss",
        "boosting_type": "gbdt",
        "num_leaves": 31,  # Small trees
        "max_depth": 5,    # Shallow trees
        "learning_rate": 0.1,
        "feature_fraction": 0.8,
        "bagging_fraction": 0.8,
        "bagging_freq": 5,
        "verbose": -1,
    }
    
    train_data = lgb.Dataset(X_train, label=y_train)
    val_data = lgb.Dataset(X_test, label=y_test, reference=train_data)
    
    # Train with only 50 iterations for speed
    model = lgb.train(
        params,
        train_data,
        num_boost_round=50,
        valid_sets=[train_data, val_data],
        valid_names=["train", "val"],
    )
    
    print("\nEvaluating...")
    y_pred = model.predict(X_test)
    y_pred_labels = np.argmax(y_pred, axis=1)
    
    accuracy = (y_pred_labels == y_test).mean()
    print(f"Test accuracy: {accuracy:.4f}")
    
    # Per-class accuracy
    for label_id in np.unique(y_test):
        mask = y_test == label_id
        class_acc = (y_pred_labels[mask] == y_test[mask]).mean()
        print(f"  Class {label_id} accuracy: {class_acc:.4f}")
    
    return model

def save_model(model):
    """Save trained model"""
    model_path = MODEL_DIR / "lightgbm_model_fast.joblib"
    print(f"\nSaving model to {model_path}...")
    joblib.dump(model, model_path)
    
    size_mb = model_path.stat().st_size / (1024 ** 2)
    print(f"Model size: {size_mb:.1f} MB")
    
    return model_path

def main():
    print("=" * 60)
    print("TrustChain Model Training")
    print("=" * 60)
    
    # Load data (use 100k samples for speed, increase for better accuracy)
    X, y, label_map = load_and_preprocess(sample_size=100000)
    
    # Train model
    model = train_model(X, y)
    
    # Save model
    model_path = save_model(model)
    
    print("\n" + "=" * 60)
    print("✅ Training complete!")
    print(f"Model saved: {model_path}")
    print("Next: Upload to droplet and deploy")
    print("=" * 60)

if __name__ == "__main__":
    main()
