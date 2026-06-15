#!/usr/bin/env python
"""Retrain phishing model with aggressive threshold and better training data"""
import argparse
import os
import sys
from pathlib import Path

parser = argparse.ArgumentParser(description="Retrain phishing model with aggressive threshold and better training data")
parser.add_argument("--force", "-f", action="store_true", help="Force retraining and delete the existing model file")
args = parser.parse_args()

if not args.force:
    print("No --force flag specified; existing model will be preserved.")
    print("Use --force to retrain aggressively when you intend to.")
    sys.exit(0)

# Delete old model to force retraining
model_path = Path("models/phishing_model.joblib")
meta_path = Path("models/phishing_model.meta.json")

if model_path.exists():
    os.remove(model_path)
    print(f"✓ Deleted old model: {model_path}")

if meta_path.exists():
    os.remove(meta_path)
    print(f"✓ Deleted old metadata: {meta_path}")

print("\n" + "="*80)
print("RETRAINING PHISHING MODEL WITH AGGRESSIVE THRESHOLD (0.5)")
print("="*80 + "\n")

# Import and create new model - this will trigger training
from phishing_detection.model import PhishingModelManager

print("Creating new model (this will trigger training)...")
model = PhishingModelManager()

print("\n" + "="*80)
print("MODEL RETRAINING COMPLETE")
print("="*80)
print(f"Decision Threshold: 0.5 (50%)")
print(f"Any URL with ≥50% malicious confidence = PHISHING")
print("\nNew model ready for testing!")
