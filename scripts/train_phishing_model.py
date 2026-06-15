"""Retrain the phishing detection model using the strongest available dataset.

Usage:
    python scripts/train_phishing_model.py
"""
from __future__ import annotations

import sys

from phishing_detection.model import PhishingModelManager


import argparse


def main():
    parser = argparse.ArgumentParser(description='Train phishing model (optionally with custom dataset)')
    parser.add_argument('--dataset', '-d', help='Path to dataset CSV to use for training')
    parser.add_argument('--threshold', '-t', type=float, help='Override saved decision threshold after training (0.0-1.0)')
    parser.add_argument('--force', '-f', action='store_true', help='Force retrain even if model exists')
    args = parser.parse_args()

    manager = PhishingModelManager()
    if args.dataset:
        manager.train_from_path(args.dataset)
    else:
        if args.force or not manager.model_path.exists():
            manager.train_default_model()
        else:
            print('Model already exists; use --force to retrain or --dataset to train with a custom file')

    if args.threshold is not None:
        manager.set_decision_threshold(float(args.threshold))
        print(f'Set decision_threshold to {args.threshold:.3f}')


if __name__ == "__main__":
    main()
