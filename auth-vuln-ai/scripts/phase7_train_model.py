#!/usr/bin/env python3
"""
Phase 7 — Train ML Model for authentication vulnerability classification.

This script performs the following:
- loads a dataset with numeric features and a `vulnerability` label
- encodes labels
- splits train/test
- trains DecisionTree, RandomForest, LogisticRegression
- evaluates models and selects the best by accuracy
- saves the best model to `models/model_auth_vuln.pkl`

Usage:
  python phase7_train_model.py --input ../dataset/dataset_features2.csv --output models/model_auth_vuln.pkl

Comments in the code explain each step.
"""
import argparse
import logging
from pathlib import Path

import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def parse_args():
    p = argparse.ArgumentParser(description="Train models for auth vulnerability classification")
    p.add_argument("--input", "-i", default="../dataset/dataset_cleaned.csv", help="Path to input CSV with features and label")
    p.add_argument("--output", "-o", default="../models/model_auth_vuln.pkl", help="Path to save best model")
    return p.parse_args()


def main():
    args = parse_args()
    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()

    # Load dataset
    if not input_path.exists():
        logging.error("Input dataset not found: %s", input_path)
        raise SystemExit(1)
    logging.info("Loading dataset: %s", input_path)
    df = pd.read_csv(input_path)

    # Feature selection: use these four features
    feature_cols = ["jwt_secret_length", "cookie_secure", "cookie_httponly", "session_timeout"]
    for c in feature_cols:
        if c not in df.columns:
            logging.error("Required feature column missing: %s", c)
            raise SystemExit(1)

    X = df[feature_cols].copy()
    # Target label
    if "vulnerability" not in df.columns:
        logging.error("Label column 'vulnerability' not found in dataset")
        raise SystemExit(1)
    y = df["vulnerability"].astype(str)

    # Encode labels if needed
    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    logging.info("Classes: %s", list(le.classes_))

    # Split dataset into train/test
    X_train, X_test, y_train, y_test = train_test_split(X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)

    # Define models to train
    models = {
        "Decision Tree": DecisionTreeClassifier(random_state=42),
        "Random Forest": RandomForestClassifier(random_state=42, n_estimators=100),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
    }

    results = {}

    # Train and evaluate each model
    for name, model in models.items():
        # Training
        model.fit(X_train, y_train)
        # Prediction
        y_pred = model.predict(X_test)
        # Evaluation metrics
        acc = accuracy_score(y_test, y_pred)
        results[name] = {"model": model, "accuracy": acc, "y_pred": y_pred}
        # Print brief results
        logging.info("%s Accuracy: %.4f", name, acc)
        print(f"\n{name} Classification Report:")
        print(classification_report(y_test, y_pred, target_names=le.classes_))
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))

    # Select best model by accuracy
    best_name = max(results.keys(), key=lambda n: results[n]["accuracy"])
    best_model = results[best_name]["model"]
    best_acc = results[best_name]["accuracy"]
    logging.info("Best model: %s (accuracy=%.4f)", best_name, best_acc)

    # Save the pipeline: include label encoder and feature columns with the model
    output_path.parent.mkdir(parents=True, exist_ok=True)
    package = {"model": best_model, "label_encoder": le, "feature_columns": feature_cols}
    joblib.dump(package, output_path)
    logging.info("Saved best model to %s", output_path)

    # Print final accuracies summary
    print("\nAccuracy Summary:")
    for name in results:
        print(f"{name}: {results[name]['accuracy']:.4f}")


if __name__ == "__main__":
    main()
