#!/usr/bin/env python3
"""
Phase 7 — Hyperparameter tuning, evaluation, and report export.

This script:
- Loads features dataset
- Runs GridSearchCV for DecisionTree, RandomForest, LogisticRegression
- Evaluates best estimators on a held-out test set
- Saves best model (by test accuracy) to models/model_auth_vuln.pkl
- Writes a metrics report to models/metrics_report.txt
- Attempts to git add/commit the new artifacts
"""
import argparse
import logging
from pathlib import Path
import json

import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import subprocess


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def parse_args():
    p = argparse.ArgumentParser(description="Tune models and save report")
    p.add_argument("--input", "-i", default="../dataset/dataset_features2.csv")
    p.add_argument("--output-model", default="../models/model_auth_vuln.pkl")
    p.add_argument("--report", default="../models/metrics_report.txt")
    return p.parse_args()


def run_grid_search(model, param_grid, X_train, y_train):
    gs = GridSearchCV(model, param_grid, cv=5, scoring='accuracy', n_jobs=-1)
    gs.fit(X_train, y_train)
    return gs


def try_git_commit(paths, message="Add tuned model and metrics report"):
    try:
        subprocess.run(["git", "add"] + paths, check=True)
        subprocess.run(["git", "commit", "-m", message], check=True)
        logging.info("Committed artifacts to git")
    except Exception as e:
        logging.warning("Git commit failed or git not available: %s", e)


def main():
    args = parse_args()
    inp = Path(args.input).resolve()
    out_model = Path(args.output_model).resolve()
    report_path = Path(args.report).resolve()

    if not inp.exists():
        logging.error("Input not found: %s", inp)
        raise SystemExit(1)

    df = pd.read_csv(inp)
    feature_cols = ["jwt_secret_length", "cookie_secure", "cookie_httponly", "session_timeout"]
    X = df[feature_cols]
    y = df['vulnerability'].astype(str)

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(X, y_enc, test_size=0.2, random_state=42, stratify=y_enc)

    # Define models and parameter grids
    models_params = {
        'DecisionTree': (DecisionTreeClassifier(random_state=42), {
            'max_depth': [None, 5, 10, 20],
            'min_samples_split': [2, 5, 10]
        }),
        'RandomForest': (RandomForestClassifier(random_state=42), {
            'n_estimators': [50, 100, 200],
            'max_depth': [None, 10, 20],
            'min_samples_split': [2, 5]
        }),
        'LogisticRegression': (LogisticRegression(max_iter=2000, random_state=42), {
            'C': [0.01, 0.1, 1, 10],
            'solver': ['lbfgs']
        })
    }

    results = {}

    for name, (model, grid) in models_params.items():
        logging.info("Tuning %s", name)
        gs = run_grid_search(model, grid, X_train, y_train)
        best = gs.best_estimator_
        y_pred = best.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)
        results[name] = {
            'best_params': gs.best_params_,
            'best_score_cv': gs.best_score_,
            'test_accuracy': acc,
            'classification_report': report,
            'confusion_matrix': cm.tolist(),
            'estimator': best
        }
        logging.info("%s test accuracy: %.4f", name, acc)

    # Choose best model by test_accuracy
    best_name = max(results.keys(), key=lambda n: results[n]['test_accuracy'])
    best_entry = results[best_name]
    best_model = best_entry['estimator']

    # Save model package
    out_model.parent.mkdir(parents=True, exist_ok=True)
    package = {'model': best_model, 'label_encoder': le, 'feature_columns': feature_cols}
    joblib.dump(package, out_model)
    logging.info("Saved best model (%s) to %s", best_name, out_model)

    # Write report
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(f"Best model: {best_name}\n\n")
        json.dump({k: {k2: v for k2, v in results[k].items() if k2 != 'estimator'} for k in results}, f, indent=2)
        f.write('\n\nDetailed classification reports:\n')
        for k in results:
            f.write(f"\n== {k} ==\n")
            f.write(results[k]['classification_report'])
            f.write('\nConfusion Matrix:\n')
            f.write(str(results[k]['confusion_matrix']))
            f.write('\n')

    logging.info("Wrote metrics report to %s", report_path)

    # Try to commit model and report
    try_git_commit([str(out_model), str(report_path)])

    # Summary
    total = len(df)
    vuln_count = (df['vulnerability'] != 'none').sum()
    print(f"Total rows processed: {total}")
    print(f"Number of vulnerabilities detected: {vuln_count}")
    print(f"Saved model: {out_model}")
    print(f"Saved report: {report_path}")


if __name__ == '__main__':
    main()
