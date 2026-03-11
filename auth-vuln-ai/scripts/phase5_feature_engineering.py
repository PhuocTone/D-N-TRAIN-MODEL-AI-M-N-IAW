#!/usr/bin/env python3
"""
Phase 5 — Feature Engineering

This script reads a cleaned dataset of authentication configuration samples
and extracts machine-learning features for each sample.

Default paths assume this script lives in `scripts/` and dataset is in
`dataset/` relative to the project root. You can override with `--input`
and `--output`.

Outputs: dataset_features.csv
"""
import argparse
import logging
import re
from pathlib import Path

import numpy as np
import pandas as pd


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def parse_args():
    p = argparse.ArgumentParser(description="Phase 5: Feature Engineering")
    p.add_argument(
        "--input",
        "-i",
        default="../data/processed/cleaned_dataset.csv",
        help="Path to cleaned input CSV (default: ../data/processed/cleaned_dataset.csv)",
    )
    p.add_argument(
        "--output",
        "-o",
        default="../dataset/dataset_features.csv",
        help="Path to output features CSV (default: ../dataset/dataset_features.csv)",
    )
    return p.parse_args()


def extract_value(text: str, key: str):
    """Find key=value (or key: value) in text, case-insensitive. Returns None if not found."""
    if not isinstance(text, str):
        return None
    pattern = rf"{re.escape(key)}\s*[:=]\s*([^\n\r\s]+)"
    m = re.search(pattern, text, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


def bool_to_int(v):
    """Convert boolean-like string to 1/0. Missing or unrecognized -> 0."""
    if v is None:
        return 0
    s = str(v).strip().lower()
    if s in {"1", "true", "t", "yes", "y"}:
        return 1
    return 0


def safe_int(v):
    """Convert to integer safely, default 0 for missing/non-numeric."""
    try:
        if v is None:
            return 0
        return int(float(v))
    except Exception:
        return 0


def extract_features_from_row(row) -> dict:
    """Extract required features from a dataframe row.

    Strategy: concatenate all string fields from the row into a single
    text blob and search for keys like JWT_SECRET, COOKIE_SECURE, etc.
    This lets the script handle both multi-line config fields and
    flattened columns.
    """
    # Concatenate all non-null string values into a single text blob
    texts = []
    for v in row.values:
        if pd.isna(v):
            continue
        texts.append(str(v))
    blob = "\n".join(texts)

    # Extract raw values (case-insensitive)
    jwt_secret = extract_value(blob, "JWT_SECRET")
    cookie_secure = extract_value(blob, "COOKIE_SECURE")
    cookie_httponly = extract_value(blob, "COOKIE_HTTPONLY")
    session_timeout = extract_value(blob, "SESSION_TIMEOUT")
    jwt_exp = extract_value(blob, "JWT_EXPIRATION")

    # Feature: jwt_secret_length (length of secret string)
    if jwt_secret is None or jwt_secret.lower() in {"none", "null", "nan", ""}:
        jwt_secret_length = 0
    else:
        jwt_secret_length = len(jwt_secret)

    # Feature: cookie_secure (boolean -> 1/0)
    cookie_secure_f = bool_to_int(cookie_secure)

    # Feature: cookie_httponly (boolean -> 1/0)
    cookie_httponly_f = bool_to_int(cookie_httponly)

    # Feature: session_timeout (integer, missing -> 0)
    session_timeout_f = safe_int(session_timeout)

    # Feature: jwt_has_exp (1 if expiration exists and not 'none')
    jwt_has_exp = 0
    if jwt_exp is not None and jwt_exp.lower() not in {"none", "null", "nan", ""}:
        jwt_has_exp = 1

    return {
        "jwt_secret_length": jwt_secret_length,
        "cookie_secure": cookie_secure_f,
        "cookie_httponly": cookie_httponly_f,
        "session_timeout": session_timeout_f,
        "jwt_has_exp": jwt_has_exp,
    }


def main():
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        logging.error("Input not found: %s", input_path)
        raise SystemExit(1)

    df = pd.read_csv(input_path, dtype=object)
    logging.info("Read %d rows from %s", len(df), input_path)

    features = []
    # Process each row and extract features
    for _, row in df.iterrows():
        feats = extract_features_from_row(row)
        # Keep labels if present, else 'unknown'
        vuln = row.get("vulnerability") if "vulnerability" in df.columns else None
        sev = row.get("severity") if "severity" in df.columns else None
        if pd.isna(vuln) or vuln is None:
            vuln = "unknown"
        if pd.isna(sev) or sev is None:
            sev = "unknown"

        feats["vulnerability"] = str(vuln).strip()
        feats["severity"] = str(sev).strip()
        features.append(feats)

    feat_df = pd.DataFrame(features)

    # Ensure column order matches spec
    cols = ["jwt_secret_length", "cookie_secure", "cookie_httponly", "session_timeout", "jwt_has_exp", "vulnerability", "severity"]
    feat_df = feat_df[cols]

    feat_df.to_csv(output_path, index=False)
    logging.info("Wrote features to %s", output_path)

    # Print summary
    print(f"Total samples processed: {len(feat_df)}")
    print("Feature columns created:", ", ".join(cols[:-2]))


if __name__ == "__main__":
    main()
