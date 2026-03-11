#!/usr/bin/env python3
"""
PHASE 4 — Data Cleaning script for auth vulnerability dataset.

Usage:
  python phase4_data_cleaning.py \
    --input ../data/processed/dataset_structured.csv \
    --output-dir ../data/processed

Outputs (written into --output-dir):
  cleaned_dataset.csv
  train_dataset.csv
  test_dataset.csv
"""
import argparse
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def parse_args():
    p = argparse.ArgumentParser(description="Phase 4: Data Cleaning")
    p.add_argument(
        "--input",
        "-i",
        default="../data/processed/dataset_structured.csv",
        help="Path to input CSV (default: ../data/processed/dataset_structured.csv)",
    )
    p.add_argument(
        "--output-dir",
        "-o",
        default="../data/processed",
        help="Directory to write outputs (default: ../data/processed)",
    )
    p.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Proportion for test split (default: 0.2)",
    )
    p.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random state for reproducible splits",
    )
    return p.parse_args()


def convert_bool_like_series(s: pd.Series) -> pd.Series:
    """
    Convert boolean-like values in a Series to 1/0 integers.
    Recognized true values: 'true','1','yes','y','t' (case-insensitive)
    Recognized false values: 'false','0','no','n','f'
    """
    true_set = {"true", "1", "yes", "y", "t"}
    false_set = {"false", "0", "no", "n", "f"}

    def conv(v):
        if pd.isna(v):
            return np.nan
        if isinstance(v, (bool, np.bool_)):
            return int(v)
        if isinstance(v, (int, np.integer)) and (v == 0 or v == 1):
            return int(v)
        vs = str(v).strip().lower()
        if vs in true_set:
            return 1
        if vs in false_set:
            return 0
        return np.nan

    return s.map(conv)


def is_mostly_bool_like(s: pd.Series, thresh=0.6) -> bool:
    non_null = s.dropna()
    if len(non_null) == 0:
        return False
    converted = convert_bool_like_series(non_null)
    num_converted = converted.notna().sum()
    return (num_converted / len(non_null)) >= thresh


def main():
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        logging.error("Input file not found: %s", input_path)
        raise SystemExit(1)

    logging.info("Reading input: %s", input_path)
    df = pd.read_csv(input_path, dtype=object)

    logging.info("Initial rows: %d", len(df))

    # 1) Remove duplicate rows
    df = df.drop_duplicates().reset_index(drop=True)
    logging.info("After dropping duplicates: %d", len(df))

    # 2) Normalize values:
    # - Lowercase column names and strip whitespace
    df.columns = [str(c).strip().lower() for c in df.columns]

    # Trim whitespace from all string/object fields
    for col in df.select_dtypes(include=["object"]).columns:
        df[col] = df[col].where(df[col].notna(), None)
        try:
            df[col] = df[col].astype(str).str.strip()
            df[col] = df[col].replace({"": None, "nan": None})
        except Exception:
            pass

    expected_cols = [
        "jwt_secret_length",
        "cookie_secure",
        "cookie_httponly",
        "session_timeout",
        "vulnerability",
        "severity",
    ]

    for c in expected_cols:
        if c not in df.columns:
            logging.warning("Expected column '%s' not found; creating as empty.", c)
            df[c] = np.nan

    # Convert boolean-like columns to numeric
    bool_candidate_cols = set()
    for col in df.columns:
        if col in ("cookie_secure", "cookie_httponly"):
            bool_candidate_cols.add(col)
        else:
            if is_mostly_bool_like(df[col], thresh=0.6):
                bool_candidate_cols.add(col)

    logging.info("Boolean-like columns detected: %s", sorted(bool_candidate_cols))
    for col in bool_candidate_cols:
        df[col] = convert_bool_like_series(df[col])

    # 3) Handle missing values
    numeric_cols = ["jwt_secret_length", "cookie_secure", "cookie_httponly", "session_timeout"]
    categorical_cols = ["vulnerability", "severity"]

    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    for col in numeric_cols:
        if col in df.columns:
            median = df[col].median(skipna=True)
            if pd.isna(median):
                median = 0
            df[col] = df[col].fillna(median)

    for col in categorical_cols:
        if col in df.columns:
            df[col] = df[col].where(df[col].notna(), "unknown")
            df[col] = df[col].astype(str).str.strip().replace({"": "unknown", "nan": "unknown"})

    # 4) Ensure correct dtypes
    if "jwt_secret_length" in df.columns:
        df["jwt_secret_length"] = pd.to_numeric(df["jwt_secret_length"], errors="coerce").fillna(0)
        df["jwt_secret_length"] = df["jwt_secret_length"].round().astype(int)

    if "session_timeout" in df.columns:
        df["session_timeout"] = pd.to_numeric(df["session_timeout"], errors="coerce").fillna(0)
        df["session_timeout"] = df["session_timeout"].round().astype(int)

    for col in ("cookie_secure", "cookie_httponly"):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
            df[col] = df[col].fillna(0)
            df[col] = df[col].apply(lambda x: 1 if x >= 1 else 0).astype(int)

    for col in ("vulnerability", "severity"):
        if col in df.columns:
            df[col] = df[col].astype(str).fillna("unknown").str.strip()
            df[col] = df[col].replace({"": "unknown", "nan": "unknown"})

    # 5) Validate ranges
    for col in ("jwt_secret_length", "session_timeout"):
        if col in df.columns:
            negatives = df[df[col] < 0].shape[0]
            if negatives > 0:
                median = int(df[df[col] >= 0][col].median(skipna=True) if df[df[col] >= 0].shape[0] > 0 else 0)
                logging.warning("Column '%s' has %d negative values; replacing with median=%s", col, negatives, median)
                df.loc[df[col] < 0, col] = median

    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).round().astype(int)

    for col in df.select_dtypes(include=["object"]).columns:
        df[col] = df[col].astype(str).str.strip().replace({"": "unknown", "nan": "unknown"})

    # 6) Split dataset
    stratify_col = None
    if "vulnerability" in df.columns:
        unique_vals = df["vulnerability"].nunique(dropna=True)
        if unique_vals > 1 and unique_vals < 100:
            stratify_col = df["vulnerability"]
            logging.info("Stratifying split by 'vulnerability' (%d unique values).", unique_vals)
        else:
            logging.info("Not stratifying (vulnerability unique=%d).", unique_vals)

    train_df, test_df = train_test_split(
        df,
        test_size=args.test_size,
        random_state=args.random_state,
        shuffle=True,
        stratify=stratify_col,
    )

    logging.info("Train rows: %d  Test rows: %d", len(train_df), len(test_df))

    # 7) Save outputs
    cleaned_path = Path(output_dir) / "cleaned_dataset.csv"
    train_path = Path(output_dir) / "train_dataset.csv"
    test_path = Path(output_dir) / "test_dataset.csv"

    df.to_csv(cleaned_path, index=False)
    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)

    logging.info("Saved cleaned dataset: %s", cleaned_path)
    logging.info("Saved train dataset: %s", train_path)
    logging.info("Saved test dataset: %s", test_path)
    logging.info("Data cleaning complete.")


if __name__ == "__main__":
    main()
