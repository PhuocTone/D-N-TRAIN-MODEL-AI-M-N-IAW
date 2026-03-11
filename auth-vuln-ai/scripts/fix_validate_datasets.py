#!/usr/bin/env python3
"""
Fix and validate dataset files for the ML security project.

This script processes two files:
- dataset_cleaned.csv -> ensures columns (config,vulnerability,severity) and
  that each row has a single config string of key=value pairs separated by ";".
- dataset_features.csv -> ensures numeric feature types and applies
  vulnerability labeling rules, writing corrected outputs.

By default the script does NOT overwrite originals; it writes dataset_cleaned2.csv
and dataset_features2.csv. Use --inplace to overwrite original files.

Prints a summary: total rows processed, vulnerabilities detected, output paths.
"""
from pathlib import Path
import argparse
import logging
import pandas as pd


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def parse_args():
    p = argparse.ArgumentParser(description="Fix and validate dataset files")
    p.add_argument("--cleaned-in", default="../dataset/dataset_cleaned.csv")
    p.add_argument("--features-in", default="../dataset/dataset_features.csv")
    p.add_argument("--cleaned-out", default="../dataset/dataset_cleaned2.csv")
    p.add_argument("--features-out", default="../dataset/dataset_features2.csv")
    p.add_argument("--inplace", action="store_true", help="Overwrite input files in-place")
    return p.parse_args()


def fix_cleaned(df: pd.DataFrame) -> pd.DataFrame:
    # Ensure columns exist
    cols = [c.lower() for c in df.columns]
    df.columns = cols

    # Normalize vulnerability/severity columns
    if 'vulnerability' not in df.columns:
        df['vulnerability'] = pd.NA
    if 'severity' not in df.columns:
        df['severity'] = pd.NA

    # Build config column
    def build_config(row):
        # If 'config' exists and looks valid, use it
        if 'config' in row.index and pd.notna(row['config']):
            cfg = str(row['config']).strip()
            if '=' in cfg:
                return cfg.replace('\n', ';').replace('; ', ';')

        # Otherwise try to assemble from other columns
        kvs = []
        for k, v in row.items():
            if k in ('vulnerability', 'severity', 'config'):
                continue
            if pd.isna(v):
                continue
            s = str(v).strip()
            # If the cell already contains key=value, keep it
            if '=' in s or ':' in s:
                # normalize to key=value with semicolon sep
                kvs.append(s.replace(':', '='))
            else:
                # turn column name into key
                key = k.upper()
                kvs.append(f"{key}={s}")

        if not kvs:
            return pd.NA
        return ';'.join(kvs)

    df['config'] = df.apply(build_config, axis=1)

    # Remove malformed rows where config is missing or doesn't contain '='
    valid_mask = df['config'].notna() & df['config'].str.contains('=')
    removed = (~valid_mask).sum()
    if removed:
        logging.info("Removing %d malformed rows from cleaned dataset", removed)
    df = df[valid_mask].copy()

    # Ensure vulnerability/severity filled
    df['vulnerability'] = df['vulnerability'].fillna('unknown').astype(str).str.strip().replace({'': 'unknown', 'nan': 'unknown'})
    df['severity'] = df['severity'].fillna('unknown').astype(str).str.strip().replace({'': 'unknown', 'nan': 'unknown'})

    # Keep only required columns in order
    return df[['config', 'vulnerability', 'severity']]


def fix_features(df: pd.DataFrame) -> pd.DataFrame:
    # Normalize column names
    df.columns = [c.lower() for c in df.columns]

    # Ensure expected columns exist
    for c in ['jwt_secret_length', 'cookie_secure', 'cookie_httponly', 'session_timeout']:
        if c not in df.columns:
            df[c] = 0

    # Coerce types safely
    df['jwt_secret_length'] = pd.to_numeric(df['jwt_secret_length'], errors='coerce').fillna(0).astype(int).clip(lower=0)
    df['cookie_secure'] = pd.to_numeric(df['cookie_secure'], errors='coerce').fillna(0).astype(int)
    df['cookie_secure'] = df['cookie_secure'].apply(lambda x: 1 if x >= 1 else 0)
    df['cookie_httponly'] = pd.to_numeric(df['cookie_httponly'], errors='coerce').fillna(0).astype(int)
    df['cookie_httponly'] = df['cookie_httponly'].apply(lambda x: 1 if x >= 1 else 0)
    df['session_timeout'] = pd.to_numeric(df['session_timeout'], errors='coerce').fillna(0).astype(int).clip(lower=0)

    # Apply labeling rules with priority: high -> medium -> low/none
    vuln_list = []
    sev_list = []
    for _, row in df.iterrows():
        jwt_len = int(row['jwt_secret_length'])
        cookie_sec = int(row['cookie_secure'])
        cookie_http = int(row['cookie_httponly'])
        session_t = int(row['session_timeout'])

        # Priority 1: high severity rules
        if jwt_len < 16:
            vuln_list.append('weak_jwt_secret')
            sev_list.append('high')
            continue
        if cookie_sec == 0:
            vuln_list.append('insecure_cookie')
            sev_list.append('high')
            continue

        # Priority 2: medium severity
        if cookie_http == 0:
            vuln_list.append('missing_httponly')
            sev_list.append('medium')
            continue
        if session_t > 3600:
            vuln_list.append('long_session')
            sev_list.append('medium')
            continue

        # No issue
        vuln_list.append('none')
        sev_list.append('low')

    df['vulnerability'] = vuln_list
    df['severity'] = sev_list

    # Keep only required columns in order
    out_cols = ['jwt_secret_length', 'cookie_secure', 'cookie_httponly', 'session_timeout', 'vulnerability', 'severity']
    for c in out_cols:
        if c not in df.columns:
            df[c] = 0
    return df[out_cols]


def main():
    args = parse_args()
    cleaned_in = Path(args.cleaned_in).resolve()
    features_in = Path(args.features_in).resolve()

    if args.inplace:
        cleaned_out = cleaned_in
        features_out = features_in
    else:
        cleaned_out = Path(args.cleaned_out).resolve()
        features_out = Path(args.features_out).resolve()

    # Process cleaned dataset
    if not cleaned_in.exists():
        logging.error('Input cleaned dataset not found: %s', cleaned_in)
    else:
        df_cleaned = pd.read_csv(cleaned_in, dtype=object)
        df_fixed = fix_cleaned(df_cleaned)
        cleaned_out.parent.mkdir(parents=True, exist_ok=True)
        df_fixed.to_csv(cleaned_out, index=False)
        logging.info('Wrote fixed cleaned dataset to %s', cleaned_out)

    # Process features dataset
    if not features_in.exists():
        logging.error('Input features dataset not found: %s', features_in)
    else:
        df_feat = pd.read_csv(features_in, dtype=object)
        df_feat_fixed = fix_features(df_feat)
        features_out.parent.mkdir(parents=True, exist_ok=True)
        df_feat_fixed.to_csv(features_out, index=False)
        logging.info('Wrote fixed features dataset to %s', features_out)

    # Summary
    total_rows = 0
    vuln_count = 0
    if (args.inplace and cleaned_in.exists()) or (not args.inplace and cleaned_out.exists()):
        df_final = pd.read_csv(cleaned_out, dtype=object)
        total_rows = len(df_final)

    if (args.inplace and features_in.exists()) or (not args.inplace and features_out.exists()):
        dff = pd.read_csv(features_out, dtype=object)
        vuln_count = (dff['vulnerability'] != 'none').sum()

    print(f"Total rows processed: {total_rows}")
    print(f"Number of vulnerabilities detected: {vuln_count}")
    print(f"Cleaned output: {cleaned_out}")
    print(f"Features output: {features_out}")


if __name__ == '__main__':
    main()
