#!/usr/bin/env python3
"""
Parse `dataset_cleaned2.csv` config column into numeric features and regenerate
`dataset_features2.csv` with correct values and vulnerability labels.

Usage:
  python parse_cleaned_to_features.py \
    --input ../data/processed/dataset_cleaned2.csv \
    --output ../dataset/dataset_features2.csv

Prints a summary after running.
"""
from pathlib import Path
import argparse
import logging
import pandas as pd


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def parse_args():
    p = argparse.ArgumentParser(description="Parse cleaned config into features")
    p.add_argument("--input", "-i", default="../data/processed/dataset_cleaned2.csv")
    p.add_argument("--output", "-o", default="../dataset/dataset_features2.csv")
    return p.parse_args()


def parse_config_string(cfg: str) -> dict:
    """Parse semicolon-separated key=value pairs from cfg string.

    Returns a dict with keys uppercased. Missing keys are absent.
    """
    result = {}
    if not isinstance(cfg, str):
        return result
    parts = [p.strip() for p in cfg.split(';') if p and p.strip()]
    for part in parts:
        if '=' in part:
            k, v = part.split('=', 1)
        elif ':' in part:
            k, v = part.split(':', 1)
        else:
            continue
        key = k.strip().upper()
        val = v.strip()
        result[key] = val
    return result


def to_int_safe(v, default=0):
    try:
        if v is None:
            return default
        return int(float(v))
    except Exception:
        return default


def label_row(jwt_len, cookie_secure, cookie_httponly, session_timeout):
    """Apply labeling rules and return (vulnerability, severity)."""
    # Priority: high (weak_jwt_secret, insecure_cookie), then medium, then none/low
    if jwt_len < 16:
        return 'weak_jwt_secret', 'high'
    if cookie_secure == 0:
        return 'insecure_cookie', 'high'
    if cookie_httponly == 0:
        return 'missing_httponly', 'medium'
    if session_timeout > 3600:
        return 'long_session', 'medium'
    return 'none', 'low'


def main():
    args = parse_args()
    inp = Path(args.input).resolve()
    out = Path(args.output).resolve()

    if not inp.exists():
        logging.error('Input not found: %s', inp)
        raise SystemExit(1)

    df = pd.read_csv(inp, dtype=str)
    logging.info('Read %d rows from %s', len(df), inp)

    rows = []
    vuln_count = 0
    for _, r in df.iterrows():
        cfg = r.get('config') if 'config' in r.index else None
        parsed = parse_config_string(cfg)

        jwt_len = to_int_safe(parsed.get('JWT_SECRET_LENGTH') or parsed.get('JWT_SECRET') or parsed.get('JWT_SECRET_LEN'))
        cookie_secure = to_int_safe(parsed.get('COOKIE_SECURE'))
        cookie_httponly = to_int_safe(parsed.get('COOKIE_HTTPONLY'))
        session_timeout = to_int_safe(parsed.get('SESSION_TIMEOUT'))

        vuln, sev = label_row(jwt_len, cookie_secure, cookie_httponly, session_timeout)
        if vuln != 'none':
            vuln_count += 1

        rows.append({
            'jwt_secret_length': jwt_len,
            'cookie_secure': cookie_secure,
            'cookie_httponly': cookie_httponly,
            'session_timeout': session_timeout,
            'vulnerability': vuln,
            'severity': sev,
        })

    out_df = pd.DataFrame(rows)

    out.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(out, index=False)
    print(f'Total rows processed: {len(out_df)}')
    print(f'Number of vulnerabilities detected: {vuln_count}')
    print(f'Output file: {out}')


if __name__ == '__main__':
    main()
