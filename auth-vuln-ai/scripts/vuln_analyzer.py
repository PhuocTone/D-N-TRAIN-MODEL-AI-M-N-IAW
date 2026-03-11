#!/usr/bin/env python3
"""
Authentication Vulnerability Analyzer

Pipeline stages:
- Parser: load config and rules
- Feature extractor: compute security features
- Blacklist engine: detect immediate rule matches
- ML model (heuristic): score and classify overall risk
- Report generator: structured vulnerability report (text + optional JSON)

Usage:
  python vuln_analyzer.py --config path/to/config.json --rules path/to/rules.json [--output-json path]
"""
from __future__ import annotations
import argparse
import json
import re
from typing import Any, Dict, List, Optional


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_by_path(obj: Any, path: str):
    if path is None or path == "":
        return obj
    parts = path.split('.')
    cur = obj
    for p in parts:
        m = re.match(r"([a-zA-Z0-9_\-]+)\[(\d+)\]$", p)
        if m:
            key, idx = m.group(1), int(m.group(2))
            if not isinstance(cur, dict) or key not in cur:
                return None
            arr = cur.get(key)
            if not isinstance(arr, list) or idx >= len(arr):
                return None
            cur = arr[idx]
            continue
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur


def eval_rule(value: Any, operator: str, expected: Any) -> bool:
    if operator == "equals":
        return value == expected
    if operator == "not_equals":
        return value != expected
    if operator in ("lt", "lte", "gt", "gte"):
        try:
            v = float(value)
            e = float(expected)
        except Exception:
            return False
        if operator == "lt":
            return v < e
        if operator == "lte":
            return v <= e
        if operator == "gt":
            return v > e
        if operator == "gte":
            return v >= e
    if operator == "length_lt":
        try:
            return len(value) < int(expected)
        except Exception:
            return False
    if operator == "length_gt":
        try:
            return len(value) > int(expected)
        except Exception:
            return False
    if operator == "contains":
        try:
            return expected in value
        except Exception:
            return False
    if operator == "missing":
        return value is None
    if operator == "is_false":
        return value is False or str(value).lower() == "false"
    if operator == "is_true":
        return value is True or str(value).lower() == "true"
    if operator == "regex":
        try:
            return re.search(expected, str(value)) is not None
        except Exception:
            return False
    return False


def run_blacklist_checks(config: Dict[str, Any], rules: List[Dict[str, Any]]):
    matches = []
    for r in rules:
        path = r.get("path")
        op = r.get("operator")
        expected = r.get("value")
        value = get_by_path(config, path)
        if eval_rule(value, op, expected):
            matches.append({
                "id": r.get("id"),
                "description": r.get("description"),
                "path": path,
                "operator": op,
                "expected": expected,
                "found_value": value,
                "risk": r.get("risk"),
                "recommendation": r.get("recommendation"),
            })
    return matches


def extract_features(config: Dict[str, Any]) -> Dict[str, Any]:
    f = {}
    f["jwt_secret_length"] = None
    secret = get_by_path(config, "jwt.secret")
    if isinstance(secret, str):
        f["jwt_secret_length"] = len(secret)
    f["jwt_expires_in"] = get_by_path(config, "jwt.expires_in")
    f["jwt_algorithm"] = get_by_path(config, "jwt.algorithm")
    f["cookie_secure"] = get_by_path(config, "cookie.secure")
    f["cookie_http_only"] = get_by_path(config, "cookie.http_only")
    f["session_timeout"] = get_by_path(config, "session.timeout")
    f["mfa_enabled"] = get_by_path(config, "mfa.enabled") or get_by_path(config, "mfa")
    f["token_storage"] = get_by_path(config, "token.storage") or get_by_path(config, "token_storage")
    return f


def ml_score_and_classify(features: Dict[str, Any], blacklist_matches: List[Dict[str, Any]]):
    # Heuristic scoring model. Higher score => higher risk.
    score = 0
    details = []

    # Count blacklist matches
    score += len(blacklist_matches) * 3
    if blacklist_matches:
        details.append(f"{len(blacklist_matches)} blacklist rule(s) matched")

    # Weak JWT secret
    jlen = features.get("jwt_secret_length")
    if jlen is None:
        score += 2
        details.append("JWT secret missing or not a string")
    else:
        if jlen < 16:
            score += 4
            details.append("JWT secret very short (<16)")
        elif jlen < 32:
            score += 3
            details.append("JWT secret short (<32)")
        elif jlen < 64:
            score += 1

    # Session timeout
    st = features.get("session_timeout")
    try:
        if st is not None:
            st_v = float(st)
            if st_v > 3600:
                score += 2
                details.append("Session timeout > 3600s")
            elif st_v > 1800:
                score += 1
    except Exception:
        pass

    # Cookie flags
    if features.get("cookie_secure") is False:
        score += 2
        details.append("Cookie Secure flag disabled")
    if features.get("cookie_http_only") is False:
        score += 2
        details.append("Cookie HttpOnly flag disabled")

    # MFA
    if features.get("mfa_enabled") in (False, None, "false", "False"):
        score += 1
        details.append("MFA not enabled")

    # token storage
    if features.get("token_storage") in ("localStorage", "LocalStorage"):
        score += 2
        details.append("Insecure token storage (localStorage)")

    # Map score to risk level
    if score >= 8:
        level = "Critical"
    elif score >= 5:
        level = "High"
    elif score >= 3:
        level = "Medium"
    else:
        level = "Low"

    return {"score": score, "level": level, "details": details}


def generate_report(config_path: str, config: Dict[str, Any], features: Dict[str, Any], blacklist_matches: List[Dict[str, Any]], ml_result: Dict[str, Any]) -> Dict[str, Any]:
    issues = []
    # Convert blacklist matches to report items
    for m in blacklist_matches:
        # map some simple rules to detected problem text
        problem = m.get("description") or m.get("id")
        risk_level = ml_result.get("level")
        issues.append({
            "configuration_issue": problem,
            "detected_problem": problem,
            "risk_level": risk_level,
            "description": m.get("risk"),
            "triggered_rule": f"{m.get('id')} ({m.get('operator')})",
            "matched_value": m.get("found_value"),
            "recommendation": m.get("recommendation"),
        })

    # Add heuristic-detected issues not covered by blacklist
    # Example: weak jwt secret even if no rule
    jlen = features.get("jwt_secret_length")
    if jlen is not None and jlen < 32:
        if not any(i for i in issues if "JWT" in i.get("configuration_issue", "")):
            issues.append({
                "configuration_issue": "Weak JWT Secret",
                "detected_problem": f"JWT secret length {jlen} < 32",
                "risk_level": ml_result.get("level"),
                "description": "JWT secret shorter than recommended length",
                "triggered_rule": "jwt.secret length < 32",
                "matched_value": jlen,
                "recommendation": "Use a secret key with at least 32–64 characters and high entropy.",
            })

    report = {
        "config_path": config_path,
        "overall_risk": ml_result.get("level"),
        "score": ml_result.get("score"),
        "ml_details": ml_result.get("details"),
        "features": features,
        "issues": issues,
    }
    return report


def print_human_report(report: Dict[str, Any]):
    print()
    print("Vulnerability Report")
    print("Configuration Path:", report.get("config_path"))
    print("Overall Risk Level:", report.get("overall_risk"), f"(score={report.get('score')})")
    print()
    for idx, it in enumerate(report.get("issues", []), start=1):
        print(f"Issue {idx}:")
        print(f"Configuration Issue: {it.get('configuration_issue')}")
        print(f"Detected Problem: {it.get('detected_problem')}")
        print(f"Risk Level: {it.get('risk_level')}")
        print()
        print("Description:")
        print(it.get("description"))
        print()
        print(f"Triggered Rule: {it.get('triggered_rule')}")
        if it.get("matched_value") is not None:
            print(f"Matched Value: {it.get('matched_value')}")
        print()
        print("Recommendation:")
        print(it.get("recommendation"))
        print("-" * 60)


def main():
    parser = argparse.ArgumentParser(description="Authentication Vulnerability Analyzer")
    parser.add_argument("--config", required=True, help="Path to authentication config JSON")
    parser.add_argument("--rules", required=True, help="Path to blacklist rules JSON")
    parser.add_argument("--output-json", required=False, help="Optional output path for machine-readable report JSON")
    args = parser.parse_args()

    config = load_json(args.config)
    rules = load_json(args.rules)

    features = extract_features(config)
    blacklist_matches = run_blacklist_checks(config, rules)
    ml_result = ml_score_and_classify(features, blacklist_matches)

    report = generate_report(args.config, config, features, blacklist_matches, ml_result)

    print_human_report(report)

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\nSaved JSON report to {args.output_json}")

if __name__ == "__main__":
    main()
