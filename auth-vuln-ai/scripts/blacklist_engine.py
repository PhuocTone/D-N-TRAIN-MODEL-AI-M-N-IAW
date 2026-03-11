#!/usr/bin/env python3
"""
Simple Blacklist Engine for authentication configuration checks.

Usage:
  python blacklist_engine.py --config path/to/config.json --rules path/to/rules.json

Rules format: a JSON array of rule objects. Example rule keys:
  - id
  - description
  - path (dotted path into config, e.g. "jwt.secret")
  - operator (equals, not_equals, lt, lte, gt, gte, length_lt, length_gt, contains, missing, is_false, is_true)
  - value (value to compare against)
  - risk
  - recommendation

The script prints detected issues with explanation and recommendation.
"""
from __future__ import annotations
import argparse
import json
import re
from typing import Any, Dict, List


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_by_path(obj: Any, path: str):
    if path is None or path == "":
        return obj
    parts = path.split('.')
    cur = obj
    for p in parts:
        # allow array index like items[0]
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
    # unknown operator -> no match
    return False


def human_issue(rule: Dict[str, Any], value: Any) -> str:
    desc = rule.get("description") or rule.get("id")
    return f"Issue: {desc}\nRule Triggered: {rule.get('description', rule.get('id'))}\nRisk: {rule.get('risk', 'No risk provided.')}\nRecommendation: {rule.get('recommendation', 'No recommendation provided.')}"


def run_checks(config: Dict[str, Any], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    issues = []
    for r in rules:
        path = r.get("path")
        op = r.get("operator")
        expected = r.get("value")
        value = get_by_path(config, path)
        triggered = eval_rule(value, op, expected)
        if triggered:
            issues.append({
                "issue": r.get("description", r.get("id")),
                "rule": r,
                "found_value": value,
            })
    return issues


def print_issues(issues: List[Dict[str, Any]]):
    if not issues:
        print("No blacklist rule violations detected.")
        return
    for it in issues:
        rule = it["rule"]
        print()
        print(f"Issue: {it['issue']}")
        print(f"Rule Triggered: {rule.get('description', rule.get('id'))}")
        if it.get('found_value') is not None:
            print(f"Matched Value: {it.get('found_value')}")
        print(f"Risk: {rule.get('risk', 'No risk provided.')}")
        print(f"Recommendation: {rule.get('recommendation', 'No recommendation provided.')}")


def main():
    parser = argparse.ArgumentParser(description="Blacklist engine for auth configs")
    parser.add_argument("--config", required=True, help="Path to auth config JSON")
    parser.add_argument("--rules", required=True, help="Path to blacklist rules JSON")
    args = parser.parse_args()

    config = load_json(args.config)
    rules = load_json(args.rules)

    issues = run_checks(config, rules)
    print_issues(issues)


if __name__ == "__main__":
    main()
