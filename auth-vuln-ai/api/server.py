"""
FastAPI service for scanning authentication configuration files.

Endpoint:
  POST /scan-auth-config

Behavior:
- Accepts an uploaded JSON config file or a JSON body.
- Saves a temporary config file and runs the existing analyzer pipeline
  (`auth-vuln-ai/scripts/vuln_analyzer.py`) to produce a JSON report.
- Returns a concise JSON response with score, vulnerabilities, and recommendations.

Also exposes a small CLI test: `python server.py --config path/to/config.json`
which runs the scan and prints summarized JSON to stdout.
"""
from __future__ import annotations
import json
import os
import subprocess
import tempfile
from typing import List
from fastapi import FastAPI, File, UploadFile, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Auth Config Scanner")

# Paths (workspace-relative)
ANALYZER = os.path.join("auth-vuln-ai", "scripts", "vuln_analyzer.py")
RULES = os.path.join("auth-vuln-ai", "data", "raw", "blacklist_rules.json")

class ScanResult(BaseModel):
    score: float
    vulnerabilities: List[str]
    recommendations: List[str]
    raw_report: dict


def run_analyzer_on_file(config_path: str) -> dict:
    out_fd, out_path = tempfile.mkstemp(prefix="vuln_report_", suffix=".json", dir=os.path.join("auth-vuln-ai","data","processed"))
    os.close(out_fd)
    cmd = [
        "python",
        ANALYZER,
        "--config",
        config_path,
        "--rules",
        RULES,
        "--output-json",
        out_path,
    ]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Analyzer failed: {e.stderr.decode('utf-8', errors='replace')}" )
    with open(out_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    # keep the generated file for inspection
    return report


def summarize_report(report: dict) -> ScanResult:
    score = report.get("score")
    issues = report.get("issues", [])
    vulnerabilities = [i.get("configuration_issue") for i in issues]
    recommendations = [i.get("recommendation") for i in issues if i.get("recommendation")]
    return ScanResult(score=score or 0, vulnerabilities=vulnerabilities, recommendations=recommendations, raw_report=report)


@app.post("/scan-auth-config", response_model=ScanResult)
async def scan_auth_config(file: UploadFile = File(...)):
    if file.content_type != "application/json":
        raise HTTPException(status_code=400, detail="Only application/json uploads are accepted")
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="uploaded_config_", suffix=".json")
    os.close(tmp_fd)
    try:
        contents = await file.read()
        with open(tmp_path, "wb") as f:
            f.write(contents)
        report = run_analyzer_on_file(tmp_path)
        result = summarize_report(report)
        return result
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run analyzer on a config file and print summary JSON")
    parser.add_argument("--config", help="Path to config JSON to scan")
    args = parser.parse_args()
    if not args.config:
        print("Provide --config path")
        raise SystemExit(1)
    if not os.path.exists(args.config):
        print("Config file not found:", args.config)
        raise SystemExit(2)
    report = run_analyzer_on_file(args.config)
    summary = summarize_report(report)
    print(json.dumps(summary.dict(), indent=2))
