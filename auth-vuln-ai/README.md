auth-vuln-ai

Project scaffold for authentication vulnerability dataset and ML pipeline.

Structure created by assistant. Data generator available at `scripts/generate_synthetic_dataset.py`.

Authentication Vulnerability Analyzer
-----------------------------------

What this does
- Parses authentication configuration files (JWT, cookies, sessions).
- Extracts security features and runs blacklist rules.
- Applies a heuristic ML-style scorer to classify risk.
- Generates a human-readable report and JSON output.

Key files
- `scripts/vuln_analyzer.py`: Main analyzer pipeline.
- `scripts/blacklist_engine.py`: Lightweight rule engine used for focused checks.
- `data/raw/sample_auth_config.json`: Example config used for testing.
- `data/raw/blacklist_rules.json`: Example blacklist rules.
- `data/processed/vuln_report.json`: Example generated report (JSON).

Quick start
From the repository root run:

```bash
python auth-vuln-ai/scripts/vuln_analyzer.py \
	--config auth-vuln-ai/data/raw/sample_auth_config.json \
	--rules auth-vuln-ai/data/raw/blacklist_rules.json \
	--output-json auth-vuln-ai/data/processed/vuln_report.json
```

Output
- The analyzer prints a human-readable vulnerability report to stdout and, if `--output-json` is provided, writes a structured JSON report.

Next steps you can ask me to do
- Add more blacklist rules (MFA, token rotation, CSP, etc.).
- Produce SARIF/Markdown report formats or CI integration.
- Replace heuristic scoring with a trained ML model and sample dataset.
