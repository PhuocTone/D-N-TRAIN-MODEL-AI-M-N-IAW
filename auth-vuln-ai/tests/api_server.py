from fastapi import FastAPI
import subprocess
import json
import tempfile
import os

app = FastAPI()

@app.post("/analyze")
def analyze_config(config: dict):
    # tạo file config tạm
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w") as f:
        json.dump(config, f)
        config_path = f.name

    rules_path = "scripts/rules.json"

    # chạy analyzer
    result = subprocess.run(
        ["python", "scripts/vuln_analyzer.py", "--config", config_path, "--rules", rules_path],
        capture_output=True,
        text=True
    )

    os.remove(config_path)

    return {"analysis_result": result.stdout}