from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import joblib
import numpy as np
from pathlib import Path

from engine.parser import parse_config
from engine.feature_extractor import extract_features
from engine.blacklist_engine import run_blacklist_rules
from engine.vulnerability_analyzer import analyze_with_model
from engine.recommendation_engine import recommendations_from_vulns


app = FastAPI(title="Auth Config Vulnerability Analyzer")


class AnalyzeRequest(BaseModel):
    JWT_SECRET_LENGTH: int
    COOKIE_SECURE: int
    COOKIE_HTTPONLY: int
    SESSION_TIMEOUT: int


class AnalyzeResponse(BaseModel):
    risk_score: int
    vulnerabilities: List[str]
    recommendations: List[str]


MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "model_auth_vuln.pkl"


@app.on_event("startup")
def load_model():
    global MODEL
    if not MODEL_PATH.exists():
        raise RuntimeError(f"Model not found: {MODEL_PATH}")
    MODEL = joblib.load(MODEL_PATH)


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    # 1) Parse configuration
    config = parse_config(req.dict())

    # 2) Extract features
    features = extract_features(config)

    # 3) Run blacklist rules
    vulns = run_blacklist_rules(config)

    # 4) Run ML model prediction and get probability
    prob = analyze_with_model(MODEL, features)

    # 5) Calculate risk score: base = len(vulns)*2, ml component scaled to 0-2
    ml_component = int(round(float(prob) * 2))
    risk_score = min(10, len(vulns) * 2 + ml_component)

    # 6) Recommendations
    recs = recommendations_from_vulns(vulns)

    return {
        "risk_score": int(risk_score),
        "vulnerabilities": vulns,
        "recommendations": recs,
    }
