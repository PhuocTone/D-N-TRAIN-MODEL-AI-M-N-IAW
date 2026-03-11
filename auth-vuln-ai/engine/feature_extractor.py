"""Feature extractor: convert normalized config into model feature vector."""
from typing import Dict, List


def extract_features(cfg: Dict[str, int]) -> List[int]:
    """Return feature vector [jwt_secret_length, cookie_secure, cookie_httponly, session_timeout]"""
    return [
        int(cfg.get('JWT_SECRET_LENGTH', 0)),
        int(cfg.get('COOKIE_SECURE', 0)),
        int(cfg.get('COOKIE_HTTPONLY', 0)),
        int(cfg.get('SESSION_TIMEOUT', 0)),
    ]
