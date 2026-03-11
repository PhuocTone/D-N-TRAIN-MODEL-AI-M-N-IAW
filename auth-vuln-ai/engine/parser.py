"""Config parser: normalize input JSON into typed config dict."""
from typing import Dict, Any


def _to_bool_int(v) -> int:
    try:
        if v is None:
            return 0
        if isinstance(v, bool):
            return 1 if v else 0
        vi = int(v)
        return 1 if vi >= 1 else 0
    except Exception:
        vs = str(v).strip().lower()
        return 1 if vs in ("1", "true", "yes", "y") else 0


def parse_config(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize and type-cast config values.

    Ensures keys are the expected ones and converts types:
      - JWT_SECRET_LENGTH: int
      - COOKIE_SECURE: int (0/1)
      - COOKIE_HTTPONLY: int (0/1)
      - SESSION_TIMEOUT: int
    """
    cfg = {}
    # Use .get with defaults and cast
    cfg['JWT_SECRET_LENGTH'] = int(raw.get('JWT_SECRET_LENGTH') or 0)
    cfg['COOKIE_SECURE'] = _to_bool_int(raw.get('COOKIE_SECURE'))
    cfg['COOKIE_HTTPONLY'] = _to_bool_int(raw.get('COOKIE_HTTPONLY'))
    try:
        cfg['SESSION_TIMEOUT'] = int(raw.get('SESSION_TIMEOUT') or 0)
    except Exception:
        cfg['SESSION_TIMEOUT'] = 0
    return cfg
