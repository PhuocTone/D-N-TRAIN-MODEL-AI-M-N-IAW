"""Rule-based blacklist engine for common auth config issues."""
from typing import Dict, List


def run_blacklist_rules(cfg: Dict[str, int]) -> List[str]:
    vulns = []
    if cfg.get('JWT_SECRET_LENGTH', 0) < 16:
        vulns.append('Weak JWT secret')
    if int(cfg.get('COOKIE_SECURE', 0)) == 0:
        vulns.append('Cookie missing Secure flag')
    if int(cfg.get('COOKIE_HTTPONLY', 0)) == 0:
        vulns.append('Cookie missing HttpOnly flag')
    if int(cfg.get('SESSION_TIMEOUT', 0)) > 3600:
        vulns.append('Long session timeout')
    return vulns
