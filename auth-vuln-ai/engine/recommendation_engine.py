"""Generate remediation recommendations based on detected vulnerabilities."""
from typing import List


RECOMMENDATION_MAP = {
    'Weak JWT secret': 'Use 256-bit JWT secret',
    'Cookie missing Secure flag': 'Enable Secure flag',
    'Cookie missing HttpOnly flag': 'Enable HttpOnly flag',
    'Long session timeout': 'Reduce session timeout to <= 3600 seconds',
}


def recommendations_from_vulns(vulns: List[str]) -> List[str]:
    recs = []
    for v in vulns:
        r = RECOMMENDATION_MAP.get(v)
        if r and r not in recs:
            recs.append(r)
    return recs
