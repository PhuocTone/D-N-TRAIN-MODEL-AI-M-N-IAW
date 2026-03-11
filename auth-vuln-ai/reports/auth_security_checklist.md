# Authentication Security Checklist

Generated from: `auth-vuln-ai/data/processed/vuln_report.json`
Date: 2026-03-11
Overall Risk: Critical (score=39)

---

## JWT
- ✖ **Weak JWT secret** — secret length 11 (recommend 32–64 chars, high entropy).
- ✔ **Token expiration** — access token expiry 3600s (acceptable; prefer shorter lifetimes).

## Cookies
- ✖ **Secure flag missing** — `cookie.secure` is false; enable Secure (HTTPS-only).
- ✖ **HttpOnly flag missing** — `cookie.http_only` is false; set HttpOnly to prevent JS access.
- ✖ **SameSite=None** — `cookie.same_site` = None; prefer `Lax` or `Strict` and add CSRF protections.

## Session Management
- ✖ **Session timeout too long** — `session.timeout` = 7200s; reduce to 900–1800s (15–30 minutes).

## MFA / Authentication Policies
- ✖ **Multi-Factor Authentication disabled** — `mfa.enabled` = false; enable MFA for sensitive accounts.

## Token Policies & Storage
- ✖ **Tokens stored in localStorage** — `token.storage` = localStorage; use HttpOnly secure cookies or other secure storage.
- ✖ **Token rotation disabled** — `token.rotation_enabled` = false; enable refresh token rotation and revoke on reuse.

## Password Storage
- ✖ **Weak password hash algorithm** — `password.hash_algo` contains `md5`; use bcrypt/scrypt/Argon2.

---

### Prioritized Remediation (Suggested order)
1. Rotate/replace JWT secret with a 32–64 char high-entropy secret.
2. Enable `cookie.secure` and `cookie.http_only` for auth/session cookies.
3. Move tokens out of `localStorage` into secure, HttpOnly cookies and enable token rotation.
4. Enable MFA for user accounts.
5. Reduce session timeout to 15–30 minutes.
6. Replace weak password hashing (MD5) with a slow adaptive hash.

### Files
- Vulnerability report: `auth-vuln-ai/data/processed/vuln_report.json`
- Analyzer: `auth-vuln-ai/scripts/vuln_analyzer.py`

