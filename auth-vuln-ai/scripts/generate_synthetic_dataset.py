import json
import random
from datetime import datetime

OUTPUT = "c:/Users/ADMIN/Documents/AI/auth-vuln-ai/data/raw/synthetic_configs.json"
TOTAL = 5000

labels = [
    "weak_jwt_secret",
    "missing_jwt_expiration",
    "insecure_cookie",
    "missing_httponly",
    "missing_samesite",
    "long_session_timeout",
    "session_fixation",
    "oauth_redirect_misconfig",
    "weak_password_policy",
    "none",
]

# severity mapping
severity_map = {
    "weak_jwt_secret": "critical",
    "missing_jwt_expiration": "high",
    "insecure_cookie": "high",
    "missing_httponly": "high",
    "missing_samesite": "high",
    "long_session_timeout": "medium",
    "session_fixation": "medium",
    "oauth_redirect_misconfig": "high",
    "weak_password_policy": "medium",
    "none": "low",
}

# allocate counts: 25% secure (none)
none_count = int(TOTAL * 0.25)
remaining = TOTAL - none_count
# distribute evenly among the other 9 labels
per_label = remaining // (len(labels) - 1)
remainder = remaining - per_label * (len(labels) - 1)

counts = {}
for l in labels:
    counts[l] = 0
counts["none"] = none_count

other_labels = [l for l in labels if l != "none"]
for i, l in enumerate(other_labels):
    counts[l] = per_label + (1 if i < remainder else 0)

# helper generators

def jwt_weak(i):
    return f"JWT_SECRET=pass{i}"  

def jwt_missing_exp(i):
    return f"JWT_SECRET=Str0ngKey_{i}\n# missing JWT_EXPIRATION"

def cookie_insecure(i):
    variants = [
        f"COOKIE_SECURE=false\nCOOKIE_HTTPONLY=true\nCOOKIE_SAMESITE=Lax",
        f"Set-Cookie: session={i}; Secure=false; HttpOnly=true",
        f"COOKIE_SECURE=false\nCOOKIE_HTTPONLY=false",
    ]
    return random.choice(variants)

def missing_httponly(i):
    return f"COOKIE_HTTPONLY=false\nCOOKIE_SECURE=true"

def missing_samesite(i):
    return f"COOKIE_SAMESITE=None\nCOOKIE_HTTPONLY=true"

def long_session(i):
    secs = random.choice([2592000, 604800, 31536000, 1209600])
    return f"SESSION_TIMEOUT={secs}"

def session_fix(i):
    return f"SESSION_ID_IN_URL=true\nSESSION_ID_ROTATION=false"

def oauth_mis(i):
    variants = [
        f"OAUTH_REDIRECT_URI=http://malicious.com/callback{i}",
        f"OAUTH_REDIRECT_URI=https://app.example.com/callback?next=http://evil.com/{i}",
        f"oauth.redirect_uri=*",
    ]
    return random.choice(variants)

def weak_pw(i):
    return f"PASSWORD_MIN_LENGTH={random.choice([1,3,4,5,6])}\nPASSWORD_REQUIRE_SPECIAL=false\nPASSWORD_COMPLEXITY=low"

def secure_sample(i):
    return (
        "JWT_SECRET=Str0ng!Secret_{}\nJWT_EXPIRATION=900\nCOOKIE_SECURE=true\n" 
        "COOKIE_HTTPONLY=true\nCOOKIE_SAMESITE=Strict\nSESSION_TIMEOUT=900\n" 
        "SESSION_ID_ROTATION=true\nPASSWORD_MIN_LENGTH=12\nPASSWORD_REQUIRE_SPECIAL=true\n".format(i)
    )

# generate samples
samples = []
used_configs = set()

def add_sample(config, vuln):
    # avoid duplicates naive way
    key = config
    if key in used_configs:
        return False
    used_configs.add(key)
    samples.append({
        "config": config,
        "vulnerability": vuln,
        "severity": severity_map[vuln]
    })
    return True

idx = 0
for label in other_labels:
    target = counts[label]
    i = 0
    while i < target:
        idx += 1
        if label == "weak_jwt_secret":
            cfg = jwt_weak(idx)
        elif label == "missing_jwt_expiration":
            cfg = jwt_missing_exp(idx)
        elif label == "insecure_cookie":
            cfg = cookie_insecure(idx)
        elif label == "missing_httponly":
            cfg = missing_httponly(idx)
        elif label == "missing_samesite":
            cfg = missing_samesite(idx)
        elif label == "long_session_timeout":
            cfg = long_session(idx)
        elif label == "session_fixation":
            cfg = session_fix(idx)
        elif label == "oauth_redirect_misconfig":
            cfg = oauth_mis(idx)
        elif label == "weak_password_policy":
            cfg = weak_pw(idx)
        else:
            cfg = ""
        if add_sample(cfg, label):
            i += 1

# add secure samples
i = 0
while i < counts["none"]:
    idx += 1
    cfg = secure_sample(idx)
    if add_sample(cfg, "none"):
        i += 1

# final sanity
random.shuffle(samples)

with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(samples, f, ensure_ascii=False, indent=2)

print(f"Wrote {len(samples)} samples to {OUTPUT}")
