import json
import random
from datetime import datetime
random.seed(42)

total = 5000
none_ratio = 0.25
none_count = int(total * none_ratio)
other_count = total - none_count
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
]
# distribute other_count across labels
base = other_count // len(labels)
remainder = other_count - base * len(labels)
counts = {label: base for label in labels}
for i in range(remainder):
    counts[labels[i]] += 1

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

items = []
used = set()

def unique_config(conf):
    if conf in used:
        # append small random token until unique
        suffix = 1
        while conf + f"\n#id={suffix}" in used:
            suffix += 1
        conf = conf + f"\n#id={suffix}"
    used.add(conf)
    return conf

# generators per label

def gen_weak_jwt(i):
    v = random.choice(["12345", "password", "secret", "jwtsecret", "admin", "letmein"])
    conf = f"JWT_SECRET={v}{i}"
    return unique_config(conf)

def gen_missing_jwt_exp(i):
    secret = "S3cureKey!" + str(i)
    conf = f"JWT_SECRET={secret}\n# no JWT_EXPIRATION provided"
    return unique_config(conf)

def gen_insecure_cookie(i):
    templates = [
        "COOKIE_SECURE=false",
        "Set-Cookie: session=abc; Secure=false; HttpOnly=true",
        "session.cookie_secure=false",
        "COOKIE_SECURE=false\nCOOKIE_HTTPONLY=false",
        "COOKIE_SECURE=false\nCOOKIE_SAMESITE=None",
    ]
    conf = random.choice(templates) + f"\n#id={i}"
    return unique_config(conf)

def gen_missing_httponly(i):
    templates = [
        "COOKIE_HTTPONLY=false",
        "Set-Cookie: sid=abc; HttpOnly=false; Secure=true",
        "session.cookie_httponly=false",
    ]
    conf = random.choice(templates) + f"\n#id={i}"
    return unique_config(conf)

def gen_missing_samesite(i):
    templates = [
        "COOKIE_SAMESITE=None",
        "COOKIE_SAMESITE=",
        "session.cookie_samesite=",
        "Set-Cookie: sid=abc; SameSite=; Secure=true",
    ]
    conf = random.choice(templates) + f"\n#id={i}"
    return unique_config(conf)

def gen_long_session(i):
    # seconds large
    secs = random.choice([2592000, 604800, 31536000, 1209600, 864000])
    conf = f"SESSION_TIMEOUT={secs}\nSESSION_ID_ROTATION={random.choice(["true","false"]) }"
    conf += f"\n#id={i}"
    return unique_config(conf)

def gen_session_fixation(i):
    templates = [
        "SESSION_ID_IN_URL=true\nSESSION_ID_ROTATION=false",
        "session.allow_url_session=true\nsession.rotate_on_login=false",
        "SESSION_ID_IN_URL=true\nSESSION_TIMEOUT=3600",
    ]
    conf = random.choice(templates) + f"\n#id={i}"
    return unique_config(conf)

def gen_oauth_misconfig(i):
    templates = [
        f"OAUTH_REDIRECT_URI=http://malicious.com/callback?id={i}",
        "oauth.redirect_uri=*",
        "OAUTH_REDIRECT_URI=https://*.example.com/callback",
        "OAUTH_REDIRECT_URI=https://app.example.com/callback?next=https://attacker.com",
    ]
    conf = random.choice(templates) + f"\n#id={i}"
    return unique_config(conf)

def gen_weak_password(i):
    minlen = random.choice([1,3,4,5,6])
    special = random.choice(["false","false","true"])  # bias towards false
    complexity = random.choice(["low","none","weak"]) 
    conf = f"PASSWORD_MIN_LENGTH={minlen}\nPASSWORD_REQUIRE_SPECIAL={special}\nPASSWORD_COMPLEXITY={complexity}"
    conf += f"\n#id={i}"
    return unique_config(conf)


generators = {
    "weak_jwt_secret": gen_weak_jwt,
    "missing_jwt_expiration": gen_missing_jwt_exp,
    "insecure_cookie": gen_insecure_cookie,
    "missing_httponly": gen_missing_httponly,
    "missing_samesite": gen_missing_samesite,
    "long_session_timeout": gen_long_session,
    "session_fixation": gen_session_fixation,
    "oauth_redirect_misconfig": gen_oauth_misconfig,
    "weak_password_policy": gen_weak_password,
}

# generate others
counter = 0
for label, cnt in counts.items():
    for _ in range(cnt):
        counter += 1
        conf = generators[label](counter)
        items.append({"config": conf, "vulnerability": label, "severity": severity_map[label]})

# generate 'none' secure samples
for i in range(none_count):
    counter += 1
    conf = (
        f"JWT_SECRET=Str0ng!Secret_{i}\nJWT_EXPIRATION=900\nCOOKIE_SECURE=true\nCOOKIE_HTTPONLY=true\n"
        f"COOKIE_SAMESITE=Strict\nSESSION_TIMEOUT=900\nSESSION_ID_ROTATION=true\nPASSWORD_MIN_LENGTH=12\n"
        f"PASSWORD_REQUIRE_SPECIAL=true\nPASSWORD_COMPLEXITY=high\nOAUTH_REDIRECT_URI=https://app.example.com/callback#id={i}"
    )
    conf = unique_config(conf)
    items.append({"config": conf, "vulnerability": "none", "severity": severity_map["none"]})

# shuffle to avoid blocks
random.shuffle(items)

# final sanity checks
assert len(items) == total, f"Expected {total}, got {len(items)}"

# write to file in project folder
out_path = r"c:/Users/ADMIN/Documents/AI/dự án AI/auth_dataset_5000.json"
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(items, f, ensure_ascii=False, indent=2)

print(f"Wrote {len(items)} samples to {out_path}")
