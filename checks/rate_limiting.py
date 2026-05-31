from pathlib import Path
from scanner import iter_source_files, relative_to
import re


RATE_LIMIT_PATTERNS = [
    ('rate_limit', 'rate_limit decorator/function'),
    ('ratelimit', 'ratelimit package'),
    ('RateLimiter', 'RateLimiter class'),
    ('throttle', 'throttle function'),
    ('limiter', 'limiter middleware'),
    ('@limits', 'flask-limiter decorator'),
    ('slowapi', 'SlowAPI'),
    ('express-rate-limit', 'express-rate-limit middleware'),
    ('rate-limiting', 'rate limiting config'),
]

AUTH_ENDPOINT_PATTERNS = [
    'login', 'signin', 'sign-up', 'register', 'signup',
    'password-reset', 'forgot-password', 'reset-password',
]


def check_rate_limiting(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"

    rate_limit_found = False
    auth_endpoints_found = []

    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            rel = relative_to(fpath, target)

            for pattern, desc in RATE_LIMIT_PATTERNS:
                if pattern in text or pattern.lower() in text.lower():
                    rate_limit_found = True
                    details.append(f"[PASS] Rate limiting: {desc} in {rel}")

            for endpoint in AUTH_ENDPOINT_PATTERNS:
                if endpoint in text.lower() and any(p in text.lower() for p in ['route', 'def ', 'path', 'app.', 'router.']):
                    auth_endpoints_found.append((rel, endpoint))

        except (PermissionError, UnicodeDecodeError):
            continue

    if rate_limit_found:
        details.append("[PASS] Rate limiting middleware detected")
    else:
        findings.append("No rate limiting detected")
        details.append("[WARN] No rate limiting middleware found")
        severity = "MEDIUM"

    if auth_endpoints_found:
        auth_files = set(str(f) for f, _ in auth_endpoints_found)
        details.append(f"[INFO] Found auth-related endpoints in {len(auth_files)} file(s)")
        for f, ep in auth_endpoints_found[:5]:
            details.append(f"  - {f}: {ep}")
        if not rate_limit_found:
            findings.append("Auth endpoints found without rate limiting")
            details.append("[FAIL] Auth endpoints without rate limiting detected")
            severity = "HIGH"

    summary = f"Found {len(findings)} rate limiting issue(s)" if findings else "Rate limiting appears present"
    return {
        "id": "RATE_LIMITING",
        "name": "Rate Limiting",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
