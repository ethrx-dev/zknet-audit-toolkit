from pathlib import Path
from scanner import iter_source_files, relative_to
import re


CSRF_PATTERNS = {
    'SameSite=Lax': 'SameSite=Lax cookie setting',
    'SameSite=Strict': 'SameSite=Strict cookie setting',
    'SameSite=None': 'SameSite=None (insecure)',
    'csrf': 'CSRF token/reference',
    'csrf_protect': 'CSRF protection',
    'csrf_exempt': 'CSRF exemption',
    'CSRFToken': 'CSRF token generation',
    'XSRF-TOKEN': 'XSRF token',
}

BEARER_PATTERNS = [
    r'Authorization:\s*Bearer',
    r'["\']Authorization["\']\s*[:=]\s*["\']Bearer\s',
    r'headers\.get\(["\']Authorization["\']\)',
    r'headers\[["\']Authorization["\']\]',
    r'bearer_token',
    r'token\s*=\s*headers',
]


def check_csrf(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"

    found_patterns = {k: [] for k in CSRF_PATTERNS}
    uses_bearer_auth = False

    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            rel = relative_to(fpath, target)
            for pattern, desc in CSRF_PATTERNS.items():
                if pattern in text or pattern.lower() in text.lower():
                    found_patterns[pattern].append(str(rel))
            for bearer_pat in BEARER_PATTERNS:
                if re.search(bearer_pat, text, re.IGNORECASE):
                    uses_bearer_auth = True
        except (PermissionError, UnicodeDecodeError):
            continue

    samsite_secure = found_patterns['SameSite=Lax'] + found_patterns['SameSite=Strict']
    samsite_insecure = found_patterns['SameSite=None']
    csrf_tokens = found_patterns['csrf'] + found_patterns['CSRFToken'] + found_patterns['XSRF-TOKEN']

    has_cookie_protection = bool(samsite_secure) or (
        bool(csrf_tokens) and
        bool(found_patterns['csrf_protect'] or found_patterns['CSRFToken'])
    )

    if samsite_secure:
        details.append(f"[PASS] SameSite cookie settings found (Lax/Strict) in {len(samsite_secure)} file(s)")
        for f in samsite_secure[:3]:
            details.append(f"  - {f}")
    else:
        details.append("[INFO] No SameSite cookie settings detected")

    if samsite_insecure:
        details.append(f"[INFO] SameSite=None found in {len(samsite_insecure)} file(s)")

    if csrf_tokens:
        details.append(f"[PASS] CSRF token references found in {len(set(csrf_tokens))} file(s)")
    else:
        details.append("[INFO] No CSRF token references found")

    if uses_bearer_auth:
        details.append("[INFO] Bearer token auth detected — CSRF via cookies not applicable")
        if not has_cookie_protection:
            severity = "LOW"

    if not has_cookie_protection and not uses_bearer_auth:
        findings.append("No CSRF protection detected (SameSite or CSRF tokens)")
        details.append("[WARN] No CSRF protection mechanism found")
        severity = "HIGH"

    summary = f"Found {len(findings)} CSRF issue(s)" if findings else "CSRF protection appears present"
    return {
        "id": "CSRF",
        "name": "Cross-Site Request Forgery",
        "status": "PASS" if not findings else "FAIL",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
