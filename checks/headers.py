from pathlib import Path
from scanner import iter_source_files, relative_to
import re


REQUIRED_HEADERS = {
    'Content-Security-Policy': 'Content-Security-Policy header',
    'Strict-Transport-Security': 'HSTS header',
    'X-Frame-Options': 'X-Frame-Options header',
    'X-Content-Type-Options': 'X-Content-Type-Options header',
    'Referrer-Policy': 'Referrer-Policy header',
}


FRAMEWORK_PATTERNS = [
    ('helmet', 'Express/Hapi helmet middleware'),
    ('Secure', 'security middleware'),
    ('csp', 'CSP middleware'),
    ('Content-Security-Policy', 'inline CSP header'),
    ('security_headers', 'custom security headers middleware'),
    ('add_header', 'Nginx/other security headers'),
]


def check_security_headers(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"
    found_headers = set()
    found_frameworks = set()

    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            rel = relative_to(fpath, target)

            for header, desc in REQUIRED_HEADERS.items():
                if header in text or header.replace('-', '_') in text:
                    found_headers.add(header)
                    details.append(f"[PASS] {header} referenced in {rel}")

            for pattern, desc in FRAMEWORK_PATTERNS:
                if pattern in text:
                    found_frameworks.add(desc)
                    details.append(f"[PASS] {desc} found in {rel}")

        except (PermissionError, UnicodeDecodeError):
            continue

    missing = set(REQUIRED_HEADERS.keys()) - found_headers
    if missing:
        findings.append(f"Missing {len(missing)} security header(s): {', '.join(missing)}")
        for h in missing:
            details.append(f"[FAIL] {h} not found in any config")
        severity = "MEDIUM"

    if not missing and not found_headers:
        details.append("[INFO] No security header config found (check server/reverse proxy)")

    summary = f"Missing {len(missing)} header(s)" if missing else "All required security headers found"
    return {
        "id": "SECURITY_HEADERS",
        "name": "Security Headers",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
