from pathlib import Path
from scanner import iter_source_files, relative_to
import re


ROUTE_PATTERNS = [
    (r'@app\.(get|post|put|delete|patch)\(', 'FastAPI route'),
    (r'\.(get|post|put|delete|patch)\s*\(["\']/', 'Express route'),
    (r'router\.(get|post|put|delete|patch)\(', 'Express router'),
    (r'@app\.route\(', 'Flask route'),
    (r'@router\.(get|post|put|delete|patch)\(', 'FastAPI router'),
    (r'app\.(get|post|put|delete|patch)\s*\(', 'Next.js API route'),
    (r'def\s+.*\(request.*\):', 'Django/Flask view'),
]


AUTH_MIDDLEWARE_PATTERNS = [
    'authenticate', 'auth_required', 'login_required', 'require_auth',
    '@login_required', '@auth', 'middleware', 'authMiddleware',
    'verify_token', 'verifyAuth', 'isAuthenticated', 'protectRoute',
    'getSession', 'getToken', 'session', 'jwt.verify',
]


def check_auth_middleware(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"
    api_routes_found = []
    auth_middleware_found = []
    unprotected_routes = []

    # Scan for auth middleware usage
    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            rel = relative_to(fpath, target)

            # Check for route definitions
            for pattern, desc in ROUTE_PATTERNS:
                if re.search(pattern, text):
                    api_routes_found.append((rel, desc))

            # Check for auth middleware
            for pattern in AUTH_MIDDLEWARE_PATTERNS:
                if pattern in text:
                    auth_middleware_found.append((rel, pattern))

        except (PermissionError, UnicodeDecodeError):
            continue

    if auth_middleware_found:
        unique_files = set(str(f) for f, _ in auth_middleware_found)
        details.append(f"[PASS] Auth middleware/references found in {len(unique_files)} file(s)")
        for f, pat in auth_middleware_found[:5]:
            details.append(f"  - {f} uses: {pat}")
    else:
        findings.append("No auth middleware detected in codebase")
        details.append("[FAIL] No authentication middleware found")
        severity = "CRITICAL"

    if api_routes_found:
        unique_route_files = set(str(f) for f, _ in api_routes_found)
        details.append(f"[INFO] Found route definitions in {len(unique_route_files)} file(s)")
        for f, desc in api_routes_found[:10]:
            details.append(f"  - {f}: {desc}")

        # Check if routes are in files without auth middleware
        route_files = set(str(f) for f, _ in api_routes_found)
        auth_files = set(str(f) for f, _ in auth_middleware_found)
        potentially_unprotected = route_files - auth_files
        if potentially_unprotected:
            for f in list(potentially_unprotected)[:10]:
                unprotected_routes.append(f)
                details.append(f"[WARN] {f} has routes but no auth middleware detected in same file")
            if severity == "LOW":
                severity = "HIGH"
    else:
        details.append("[INFO] No API route definitions found (might be frontend-only project)")

    summary = f"Found {len(findings)} issue(s)" if findings else "Auth middleware appears present"
    return {
        "id": "AUTH_MIDDLEWARE",
        "name": "Auth Middleware",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
