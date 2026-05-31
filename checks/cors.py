from pathlib import Path
from scanner import iter_source_files, relative_to
import re


WILDCARD_PATTERNS = [
    (r"origin\s*:\s*['\"]\*['\"]", 'CORS origin wildcard'),
    (r"Access-Control-Allow-Origin\s*:?\s*\*", 'ACAO wildcard header'),
    (r"allow_origins\s*=\s*\[?\s*['\"]\*['\"]", 'FastAPI CORS wildcard'),
    (r"origins\s*:\s*\[?\s*['\"]\*['\"]", 'CORS config wildcard'),
    (r"Origin\s*:\s*true", 'Dynamic origin reflection'),
]


def check_cors(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"

    cors_files = []
    wildcard_found = False

    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            rel = relative_to(fpath, target)

            has_cors = any(p in text for p in ['cors', 'CORS', 'Access-Control'])
            if has_cors:
                cors_files.append(rel)

            for pattern, desc in WILDCARD_PATTERNS:
                if re.search(pattern, text):
                    wildcard_found = True
                    findings.append(f"Wildcard CORS: {desc}")
                    details.append(f"[FAIL] {desc} in {rel}")
                    severity = "CRITICAL"

        except (PermissionError, UnicodeDecodeError):
            continue

    if cors_files and not wildcard_found:
        details.append(f"[PASS] CORS configured in {len(cors_files)} file(s) without wildcards")
        for f in cors_files[:5]:
            details.append(f"  - {f}")
    elif not cors_files:
        details.append("[INFO] No CORS configuration found (may not need it if API and frontend are same origin)")

    summary = f"Found {len(findings)} CORS issue(s)" if findings else "CORS appears correctly configured"
    return {
        "id": "CORS",
        "name": "CORS Configuration",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
