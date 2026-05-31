from pathlib import Path
from scanner import iter_source_files, relative_to
import re


def check_access_control(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"

    idor_risk_patterns = [
        r'user_id\s*=\s*request\.',
        r'params\.id',
        r'query\.id',
        r'body\.id',
        r'\[id\]',
        r':id\b',
        r'/<int:id>',
        r'/{id}',
    ]

    ownership_check_patterns = [
        'owner_id', 'user_id ==', 'user.id', 'current_user',
        'request.user', 'owner', 'creator_id', 'author_id',
        'user.id !=', 'user_id !=', 'owner=', 'user_id=',
    ]

    routes_with_ids = []
    ownership_checks = []

    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            rel = relative_to(fpath, target)

            has_id_param = any(re.search(p, text) for p in idor_risk_patterns)
            has_ownership = any(p in text for p in ownership_check_patterns)

            if has_id_param:
                routes_with_ids.append(rel)
            if has_ownership:
                ownership_checks.append(rel)

        except (PermissionError, UnicodeDecodeError):
            continue

    if routes_with_ids:
        details.append(f"[INFO] Found {len(routes_with_ids)} file(s) with ID parameters (potential IDOR targets)")
        for f in routes_with_ids[:10]:
            details.append(f"  - {f}")

    if ownership_checks:
        details.append(f"[PASS] Ownership checks found in {len(ownership_checks)} file(s)")
        for f in ownership_checks[:5]:
            details.append(f"  - {f}")

    # Cross-reference: files with IDs but no ownership check
    route_set = set(str(f) for f in routes_with_ids)
    ownership_set = set(str(f) for f in ownership_checks)
    missing_checks = route_set - ownership_set

    if missing_checks:
        findings.append(f"{len(missing_checks)} file(s) have ID parameters but no ownership check detected")
        severity = "HIGH"
        for f in list(missing_checks)[:10]:
            details.append(f"[WARN] {f} uses ID param but no ownership check found")
    else:
        details.append("[PASS] All files with ID parameters appear to have ownership checks")

    summary = f"Found {len(findings)} issue(s)" if findings else "Ownership checks appear present"
    return {
        "id": "ACCESS_CONTROL",
        "name": "Access Control (IDOR)",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
