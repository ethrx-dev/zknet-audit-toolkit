from pathlib import Path
from scanner import iter_source_files, relative_to
import re


SSRF_PATTERNS = [
    (r'requests\.(get|post)\(.*url', 'Python requests library'),
    (r'urllib\.request', 'urllib library'),
    (r'httpx\.(get|post|put|delete)', 'httpx library'),
    (r'fetch\(', 'fetch API (Node/browser)'),
    (r'axios\.(get|post|put|delete)', 'axios library'),
    (r'http\.get\(', 'Node http.get'),
    (r'got\(', 'got library'),
    (r'\$\.(get|post|ajax)\(', 'jQuery AJAX'),
]

IP_BLOCK_PATTERNS = [
    '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '169.254.0.0/16', '::1', '0.0.0.0', 'localhost', 'private ip',
    'private_ip', 'is_internal', 'blocklist', 'block_list',
]


def check_ssrf(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"
    url_fetching_found = []

    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            rel = relative_to(fpath, target)

            for pattern, desc in SSRF_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    url_fetching_found.append((rel, desc))

        except (PermissionError, UnicodeDecodeError):
            continue

    if not url_fetching_found:
        details.append("[PASS] No URL fetching found (SSRF not applicable)")
        summary = "No URL fetching detected — SSRF N/A"
        return {
            "id": "SSRF",
            "name": "Server-Side Request Forgery",
            "status": "PASS",
            "severity": "LOW",
            "summary": summary,
            "details": details,
            "findings": findings,
        }

    details.append(f"[INFO] Found {len(url_fetching_found)} URL fetching usage(s)")
    for f, desc in url_fetching_found[:10]:
        details.append(f"  - {f}: {desc}")

    # Check if any URL validation/blocking is used alongside fetching
    blocking_found = set()
    for f, _ in url_fetching_found:
        try:
            text = Path(target / f).read_text(errors='ignore')
            for pattern in IP_BLOCK_PATTERNS:
                if pattern.lower() in text.lower():
                    blocking_found.add(str(f))
        except (PermissionError, UnicodeDecodeError):
            continue

    if blocking_found:
        details.append(f"[PASS] IP/URL validation found in {len(blocking_found)} file(s)")
        for f in blocking_found:
            details.append(f"  - {f} has IP validation")
    else:
        findings.append("URL fetching used without IP validation detected")
        details.append("[WARN] URL fetching found but no IP/private network validation detected")
        severity = "HIGH"

    summary = f"Found {len(findings)} SSRF issue(s)" if findings else "URL fetching with validation detected"
    return {
        "id": "SSRF",
        "name": "Server-Side Request Forgery",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
