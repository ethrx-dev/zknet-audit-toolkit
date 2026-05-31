from pathlib import Path
from scanner import iter_source_files, relative_to
import re


SQLI_PATTERNS = [
    (r'f["\'].*SELECT.*\{.*\}.*["\']', 'f-string with SQL and interpolation'),
    (r'f["\'].*INSERT.*\{.*\}.*["\']', 'f-string with SQL INSERT'),
    (r'f["\'].*UPDATE.*\{.*\}.*["\']', 'f-string with SQL UPDATE'),
    (r'f["\'].*DELETE.*\{.*\}.*["\']', 'f-string with SQL DELETE'),
    (r'f["\'].*WHERE.*\{.*\}.*["\']', 'f-string with SQL WHERE interpolation'),
    (r'f["\'].*FROM.*\{.*\}.*["\']', 'f-string with SQL FROM interpolation'),
    (r'\.format\(.*\).*SELECT', '.format in SQL query'),
    (r'\.format\(.*\).*INSERT', '.format in SQL query'),
    (r'\.format\(.*\).*DELETE', '.format in SQL query'),
]

TEMPLATE_LITERAL_PATTERNS = [
    (r'\$\{.*\}.*SELECT', 'template literal in SQL'),
    (r'\$\{.*\}.*FROM', 'template literal in SQL'),
    (r'\$\{.*\}.*WHERE', 'template literal in SQL'),
    (r'\$\{.*\}.*INSERT', 'template literal in SQL'),
    (r'\$\{.*\}.*UPDATE', 'template literal in SQL'),
    (r'\$\{.*\}.*DELETE', 'template literal in SQL'),
]


def check_sql_injection(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"

    dangerous_sql = []
    uses_parameterized = False

    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            rel = relative_to(fpath, target)

            for pattern, desc in SQLI_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    dangerous_sql.append((rel, desc))
                    findings.append(f"Potential SQL injection: {desc}")
                    details.append(f"[FAIL] {desc} in {rel}")
                    severity = "HIGH"

            for pattern, desc in TEMPLATE_LITERAL_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    dangerous_sql.append((rel, desc))

            for pattern in ['%s', '?', ':param', '$1']:
                if pattern in text:
                    uses_parameterized = True

            for keyword in ['.raw(', '.query_raw', 'prisma.$queryRaw']:
                if keyword in text:
                    details.append(f"[INFO] {rel} uses {keyword} (verify parameterization)")

        except (PermissionError, UnicodeDecodeError):
            continue

    if uses_parameterized and not dangerous_sql:
        details.append("[PASS] Parameterized queries detected")
    elif not dangerous_sql:
        details.append("[PASS] No raw SQL injection patterns found")

    if not dangerous_sql and uses_parameterized:
        details.append("[PASS] Database access appears to use parameterized queries")

    summary = f"Found {len(findings)} SQL injection risk(s)" if findings else "No SQL injection risks detected"
    return {
        "id": "SQL_INJECTION",
        "name": "SQL Injection",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
