from pathlib import Path
from scanner import iter_source_files, relative_to
import re


ERROR_PATTERNS = [
    (r'debug\s*=\s*True', 'Debug mode enabled (Django/Flask)'),
    (r'DEBUG\s*=\s*true', 'Debug mode enabled (Node/Django)'),
    (r'debug:\s*true', 'Debug mode in config'),
    (r'NODE_ENV\s*=\s*development', 'Node.js development mode'),
    (r'APP_ENV\s*=\s*development', 'App development mode'),
    (r'DEVELOPMENT\s*=\s*True', 'Development mode'),
]

GOOD_PATTERNS = [
    (r'try\s*{', 'Try/except block'),
    (r'except\s', 'Exception handler'),
    (r'catch\s*\(', 'Catch block'),
    (r'error.*handler|error_handler|errorHandler', 'Error handler middleware'),
    (r'global.*error|GlobalError', 'Global error handler'),
    (r'app\.use\(.*err', 'Express error middleware'),
    (r'@app\.errorhandler', 'Flask error handler'),
    (r'ExceptionHandler', 'Exception handler class'),
    (r'middleware.*error|error.*middleware', 'Error middleware'),
    (r'generic.*error|error.*generic', 'Generic error response'),
    (r'production.*false|debug.*false', 'Production mode'),
]


def check_error_handling(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"

    debug_modes_found = []
    error_handlers_found = []

    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            rel = relative_to(fpath, target)

            for pattern, desc in ERROR_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    debug_modes_found.append((rel, desc))
                    findings.append(f"Debug/development mode: {desc}")
                    details.append(f"[FAIL] {desc} in {rel}")
                    severity = "MEDIUM"

            for pattern, desc in GOOD_PATTERNS:
                if re.search(pattern, text):
                    error_handlers_found.append((rel, desc))

        except (PermissionError, UnicodeDecodeError):
            continue

    if error_handlers_found:
        unique_handlers = set(d for _, d in error_handlers_found)
        details.append(f"[PASS] Error handling mechanisms found: {', '.join(unique_handlers)}")
        for f, d in error_handlers_found[:5]:
            details.append(f"  - {f}: {d}")

    if not debug_modes_found:
        details.append("[PASS] No debug/development mode detected in config")

    if not error_handlers_found and not debug_modes_found:
        details.append("[INFO] No error handling or debug mode config found")

    summary = f"Found {len(findings)} error handling issue(s)" if findings else "Error handling appears adequate"
    return {
        "id": "ERROR_HANDLING",
        "name": "Error Handling",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
