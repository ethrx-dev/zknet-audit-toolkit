import subprocess
import re
from pathlib import Path
from scanner import iter_source_files, relative_to


SECRET_PATTERNS = [
    (r'sk_live_[0-9a-zA-Z]+', 'Stripe secret key (live)'),
    (r'sk_test_[0-9a-zA-Z]+', 'Stripe secret key (test)'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    (r'-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----', 'Private key'),
    (r'ghp_[0-9a-zA-Z]{36}', 'GitHub personal access token'),
    (r'gho_[0-9a-zA-Z]{36}', 'GitHub OAuth token'),
    (r'xox[baprs]-[0-9a-zA-Z-]+', 'Slack token'),
    (r'sqlite:///[^\s]+', 'SQLite path (check for creds)'),
    (r'postgresql://[^@]+@', 'PostgreSQL connection string'),
    (r'mongodb[^:]*://[^@]+@', 'MongoDB connection string'),
    (r'redis://[^@]+@', 'Redis connection string'),
    (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password'),
    (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret'),
    (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key'),
    (r'token\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']', 'Hardcoded token'),
]


def check_secrets_exposure(target, verbose=False):
    target = Path(target)
    env_file = target / ".env"
    gitignore = target / ".gitignore"
    details = []
    findings = []
    severity = "LOW"

    # Check .env is in .gitignore
    env_ignored = False
    if gitignore.exists():
        content = gitignore.read_text()
        if ".env" in content:
            env_ignored = True
            details.append("[PASS] .env is in .gitignore")
        else:
            findings.append(".env is NOT in .gitignore")
            details.append("[FAIL] .env missing from .gitignore")
            severity = "CRITICAL"
    else:
        findings.append("No .gitignore found")
        details.append("[FAIL] No .gitignore file found")
        severity = "CRITICAL"

    # Check .env is not tracked by git
    try:
        result = subprocess.run(
            ["git", "ls-files", ".env"],
            cwd=target,
            capture_output=True, text=True, timeout=10
        )
        if result.stdout.strip():
            findings.append(".env is tracked by git!")
            details.append("[FAIL] .env is tracked by version control")
            severity = "CRITICAL"
        else:
            details.append("[PASS] .env not tracked by git")
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        details.append("[SKIP] Could not check git tracking (not a git repo or git unavailable)")

    # Scan source files for secret patterns
    secret_matches = []

    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            for pattern, desc in SECRET_PATTERNS:
                matches = re.findall(pattern, text)
                for m in matches:
                    rel = relative_to(fpath, target)
                    secret_matches.append((rel, desc, m[:30]))
        except (PermissionError, UnicodeDecodeError):
            continue

    if secret_matches:
        findings.append(f"Found {len(secret_matches)} potential secrets in source files")
        severity = "CRITICAL"
        for rel, desc, preview in secret_matches[:20]:
            details.append(f"[FAIL] {desc} in {rel}: {preview}...")
        if len(secret_matches) > 20:
            details.append(f"  ... and {len(secret_matches) - 20} more matches")
    else:
        details.append("[PASS] No secrets found in source files")

    # Check .env.example
    env_example = target / ".env.example"
    if env_example.exists():
        content = env_example.read_text()
        real_values = re.findall(r'=\s*["\']?[A-Za-z0-9_\-]{16,}["\']?', content)
        if real_values:
            findings.append(".env.example contains real-looking values")
            details.append("[FAIL] .env.example has placeholder values that look real")
            severity = "CRITICAL"
        else:
            details.append("[PASS] .env.example has placeholder values")
    else:
        details.append("[INFO] No .env.example found")

    summary = f"Found {len(findings)} issue(s), {len(secret_matches)} secret pattern match(es)" if findings else "No exposed secrets found"
    return {
        "id": "SECRETS_EXPOSURE",
        "name": "Exposed Secrets",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
