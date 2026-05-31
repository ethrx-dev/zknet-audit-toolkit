from pathlib import Path
from scanner import iter_source_files, relative_to
import re


PUBLIC_PREFIXES = ['NEXT_PUBLIC_', 'VITE_', 'REACT_APP_', 'NUXT_ENV_', 'GATSBY_', 'SANITY_STUDIO_']
SECRET_INDICATORS = ['key', 'secret', 'token', 'password', 'api_key', 'apikey', 'private', 'sk_', 'pk_', 'AKIA']


def check_frontend_secrets(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"

    frontend_dirs = ['src', 'app', 'pages', 'components', 'public']
    # Check env files for public prefix patterns with secret values
    for fpath in iter_source_files(target):
        if fpath.name != '.env' and not fpath.name.startswith('.env.'):
            continue
        try:
            text = fpath.read_text(errors='ignore')
            for line in text.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                for prefix in PUBLIC_PREFIXES:
                    if line.startswith(prefix):
                        val = line.split('=', 1)[1].strip().strip('"\'')
                        if val and val != 'your-key-here':
                            for indicator in SECRET_INDICATORS:
                                if indicator in prefix.lower() or indicator in line.lower():
                                    findings.append(f"Public env var may expose secret: {line[:60]}")
                                    details.append(f"[FAIL] {line.split('=')[0]} in {relative_to(fpath, target)} has potentially secret value")
                                    severity = "CRITICAL"
                                    break
        except (PermissionError, UnicodeDecodeError):
            continue

    # Check frontend source files for hardcoded credentials
    for fd in frontend_dirs:
        frontend_path = target / fd
        if not frontend_path.exists():
            continue
        for fpath in iter_source_files(frontend_path):
            try:
                text = fpath.read_text(errors='ignore')
                # Check for direct API key assignments
                key_patterns = re.findall(r'(sk_live_|sk_test_|AKIA|ghp_)[0-9a-zA-Z_-]{16,}', text)
                if key_patterns:
                    rel = relative_to(fpath, target)
                    findings.append(f"Secret keys found in frontend: {rel}")
                    for k in key_patterns[:5]:
                        details.append(f"[FAIL] Secret in frontend file {rel}: {k[:30]}...")
                    severity = "CRITICAL"
            except (PermissionError, UnicodeDecodeError):
                continue

    if not findings and not details:
        details.append("[PASS] No frontend secrets detected")
    elif not findings:
        details.append("[PASS] No secret keys found in frontend code")

    summary = f"Found {len(findings)} frontend secret issue(s)" if findings else "Frontend secrets check passed"
    return {
        "id": "FRONTEND_SECRETS",
        "name": "Frontend Secrets",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
