from pathlib import Path
from scanner import iter_source_files, relative_to
import re


HASH_PATTERNS = [
    (r'bcrypt', 'bcrypt [GOOD]'),
    (r'argon2', 'argon2 [GOOD]'),
    (r'scrypt', 'scrypt [GOOD]'),
    (r'md5', 'MD5 [WEAK]'),
    (r'md5_hash', 'MD5 hash [WEAK]'),
    (r'hashlib\.md5', 'MD5 via hashlib [WEAK]'),
    (r'SHA-1', 'SHA-1 [WEAK]'),
    (r'sha1', 'SHA-1 [WEAK]'),
    (r'sha256.*password', 'SHA-256 for passwords [WEAK]'),
    (r'pbkdf2', 'PBKDF2 [OK if sufficient iterations]'),
]

AUTH_PROVIDERS = [
    'Auth0', 'Supabase Auth', 'Firebase Auth', 'Clerk', 'NextAuth',
    'next-auth', 'auth.js', 'Auth.js', 'Passport', 'oauth',
]


def check_password_hashing(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"

    hashes_found = {'good': [], 'weak': [], 'ok': []}
    auth_providers_found = []

    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            rel = relative_to(fpath, target)

            for pattern, desc in HASH_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    if '[GOOD]' in desc:
                        hashes_found['good'].append((rel, desc))
                    elif '[WEAK]' in desc:
                        hashes_found['weak'].append((rel, desc))
                    else:
                        hashes_found['ok'].append((rel, desc))

            for provider in AUTH_PROVIDERS:
                if provider in text:
                    auth_providers_found.append((rel, provider))

        except (PermissionError, UnicodeDecodeError):
            continue

    # Check if using third-party auth (makes this N/A)
    if auth_providers_found:
        providers = set(p for _, p in auth_providers_found)
        details.append(f"[INFO] Third-party auth provider(s) detected: {', '.join(providers)}")
        details.append("[INFO] Password hashing handled by provider (N/A)")
        summary = "Using third-party auth provider — password hashing N/A"
        return {
            "id": "PASSWORD_HASHING",
            "name": "Password Hashing",
            "status": "PASS",
            "severity": "LOW",
            "summary": summary,
            "details": details,
            "findings": [],
        }

    if hashes_found['good']:
        good_set = set(d for _, d in hashes_found['good'])
        details.append(f"[PASS] Strong hashing algorithm(s) found: {', '.join(good_set)}")
        for f, d in hashes_found['good'][:5]:
            details.append(f"  - {f}: {d}")

    if hashes_found['weak']:
        findings.append(f"Found {len(hashes_found['weak'])} weak hash usage(s)")
        for f, d in hashes_found['weak'][:10]:
            details.append(f"[FAIL] {d} in {f}")
        severity = "MEDIUM"

    if not hashes_found['good'] and not hashes_found['weak'] and not auth_providers_found:
        details.append("[INFO] No password hashing references found (may use auth provider)")

    summary = f"Found {len(findings)} password hashing issue(s)" if findings else "Password hashing appears secure"
    return {
        "id": "PASSWORD_HASHING",
        "name": "Password Hashing",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
