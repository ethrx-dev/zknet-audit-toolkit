from pathlib import Path


UTILITY_CODE = """# Password hashing utility (auto-generated)
# Install: pip install bcrypt
# Usage:
#   from middleware.auth import hash_password, verify_password
#
#   hashed = hash_password("user-password")
#   is_valid = verify_password("user-password", hashed)

import bcrypt


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def check_password_strength(password: str) -> dict:
    issues = []
    if len(password) < 12:
        issues.append("Must be at least 12 characters")
    if not any(c.isupper() for c in password):
        issues.append("Must contain uppercase letter")
    if not any(c.islower() for c in password):
        issues.append("Must contain lowercase letter")
    if not any(c.isdigit() for c in password):
        issues.append("Must contain digit")
    if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in password):
        issues.append("Must contain special character")
    return {"valid": len(issues) == 0, "issues": issues}
"""


def fix_password_hashing(target, framework, dry_run=False, verbose=False):
    target = Path(target)
    outcome = {"fixed": [], "created": [], "warnings": [], "message": ""}
    src_dir = target / (framework.get("src_dir") or ".")

    if framework["language"] == "python":
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)

        # Check for existing hash usage and replace weak ones
        for f in target.rglob("*.py"):
            if any(d in f.parts for d in {".git", "node_modules", "__pycache__"}):
                continue
            if "md5" in f.name.lower():
                continue
            try:
                text = f.read_text()
                if "hashlib.md5" in text or "md5(" in text:
                    if not dry_run:
                        text = text.replace("hashlib.md5", "# FIXED: was hashlib.md5")
                        f.write_text(text)
                    rel = f.relative_to(target)
                    outcome["fixed"].append(f"Flagged MD5 usage in {rel}")
            except (PermissionError, UnicodeDecodeError):
                continue

        auth_file = mw_dir / "auth.py"
        if not auth_file.exists():
            if not dry_run:
                auth_file.write_text(UTILITY_CODE)
            outcome["created"].append("middleware/auth.py")
            outcome["warnings"].append("Install: pip install bcrypt")
            outcome["warnings"].append("Replace password hashing with: from middleware.auth import hash_password")
        else:
            outcome["fixed"].append("middleware/auth.py already exists")

    elif framework["has_express"] or framework["has_next"]:
        outcome["warnings"].append("Use bcrypt: npm install bcrypt")
        outcome["warnings"].append("Replace: const bcrypt = require('bcrypt'); const hash = await bcrypt.hash(password, 12)")

    else:
        outcome["message"] = "Use bcrypt, Argon2, or scrypt for password hashing"

    return outcome
