from pathlib import Path


UTILITY_CODE = """# File upload validation utility (auto-generated)
# Usage:
#   from middleware.uploads import validate_file, save_upload
#
#   result = validate_file(uploaded_file)
#   if result["valid"]:
#       path = save_upload(uploaded_file, "uploads/")
#   else:
#       return {"error": result["reason"]}

import uuid
import os
from pathlib import Path


ALLOWED_MIME_TYPES = {
    "image/jpeg": [b"\\xff\\xd8\\xff"],
    "image/png": [b"\\x89PNG"],
    "image/gif": [b"GIF8"],
    "image/webp": [b"RIFF"],
    "application/pdf": [b"%PDF"],
    "text/plain": [],
    "text/csv": [],
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


def check_magic_bytes(data: bytes, mime_type: str) -> bool:
    signatures = ALLOWED_MIME_TYPES.get(mime_type, [])
    if not signatures:
        return True
    for sig in signatures:
        if data[:len(sig)] == sig:
            return True
    return False


def validate_file(file) -> dict:
    if file.size > MAX_FILE_SIZE:
        return {"valid": False, "reason": f"File too large (max {MAX_FILE_SIZE // 1024 // 1024}MB)"}

    data = file.read(1024)
    file.seek(0)

    if not check_magic_bytes(data, file.content_type):
        return {"valid": False, "reason": f"File type mismatch: declared {file.content_type} but magic bytes don't match"}

    return {"valid": True}


def save_upload(file, upload_dir: str) -> str:
    ext = Path(file.filename).suffix if file.filename else ".bin"
    filename = f"{uuid.uuid4()}{ext}"
    dest = Path(upload_dir) / filename
    dest.parent.mkdir(parents=True, exist_ok=True)

    with open(dest, "wb") as f:
        f.write(file.read())

    return str(dest)
"""


def fix_file_uploads(target, framework, dry_run=False, verbose=False):
    target = Path(target)
    outcome = {"fixed": [], "created": [], "warnings": [], "message": ""}
    src_dir = target / (framework.get("src_dir") or ".")

    if framework["language"] == "python":
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
        up_file = mw_dir / "uploads.py"
        if not up_file.exists():
            if not dry_run:
                up_file.write_text(UTILITY_CODE)
            outcome["created"].append("middleware/uploads.py")
            outcome["warnings"].append("Use: from middleware.uploads import validate_file, save_upload")
        else:
            outcome["fixed"].append("middleware/uploads.py already exists")

    elif framework["has_express"] or framework["has_next"]:
        outcome["warnings"].append("Use multer with fileFilter for magic byte validation")
        outcome["warnings"].append("Store files on external storage (S3/R2), rename to UUIDs")

    else:
        outcome["message"] = "Validate file type by magic bytes, rename to UUID, store externally"

    return outcome
