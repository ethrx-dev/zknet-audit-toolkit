from pathlib import Path
from scanner import iter_source_files, relative_to
import re


UPLOAD_PATTERNS = [
    (r'file.*upload', 'File upload endpoint'),
    (r'multer', 'Multer middleware (Node.js uploads)'),
    (r'FileField', 'Django file field'),
    (r'file_field', 'Django REST file field'),
    (r'FileUpload', 'File upload component'),
    (r'upload_file', 'upload_file function'),
    (r'request\.files', 'Flask file upload'),
    (r'request\.FILES', 'Django file upload'),
    (r'form-data', 'multipart form data'),
    (r'multipart', 'multipart upload'),
    (r'upload', 'upload reference'),
    (r'fileInput', 'file input element'),
]

SECURITY_PATTERNS = [
    (r'magic.*bytes?', 'Magic byte validation'),
    (r'file.*type.*check', 'File type validation'),
    (r'content.type', 'Content-Type validation'),
    (r'mimetype', 'MIME type check'),
    (r'uuid.*rename|uuid.*file', 'UUID file renaming'),
    (r'uuid4\(\)', 'UUID generation'),
    (r's3|r2|gcs|storage\.', 'External storage'),
    (r'max.*size|size.*limit', 'Size limit'),
    (r'size.*limit', 'Size limit enforcement'),
    (r'file.*size', 'File size check'),
]


def check_file_uploads(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"

    upload_files = []
    security_measures = []

    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            rel = relative_to(fpath, target)

            for pattern, desc in UPLOAD_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    upload_files.append((rel, desc))

            for pattern, desc in SECURITY_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    security_measures.append((rel, desc))

        except (PermissionError, UnicodeDecodeError):
            continue

    if not upload_files:
        details.append("[PASS] No file upload functionality detected (N/A)")
        summary = "No file uploads detected — N/A"
        return {
            "id": "FILE_UPLOADS",
            "name": "File Uploads",
            "status": "PASS",
            "severity": "LOW",
            "summary": summary,
            "details": details,
            "findings": [],
        }

    details.append(f"[INFO] File upload references found in {len(upload_files)} file(s)")
    for f, d in upload_files[:10]:
        details.append(f"  - {f}: {d}")

    # Categorize security measures
    has_type_validation = any('magic' in d.lower() or 'type' in d.lower() or 'MIME' in d for _, d in security_measures)
    has_renaming = any('UUID' in d or 'uuid' in d for _, d in security_measures)
    has_external_storage = any('External' in d for _, d in security_measures)
    has_size_limit = any('Size' in d or 'size' in d for _, d in security_measures)

    if security_measures:
        details.append(f"[PASS] Security measures found: {len(security_measures)} reference(s)")

    if not has_type_validation:
        findings.append("No file type validation (magic bytes) detected")
        details.append("[WARN] File type validation by magic bytes not detected")
        severity = "MEDIUM"

    if not has_renaming:
        findings.append("No UUID-based file renaming detected")
        details.append("[WARN] No UUID file renaming detected")
        if severity == "LOW":
            severity = "MEDIUM"

    if not has_external_storage:
        details.append("[INFO] No external storage (S3/R2) detected — files may be stored locally")

    if not has_size_limit:
        details.append("[INFO] No file size limit detected")

    summary = f"Found {len(findings)} file upload issue(s)" if findings else "File uploads appear secured"
    return {
        "id": "FILE_UPLOADS",
        "name": "File Uploads",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
