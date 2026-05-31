from pathlib import Path
from scanner import iter_source_files, relative_to


def check_database_access(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"

    # Check for Supabase config
    supabase_files = [fpath for fpath in iter_source_files(target) if 'supabase' in fpath.name.lower()]

    if supabase_files:
        details.append(f"[INFO] Found {len(supabase_files)} Supabase-related files")
        for f in supabase_files[:5]:
            rel = relative_to(f, target)
            try:
                text = f.read_text(errors='ignore').lower()
                if 'rls' not in text and 'row level security' not in text:
                    findings.append(f"No RLS mention in {rel}")
                    details.append(f"[FAIL] {rel} has no RLS/Row Level Security reference")
                    severity = "CRITICAL"
                else:
                    details.append(f"[PASS] {rel} references RLS")
            except (PermissionError, UnicodeDecodeError):
                continue
    else:
        details.append("[INFO] No Supabase config found (N/A if not using Supabase)")

    # Check for Firebase config
    firebase_files = [fpath for fpath in iter_source_files(target) if 'firebase' in fpath.name.lower()]
    if firebase_files:
        details.append(f"[INFO] Found {len(firebase_files)} Firebase-related files")
        for f in firebase_files[:3]:
            rel = relative_to(f, target)
            try:
                text = f.read_text(errors='ignore')
                if '.write' in text and 'auth != null' not in text:
                    findings.append(f"Firebase rules may not require auth in {rel}")
                    details.append(f"[FAIL] {rel}: potential unauthenticated write access")
                    severity = "CRITICAL"
                else:
                    details.append(f"[PASS] {rel}: auth requirement detected")
            except (PermissionError, UnicodeDecodeError):
                continue
    else:
        details.append("[INFO] No Firebase config found (N/A if not using Firebase)")

    # Check for SQLite in dev
    sqlite_files = [fpath for fpath in iter_source_files(target) if fpath.suffix in ('.db', '.sqlite')]
    if sqlite_files:
        details.append(f"[INFO] Found {len(sqlite_files)} database files")

    # Check for raw SQL patterns that might bypass RLS
    raw_db_patterns = ['.raw(', '.query(', 'execute(', '.sql(', 'prisma.$queryRaw']
    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            for pattern in raw_db_patterns:
                if pattern in text:
                    rel = relative_to(fpath, target)
                    details.append(f"[INFO] {rel} uses {pattern} (verify RLS not bypassed)")
        except (PermissionError, UnicodeDecodeError):
            continue

    if not findings:
        details.append("[PASS] No database access issues detected")
        summary = "No database access issues found"
    else:
        summary = f"Found {len(findings)} database access issue(s)"

    return {
        "id": "DATABASE_ACCESS",
        "name": "Database Access Control",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
