import json
import shutil
from pathlib import Path
from datetime import datetime

from fixes.framework import detect_framework
from fixes.secrets import fix_secrets
from fixes.headers import fix_headers
from fixes.cors import fix_cors
from fixes.csrf import fix_csrf
from fixes.rate_limiting import fix_rate_limiting
from fixes.errors import fix_error_handling
from fixes.passwords import fix_password_hashing
from fixes.uploads import fix_file_uploads
from fixes.webhooks import fix_webhooks
from fixes.ssrf import fix_ssrf
from fixes.dependencies import fix_dependencies


FIXES = [
    ("SECRETS_EXPOSURE", "Fix Exposed Secrets", fix_secrets),
    ("SECURITY_HEADERS", "Fix Security Headers", fix_headers),
    ("CORS", "Fix CORS Configuration", fix_cors),
    ("CSRF", "Fix CSRF Protection", fix_csrf),
    ("RATE_LIMITING", "Fix Rate Limiting", fix_rate_limiting),
    ("ERROR_HANDLING", "Fix Error Handling", fix_error_handling),
    ("PASSWORD_HASHING", "Fix Password Hashing", fix_password_hashing),
    ("FILE_UPLOADS", "Fix File Upload Security", fix_file_uploads),
    ("PAYMENT_WEBHOOKS", "Fix Payment Webhooks", fix_webhooks),
    ("SSRF", "Fix SSRF Protection", fix_ssrf),
    ("DEPENDENCIES", "Fix Dependencies", fix_dependencies),
]


def backup_file(fpath):
    if fpath.exists():
        bak = fpath.with_suffix(fpath.suffix + ".bak")
        shutil.copy2(str(fpath), str(bak))
        return bak
    return None


def apply_fixes(audit_results, target, dry_run=False, verbose=False):
    target = Path(target).resolve()
    framework = detect_framework(target)

    print(f"Target: {target}")
    print(f"Framework: {framework['type'] or 'static/generic'} ({framework['language']})")
    if dry_run:
        print("DRY RUN — no files will be modified")
    print("=" * 60)

    # Index results by ID for quick lookup
    results_map = {}
    for r in audit_results:
        results_map[r["id"]] = r

    fix_log = []
    for fix_id, fix_name, fix_fn in FIXES:
        result = results_map.get(fix_id)
        if result and result.get("status") == "PASS":
            print(f"[SKIP] {fix_name} — already passing")
            continue

        print(f"\n[{fix_id}] {fix_name}...")
        try:
            outcome = fix_fn(target, framework, dry_run=dry_run, verbose=verbose)
            if outcome.get("fixed"):
                for item in outcome["fixed"]:
                    print(f"  FIXED: {item}")
                fix_log.append((fix_id, "fixed", outcome["fixed"]))
            if outcome.get("created"):
                for item in outcome["created"]:
                    print(f"  CREATED: {item}")
                fix_log.append((fix_id, "created", outcome["created"]))
            if outcome.get("warnings"):
                for w in outcome["warnings"]:
                    print(f"  WARN: {w}")
                fix_log.append((fix_id, "warning", outcome["warnings"]))
            if not outcome.get("fixed") and not outcome.get("created"):
                print(f"  No automated fix available")
                fix_log.append((fix_id, "no-fix", outcome.get("message", "")))
        except Exception as e:
            print(f"  ERROR: {e}")
            fix_log.append((fix_id, "error", str(e)))

    print("\n" + "=" * 60)
    print("Fix complete.")

    # Summary
    fixed_count = sum(1 for _, status, _ in fix_log if status == "fixed")
    created_count = sum(1 for _, status, _ in fix_log if status == "created")
    warn_count = sum(1 for _, status, _ in fix_log if status == "warning")
    nofix_count = sum(1 for _, status, _ in fix_log if status == "no-fix")

    print(f"\nResults:")
    print(f"  Fixed: {fixed_count} categories")
    print(f"  Files created: {created_count}")
    print(f"  Warnings: {warn_count}")
    print(f"  Manual fix needed: {nofix_count}")

    return fix_log


def generate_fix_report(fix_log, output_dir):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    report_path = out / "FIX_REPORT.md"

    with open(report_path, "w") as f:
        f.write("# Security Fix Report\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("## Summary\n\n")
        f.write("| Category | Status | Details |\n")
        f.write("|----------|--------|--------|\n")

        for fix_id, status, details in fix_log:
            emoji = {"fixed": "✅", "created": "📄", "warning": "⚠️", "no-fix": "🔧", "error": "❌"}.get(status, "❓")
            detail_str = details[0] if isinstance(details, list) and details else str(details)
            f.write(f"| {fix_id} | {emoji} {status} | {detail_str} |\n")

        f.write("\n## Manual Steps Required\n\n")
        manual = [(fix_id, details) for fix_id, status, details in fix_log if status == "no-fix"]
        if manual:
            for fix_id, details in manual:
                f.write(f"### {fix_id}\n\n")
                if isinstance(details, list):
                    for d in details:
                        f.write(f"- {d}\n")
                else:
                    f.write(f"- {details}\n")
                f.write("\n")
        else:
            f.write("No manual steps required.\n")

    json_path = out / "fix-results.json"
    with open(json_path, "w") as f:
        json.dump(fix_log, f, indent=2)

    return report_path


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ZKNet Security Fix Tool")
    parser.add_argument("audit_json", help="Path to audit-results.json")
    parser.add_argument("target", help="Target project directory to fix")
    parser.add_argument("-o", "--output", default="./fix-report", help="Output directory for fix report")
    parser.add_argument("--dry-run", action="store_true", help="Preview fixes without modifying files")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    with open(args.audit_json) as f:
        audit_results = json.load(f)

    fix_log = apply_fixes(audit_results, args.target, dry_run=args.dry_run, verbose=args.verbose)
    report_path = generate_fix_report(fix_log, args.output)
    print(f"\nFix report saved to: {report_path}")
    print(f"JSON results: {Path(args.output) / 'fix-results.json'}")


if __name__ == "__main__":
    main()
