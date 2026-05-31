import os
import json
import re
import subprocess
import sys
from pathlib import Path
from datetime import datetime

from checks.secrets import check_secrets_exposure
from checks.database import check_database_access
from checks.auth_middleware import check_auth_middleware
from checks.idor import check_access_control
from checks.frontend_secrets import check_frontend_secrets
from checks.ssrf import check_ssrf
from checks.csrf import check_csrf
from checks.headers import check_security_headers
from checks.cors import check_cors
from checks.rate_limiting import check_rate_limiting
from checks.sqli import check_sql_injection
from checks.xss import check_xss
from checks.webhooks import check_payment_webhooks
from checks.file_upload import check_file_uploads
from checks.errors import check_error_handling
from checks.passwords import check_password_hashing
from checks.dependencies import check_dependencies


CHECKS = [
    ("SECRETS_EXPOSURE", "Exposed Secrets", check_secrets_exposure),
    ("DATABASE_ACCESS", "Database Access Control", check_database_access),
    ("AUTH_MIDDLEWARE", "Auth Middleware", check_auth_middleware),
    ("ACCESS_CONTROL", "Access Control (IDOR)", check_access_control),
    ("FRONTEND_SECRETS", "Frontend Secrets", check_frontend_secrets),
    ("SSRF", "Server-Side Request Forgery", check_ssrf),
    ("CSRF", "Cross-Site Request Forgery", check_csrf),
    ("SECURITY_HEADERS", "Security Headers", check_security_headers),
    ("CORS", "CORS Configuration", check_cors),
    ("RATE_LIMITING", "Rate Limiting", check_rate_limiting),
    ("SQL_INJECTION", "SQL Injection", check_sql_injection),
    ("XSS", "Cross-Site Scripting", check_xss),
    ("PAYMENT_WEBHOOKS", "Payment Webhooks", check_payment_webhooks),
    ("FILE_UPLOADS", "File Uploads", check_file_uploads),
    ("ERROR_HANDLING", "Error Handling", check_error_handling),
    ("PASSWORD_HASHING", "Password Hashing", check_password_hashing),
    ("DEPENDENCIES", "Dependencies", check_dependencies),
]


def scan(target_dir, verbose=False):
    target = Path(target_dir).resolve()
    if not target.is_dir():
        print(f"Error: {target_dir} is not a directory")
        sys.exit(1)

    print(f"Scanning: {target}")
    print(f"Starting audit: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    results = []
    for check_id, check_name, check_fn in CHECKS:
        print(f"\n[{check_id}] {check_name}...")
        try:
            result = check_fn(target, verbose=verbose)
            results.append(result)
            status = result.get("status", "ERROR")
            print(f"  Status: {status}")
            if verbose and result.get("details"):
                for d in result["details"][:10]:
                    print(f"    - {d}")
        except Exception as e:
            results.append({
                "id": check_id,
                "name": check_name,
                "status": "ERROR",
                "details": [f"Check failed: {e}"],
                "severity": "LOW",
            })
            print(f"  Error: {e}")

    print("\n" + "=" * 60)
    print("Audit complete.")
    return results


def generate_report(results, target_dir, output_dir):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    summary_path = out / "AUDIT_SUMMARY.md"
    with open(summary_path, "w") as f:
        f.write("# Security Audit Summary\n\n")
        f.write(f"**Target:** {target_dir}\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("## Results\n\n")
        f.write("| # | Category | Status | Severity |\n")
        f.write("|---|----------|--------|----------|\n")

        criticals = []
        for i, r in enumerate(results, 1):
            status = r.get("status", "ERROR")
            sev = r.get("severity", "LOW")
            f.write(f"| {i} | {r['name']} | {status} | {sev} |\n")
            if sev == "CRITICAL":
                criticals.append(r)

        f.write("\n## Critical Issues\n\n")
        if criticals:
            for r in criticals:
                f.write(f"- **{r['name']}**: {r.get('summary', 'No details')}\n")
                for d in r.get("details", []):
                    f.write(f"  - {d}\n")
        else:
            f.write("No critical issues found.\n")

        f.write("\n## All Findings\n\n")
        for r in results:
            f.write(f"### {r['name']} ({r.get('status', 'ERROR')})\n\n")
            f.write(f"**Severity:** {r.get('severity', 'LOW')}\n\n")
            if r.get("summary"):
                f.write(f"{r['summary']}\n\n")
            if r.get("details"):
                f.write("**Details:**\n\n")
                for d in r["details"]:
                    f.write(f"- {d}\n")
            f.write("\n---\n\n")

    # Also output JSON for programmatic use
    json_path = out / "audit-results.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)

    return summary_path


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ZKNet Security Audit Tool")
    parser.add_argument("target", nargs="?", default=".", help="Target directory to scan")
    parser.add_argument("-o", "--output", default="./security", help="Output directory for reports")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    results = scan(args.target, verbose=args.verbose)
    report_path = generate_report(results, args.target, args.output)
    print(f"\nReport saved to: {report_path}")
    print(f"JSON results: {Path(args.output) / 'audit-results.json'}")


if __name__ == "__main__":
    main()
