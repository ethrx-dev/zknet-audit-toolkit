from pathlib import Path
from scanner import iter_source_files, relative_to
import re
import subprocess
import json


PACKAGE_FILES = ['package.json', 'requirements.txt', 'pyproject.toml', 'Cargo.toml', 'go.mod', 'Gemfile']


def check_dependencies(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"

    found_pkg_files = []
    for fpath in iter_source_files(target):
        if fpath.name in PACKAGE_FILES:
            found_pkg_files.append(fpath)

    if not found_pkg_files:
        details.append("[INFO] No package dependency files found")
        summary = "No dependencies to check"
        return {
            "id": "DEPENDENCIES",
            "name": "Dependencies",
            "status": "PASS",
            "severity": "LOW",
            "summary": summary,
            "details": details,
            "findings": [],
        }

    details.append(f"[INFO] Found {len(found_pkg_files)} package file(s)")

    # Check package.json for version pinning
    for pf in found_pkg_files:
        if pf.name == 'package.json':
            rel = relative_to(pf, target)
            try:
                data = json.loads(pf.read_text())
                deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                unpinned = [f"{k}@{v}" for k, v in deps.items() if v.startswith('^') or v.startswith('~')]
                if unpinned:
                    findings.append(f"{len(unpinned)} unpinned dependencies in {rel}")
                    details.append(f"[WARN] {len(unpinned)} dependencies use ^ or ~ in {rel}")
                    for d in unpinned[:10]:
                        details.append(f"  - {d}")
                    severity = "MEDIUM"
                else:
                    details.append(f"[PASS] All dependencies pinned in {rel}")

                # Check lockfile
                lockfiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']
                has_lock = any((pf.parent / lf).exists() for lf in lockfiles)
                if has_lock:
                    details.append(f"[PASS] Lock file found for {rel}")
                else:
                    findings.append(f"No lock file for {rel}")
                    details.append(f"[WARN] No lock file found for {rel}")
                    if severity == "LOW":
                        severity = "MEDIUM"

            except (json.JSONDecodeError, KeyError):
                continue

        elif pf.name in ('requirements.txt', 'pyproject.toml'):
            rel = relative_to(pf, target)
            text = pf.read_text(errors='ignore')
            unpinned = re.findall(r'^([a-zA-Z0-9_-]+)>=', text, re.MULTILINE)
            if unpinned:
                findings.append(f"{len(unpinned)} unpinned dependencies in {rel}")
                details.append(f"[WARN] {len(unpinned)} dependencies use >= in {rel}")
                severity = "MEDIUM"
            else:
                details.append(f"[PASS] Dependencies appear pinned in {rel}")

    # Try to run npm audit if node_modules exists
    node_modules = target / 'node_modules'
    pkg_json = target / 'package.json'
    if node_modules.exists() and pkg_json.exists():
        try:
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                cwd=target,
                capture_output=True, text=True, timeout=30
            )
            if result.stdout:
                audit_data = json.loads(result.stdout)
                vulns = audit_data.get('vulnerabilities', {})
                critical = {k: v for k, v in vulns.items() if v.get('severity') == 'critical'}
                high = {k: v for k, v in vulns.items() if v.get('severity') == 'high'}
                if critical:
                    findings.append(f"{len(critical)} critical vulnerabilities")
                    details.append(f"[FAIL] {len(critical)} critical vulns: {', '.join(critical.keys())}")
                    severity = "CRITICAL"
                if high:
                    findings.append(f"{len(high)} high vulnerabilities")
                    details.append(f"[WARN] {len(high)} high vulns: {', '.join(high.keys())}")
                    if severity != "CRITICAL":
                        severity = "HIGH"
                if not critical and not high:
                    details.append(f"[PASS] npm audit: no critical or high vulnerabilities")
            else:
                details.append("[INFO] npm audit returned no output")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError) as e:
            details.append(f"[INFO] Could not run npm audit: {e}")

    summary = f"Found {len(findings)} dependency issue(s)" if findings else "Dependencies appear healthy"
    return {
        "id": "DEPENDENCIES",
        "name": "Dependencies",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
