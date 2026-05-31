from pathlib import Path
import json
import re
import subprocess


NPM_LOCKFILE_FIX = """// npm audit fix placeholder
// Run: npm audit fix
// Then commit the updated package-lock.json
"""


def fix_dependencies(target, framework, dry_run=False, verbose=False):
    target = Path(target)
    outcome = {"fixed": [], "created": [], "warnings": [], "message": ""}

    pkg_json = target / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text())
            modified = False
            for section in ("dependencies", "devDependencies"):
                if section in data:
                    for name, version in list(data[section].items()):
                        if version.startswith("^") or version.startswith("~"):
                            stripped = version.lstrip("^~")
                            parts = stripped.split(".")
                            if len(parts) >= 2:
                                exact = ".".join(parts[:3]) if len(parts) >= 3 else stripped
                                if version != exact:
                                    if not dry_run:
                                        data[section][name] = exact
                                    modified = True
                                    rel = pkg_json.relative_to(target)
                                    outcome["fixed"].append(
                                        f"Pinned {name}: {version} -> {exact} in {rel}"
                                    )

            if modified and not dry_run:
                pkg_json.write_text(json.dumps(data, indent=2) + "\n")
        except (json.JSONDecodeError, KeyError) as e:
            outcome["warnings"].append(f"package.json parse error: {e}")

    req_txt = target / "requirements.txt"
    if req_txt.exists():
        try:
            text = req_txt.read_text()
            lines = text.splitlines()
            new_lines = []
            modified = False
            for line in lines:
                m = re.match(r'^([a-zA-Z0-9_.-]+)([><]=?)(.+)$', line.strip())
                if m:
                    pkg, op, ver = m.group(1), m.group(2), m.group(3).strip()
                    if op in (">=", ">"):
                        new_lines.append(f"{pkg}=={ver}")
                        modified = True
                        outcome["fixed"].append(
                            f"Pinned {pkg}: {line.strip()} -> {pkg}=={ver}"
                        )
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            if modified and not dry_run:
                req_txt.write_text("\n".join(new_lines) + "\n")
        except (PermissionError, UnicodeDecodeError) as e:
            outcome["warnings"].append(f"requirements.txt error: {e}")

    node_modules = target / "node_modules"
    if node_modules.exists() and pkg_json.exists():
        try:
            result = subprocess.run(
                ["npm", "audit", "fix", "--production"],
                cwd=target,
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                outcome["fixed"].append("npm audit fix applied")
            else:
                audit_out = (result.stdout or "")[:200]
                outcome["warnings"].append(f"npm audit fix output: {audit_out}")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            outcome["warnings"].append(f"npm audit fix skipped: {e}")

    if not outcome["fixed"] and not outcome["warnings"]:
        outcome["message"] = "No dependency files found or all already pinned"

    return outcome
