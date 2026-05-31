import json
from pathlib import Path


def detect_framework(target):
    target = Path(target)
    framework = {"type": None, "has_express": False, "has_fastapi": False,
                 "has_django": False, "has_flask": False, "has_next": False,
                 "has_react": False, "has_vue": False, "is_static": False,
                 "language": "unknown", "src_dir": None}

    pkg_json = target / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text())
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if "express" in deps:
                framework["has_express"] = True
                framework["type"] = "express"
                framework["language"] = "node"
            if "next" in deps:
                framework["has_next"] = True
                framework["type"] = "nextjs"
                framework["language"] = "node"
            if "react" in deps or "react-dom" in deps:
                framework["has_react"] = True
                if not framework["type"]:
                    framework["type"] = "react"
                    framework["language"] = "node"
            if "vue" in deps or "@vue" in deps:
                framework["has_vue"] = True
                if not framework["type"]:
                    framework["type"] = "vue"
                    framework["language"] = "node"
        except (json.JSONDecodeError, KeyError):
            pass

    # Check for Python frameworks
    req_txt = target / "requirements.txt"
    if req_txt.exists():
        text = req_txt.read_text()
        if "fastapi" in text:
            framework["has_fastapi"] = True
            framework["type"] = "fastapi"
            framework["language"] = "python"
        if "django" in text:
            framework["has_django"] = True
            framework["type"] = "django"
            framework["language"] = "python"
        if "flask" in text:
            framework["has_flask"] = True
            if not framework["type"]:
                framework["type"] = "flask"
                framework["language"] = "python"

    # Check for pyproject.toml
    pyproject = target / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text()
        if "fastapi" in text:
            framework["has_fastapi"] = True
            if not framework["type"]:
                framework["type"] = "fastapi"
                framework["language"] = "python"
        if "django" in text:
            framework["has_django"] = True
            if not framework["type"]:
                framework["type"] = "django"
                framework["language"] = "python"

    # Detect src directory
    for d in ["src", "app", "backend", "server"]:
        if (target / d).is_dir():
            framework["src_dir"] = d
            break

    # Check if purely static
    html_files = list(target.rglob("*.html"))
    has_backend = any([framework["has_express"], framework["has_fastapi"],
                       framework["has_django"], framework["has_flask"]])
    if html_files and not has_backend and not framework["has_next"] and not framework["has_react"]:
        framework["is_static"] = True

    return framework
