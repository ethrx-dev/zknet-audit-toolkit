from pathlib import Path


EXPRESS_CORS = """// CORS configuration (auto-generated)
// Add this to your main app file:
//   const cors = require('cors');
//   const corsConfig = require('./middleware/cors');
//   app.use(cors(corsConfig));

module.exports = {
  origin: process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',')
    : ['http://localhost:3000', 'http://localhost:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  maxAge: 86400,
};
"""

FASTAPI_CORS = """# CORS configuration (auto-generated)
# Add this to your main app file:
#   from middleware.cors import configure_cors
#   configure_cors(app)

from fastapi.middleware.cors import CORSMiddleware


def configure_cors(app):
    origins = [
        "http://localhost:3000",
        "http://localhost:5173",
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
        max_age=86400,
    )
"""


def fix_cors(target, framework, dry_run=False, verbose=False):
    target = Path(target)
    outcome = {"fixed": [], "created": [], "warnings": [], "message": ""}
    src_dir = target / (framework.get("src_dir") or ".")

    if framework["has_express"] or framework["has_next"]:
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
        cors_file = mw_dir / "cors.js"
        if not cors_file.exists():
            if not dry_run:
                cors_file.write_text(EXPRESS_CORS)
            outcome["created"].append("middleware/cors.js")
            outcome["warnings"].append("Install: npm install cors")
            outcome["warnings"].append("Add to app: app.use(cors(require('./middleware/cors')))")
        else:
            outcome["fixed"].append("middleware/cors.js already exists")

        # Also fix any existing wildcard CORS
        for f in target.rglob("*.js") if not dry_run else []:
            try:
                text = f.read_text()
                if "Access-Control-Allow-Origin" in text and "*" in text:
                    text = text.replace('"*"', "process.env.CORS_ORIGIN || 'http://localhost:3000'")
                    f.write_text(text)
                    rel = f.relative_to(target)
                    outcome["fixed"].append(f"Removed CORS wildcard in {rel}")
            except (PermissionError, UnicodeDecodeError):
                continue

    elif framework["has_fastapi"]:
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
        cors_file = mw_dir / "cors.py"
        if not cors_file.exists():
            if not dry_run:
                cors_file.write_text(FASTAPI_CORS)
            outcome["created"].append("middleware/cors.py")
            outcome["warnings"].append("Add to app: from middleware.cors import configure_cors; configure_cors(app)")
        else:
            outcome["fixed"].append("middleware/cors.py already exists")

    elif framework["has_django"]:
        outcome["warnings"].append("Django: Add 'corsheaders' to INSTALLED_APPS and configure CORS_ALLOWED_ORIGINS in settings.py")

    else:
        outcome["message"] = "No recognized framework — configure CORS in your reverse proxy or manually"

    return outcome
