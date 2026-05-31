from pathlib import Path


EXPRESS_ERROR = """// Error handling middleware (auto-generated)
// Add at the END of your middleware chain (after routes):
//   const errorHandler = require('./middleware/error-handler');
//   app.use(errorHandler);

function errorHandler(err, req, res, next) {
  // Log full error server-side
  console.error('[ERROR]', new Date().toISOString(), err.stack || err.message);

  // Don't expose stack traces in production
  const isProduction = process.env.NODE_ENV === 'production';

  res.status(err.status || 500).json({
    error: isProduction ? 'Something went wrong' : err.message,
    ...(isProduction ? {} : { stack: err.stack }),
  });
}

module.exports = errorHandler;
"""

FASTAPI_ERROR = """# Error handling middleware (auto-generated)
# Add to app:
#   from middleware.error_handler import app
#   or use the handler standalone

from fastapi import Request
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger("app")


async def global_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Something went wrong"},
    )
"""


def fix_error_handling(target, framework, dry_run=False, verbose=False):
    target = Path(target)
    outcome = {"fixed": [], "created": [], "warnings": [], "message": ""}
    src_dir = target / (framework.get("src_dir") or ".")

    # Fix debug mode in configs
    config_files = [
        target / ".env",
        target / ".env.example",
        target / "config.py",
        target / "config.js",
        target / "settings.py",
    ]
    for cf in config_files:
        if cf.exists():
            try:
                text = cf.read_text()
                if "DEBUG=true" in text or "debug=true" in text or "DEBUG = True" in text:
                    if not dry_run:
                        text = text.replace("DEBUG=true", "DEBUG=false")
                        text = text.replace("debug=true", "debug=false")
                        text = text.replace("DEBUG = True", "DEBUG = False")
                        cf.write_text(text)
                    outcome["fixed"].append(f"Disabled debug mode in {cf.relative_to(target)}")
            except (PermissionError, UnicodeDecodeError):
                continue

    if framework["has_express"] or framework["has_next"]:
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
        err_file = mw_dir / "error-handler.js"
        if not err_file.exists():
            if not dry_run:
                err_file.write_text(EXPRESS_ERROR)
            outcome["created"].append("middleware/error-handler.js")
            outcome["warnings"].append("Add to app (LAST middleware): app.use(require('./middleware/error-handler'))")
        else:
            outcome["fixed"].append("middleware/error-handler.js already exists")

    elif framework["has_fastapi"]:
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
        err_file = mw_dir / "error_handler.py"
        if not err_file.exists():
            if not dry_run:
                err_file.write_text(FASTAPI_ERROR)
            outcome["created"].append("middleware/error_handler.py")
            outcome["warnings"].append("Add to app: app.add_exception_handler(Exception, global_error_handler)")
        else:
            outcome["fixed"].append("middleware/error_handler.py already exists")

    elif framework["has_django"]:
        outcome["warnings"].append("Django: Set DEBUG=False in settings.py. Add custom 500/404 handler views.")

    else:
        outcome["message"] = "Add global error handler that logs server-side and returns generic error messages"

    return outcome
