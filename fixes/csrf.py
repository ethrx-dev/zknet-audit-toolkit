from pathlib import Path


EXPRESS_CSRF = """// CSRF protection middleware (auto-generated)
// Add to app:
//   const csrfProtection = require('./middleware/csrf');
//   app.use(csrfProtection);
//
// Add CSRF token to forms:
//   <input type="hidden" name="_csrf" value="<%= csrfToken %>">

const crypto = require('crypto');

function generateToken(req, res, next) {
  if (!req.session) {
    return next(new Error('CSRF middleware requires express-session'));
  }
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
}

function validateToken(req, res, next) {
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) {
    return next();
  }

  const token = req.body?._csrf || req.headers['x-csrf-token'];
  if (!token || token !== req.session?.csrfToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
}

module.exports = [generateToken, validateToken];
"""

FASTAPI_CSRF = """# CSRF protection middleware (auto-generated)
# Add to app:
#   from middleware.csrf import CsrfMiddleware
#   app.add_middleware(CsrfMiddleware)

import secrets
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class CsrfMiddleware(BaseHTTPMiddleware):
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

    async def dispatch(self, request, call_next):
        if request.method not in self.SAFE_METHODS:
            token = request.headers.get("X-CSRF-Token", "")
            session_token = request.cookies.get("csrf_token", "")
            if not token or not secrets.compare_digest(token, session_token):
                return JSONResponse(status_code=403, content={"error": "Invalid CSRF token"})
        response = await call_next(request)
        if not request.cookies.get("csrf_token"):
            token = secrets.token_hex(32)
            response.set_cookie("csrf_token", token, httponly=True, samesite="lax")
        return response
"""


def fix_csrf(target, framework, dry_run=False, verbose=False):
    target = Path(target)
    outcome = {"fixed": [], "created": [], "warnings": [], "message": ""}
    src_dir = target / (framework.get("src_dir") or ".")

    # Add SameSite cookie to existing cookie configs if possible
    for ext in ["*.js", "*.ts", "*.py"]:
        for f in target.rglob(ext):
            if any(d in f.parts for d in {".git", "node_modules", "__pycache__"}):
                continue
            try:
                text = f.read_text()
                if "SameSite" not in text and ("cookie" in text.lower() or "session" in text.lower()):
                    # Don't modify blindly — just warn
                    rel = f.relative_to(target)
                    if "express-session" in text or "session" in text.lower():
                        outcome["warnings"].append(f"Add SameSite cookie config: check {rel}")
            except (PermissionError, UnicodeDecodeError):
                continue

    if framework["has_express"] or framework["has_next"]:
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
        csrf_file = mw_dir / "csrf.js"
        if not csrf_file.exists():
            if not dry_run:
                csrf_file.write_text(EXPRESS_CSRF)
            outcome["created"].append("middleware/csrf.js")
            outcome["warnings"].append("Add to app: app.use(require('./middleware/csrf'))")
            outcome["warnings"].append("Set cookies with SameSite=Lax in express-session config")
        else:
            outcome["fixed"].append("middleware/csrf.js already exists")

    elif framework["has_fastapi"]:
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
        csrf_file = mw_dir / "csrf.py"
        if not csrf_file.exists():
            if not dry_run:
                csrf_file.write_text(FASTAPI_CSRF)
            outcome["created"].append("middleware/csrf.py")
            outcome["warnings"].append("Add to app: app.add_middleware(CsrfMiddleware)")
        else:
            outcome["fixed"].append("middleware/csrf.py already exists")

    else:
        outcome["message"] = "Set SameSite=Strict or Lax on all session cookies"

    return outcome
