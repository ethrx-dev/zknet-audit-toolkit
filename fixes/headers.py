from pathlib import Path


EXPRESS_MIDDLEWARE = """// Security headers middleware (auto-generated)
// Add this to your main app file:
//   const securityHeaders = require('./middleware/security-headers');
//   app.use(securityHeaders);

const helmet = require('helmet');

module.exports = function securityHeaders(req, res, next) {
  // Content Security Policy
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'"
  );

  // HSTS
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');

  // Prevent MIME-type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // XSS Protection (legacy)
  res.setHeader('X-XSS-Protection', '0');

  next();
};
"""

FASTAPI_MIDDLEWARE = """# Security headers middleware (auto-generated)
# Add this to your main app file:
#   from middleware.security_headers import add_security_headers
#   app.middleware("http")(add_security_headers)

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.types import ASGIApp


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'"
        )
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "0"
        return response
"""

FLASK_MIDDLEWARE = """# Security headers middleware (auto-generated)
# Add this to your main app file:
#   from middleware.security_headers import security_headers
#   app.after_request(security_headers)

from flask import Flask


def security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "0"
    return response
"""


def fix_headers(target, framework, dry_run=False, verbose=False):
    target = Path(target)
    outcome = {"fixed": [], "created": [], "warnings": [], "message": ""}
    mw_dir = target / "middleware"
    src_dir = target / (framework.get("src_dir") or ".")

    if framework["has_express"] or framework["has_next"]:
        if src_dir != target:
            mw_dir = src_dir / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
            outcome["created"].append("middleware/ directory")
        mw_file = mw_dir / "security-headers.js"
        if not mw_file.exists():
            if not dry_run:
                mw_file.write_text(EXPRESS_MIDDLEWARE)
            outcome["created"].append("middleware/security-headers.js")
            outcome["warnings"].append("Add to app: require('./middleware/security-headers') and app.use(securityHeaders)")
        else:
            outcome["fixed"].append("middleware/security-headers.js already exists")

    elif framework["has_fastapi"]:
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
            outcome["created"].append("middleware/ directory")
        mw_file = mw_dir / "security_headers.py"
        if not mw_file.exists():
            if not dry_run:
                mw_file.write_text(FASTAPI_MIDDLEWARE)
            outcome["created"].append("middleware/security_headers.py")
            outcome["warnings"].append("Add to app: app.add_middleware(SecurityHeadersMiddleware)")
        else:
            outcome["fixed"].append("middleware/security_headers.py already exists")

    elif framework["has_flask"]:
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
            outcome["created"].append("middleware/ directory")
        mw_file = mw_dir / "security_headers.py"
        if not mw_file.exists():
            if not dry_run:
                mw_file.write_text(FLASK_MIDDLEWARE)
            outcome["created"].append("middleware/security_headers.py")
            outcome["warnings"].append("Add to app: app.after_request(security_headers)")
        else:
            outcome["fixed"].append("middleware/security_headers.py already exists")

    elif framework["is_static"]:
        # Add meta tags to HTML
        for html_file in target.rglob("*.html"):
            if "node_modules" in str(html_file):
                continue
            try:
                content = html_file.read_text()
                if "Content-Security-Policy" not in content:
                    meta = """  <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
  <meta http-equiv="Strict-Transport-Security" content="max-age=31536000; includeSubDomains">
  <meta http-equiv="X-Frame-Options" content="DENY">
  <meta http-equiv="X-Content-Type-Options" content="nosniff">
  <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
"""
                    if not dry_run:
                        content = content.replace("<head>", "<head>\n" + meta)
                        html_file.write_text(content)
                    rel = html_file.relative_to(target)
                    outcome["fixed"].append(f"Added security meta tags to {rel}")
            except (PermissionError, UnicodeDecodeError):
                continue
    else:
        outcome["message"] = "No recognized framework detected — manual header configuration needed"

    return outcome
