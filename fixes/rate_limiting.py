from pathlib import Path


EXPRESS_RATE_LIMIT = """// Rate limiting middleware (auto-generated)
// Install: npm install express-rate-limit
// Add to app:
//   const rateLimit = require('./middleware/rate-limit');
//   app.use('/api/auth', rateLimit.authLimiter);
//   app.use('/api/', rateLimit.apiLimiter);

const rateLimit = require('express-rate-limit');

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip || req.connection.remoteAddress;
  },
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = { authLimiter, apiLimiter };
"""

FASTAPI_RATE_LIMIT = """# Rate limiting middleware (auto-generated)
# Install: pip install slowapi
# Add to app:
#   from middleware.rate_limit import limiter, auth_limiter
#   app.state.limiter = limiter
#   app.add_exception_handler(429, _rate_limit_exceeded_handler)
#
# Use on routes:
#   @router.get("/login")
#   @limiter.limit("10/minute")
#   async def login(request: Request):
#       ...

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
"""


def fix_rate_limiting(target, framework, dry_run=False, verbose=False):
    target = Path(target)
    outcome = {"fixed": [], "created": [], "warnings": [], "message": ""}
    src_dir = target / (framework.get("src_dir") or ".")

    if framework["has_express"] or framework["has_next"]:
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
        rl_file = mw_dir / "rate-limit.js"
        if not rl_file.exists():
            if not dry_run:
                rl_file.write_text(EXPRESS_RATE_LIMIT)
            outcome["created"].append("middleware/rate-limit.js")
            outcome["warnings"].append("Install: npm install express-rate-limit")
            outcome["warnings"].append("Apply to auth routes: app.use('/api/auth', rateLimit.authLimiter)")
        else:
            outcome["fixed"].append("middleware/rate-limit.js already exists")

    elif framework["has_fastapi"]:
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
        rl_file = mw_dir / "rate_limit.py"
        if not rl_file.exists():
            if not dry_run:
                rl_file.write_text(FASTAPI_RATE_LIMIT)
            outcome["created"].append("middleware/rate_limit.py")
            outcome["warnings"].append("Install: pip install slowapi")
            outcome["warnings"].append("Add to app: app.state.limiter = limiter")
        else:
            outcome["fixed"].append("middleware/rate_limit.py already exists")

    else:
        outcome["message"] = "Add rate limiting at reverse proxy level (Caddy, Nginx) or implement in your framework"

    return outcome
