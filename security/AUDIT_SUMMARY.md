# Security Audit Summary

**Target:** .

**Date:** 2026-05-30 20:57:27

## Results

| # | Category | Status | Severity |
|---|----------|--------|----------|
| 1 | Exposed Secrets | FAIL | CRITICAL |
| 2 | Database Access Control | PASS | LOW |
| 3 | Auth Middleware | PASS | LOW |
| 4 | Access Control (IDOR) | PASS | LOW |
| 5 | Frontend Secrets | PASS | LOW |
| 6 | Server-Side Request Forgery | PASS | LOW |
| 7 | Cross-Site Request Forgery | PASS | LOW |
| 8 | Security Headers | PASS | LOW |
| 9 | CORS Configuration | PASS | LOW |
| 10 | Rate Limiting | PASS | LOW |
| 11 | SQL Injection | FAIL | HIGH |
| 12 | Cross-Site Scripting | FAIL | HIGH |
| 13 | Payment Webhooks | PASS | LOW |
| 14 | File Uploads | PASS | LOW |
| 15 | Error Handling | FAIL | MEDIUM |
| 16 | Password Hashing | PASS | LOW |
| 17 | Dependencies | PASS | LOW |

## Critical Issues

- **Exposed Secrets**: Found 2 issue(s), 16 secret pattern match(es)
  - [FAIL] No .gitignore file found
  - [PASS] .env not tracked by git
  - [FAIL] SQLite path (check for creds) in checks/secrets.py: sqlite:///[^\s]+',...
  - [FAIL] PostgreSQL connection string in checks/secrets.py: postgresql://[^@...
  - [FAIL] Redis connection string in checks/secrets.py: redis://[^@...
  - [FAIL] SQLite path (check for creds) in security/audit-results.json: sqlite:///[^\\s]+',...",...
  - [FAIL] PostgreSQL connection string in security/audit-results.json: postgresql://[^@...
  - [FAIL] PostgreSQL connection string in security/audit-results.json: postgresql://user:password@...
  - [FAIL] Redis connection string in security/audit-results.json: redis://[^@...
  - [FAIL] SQLite path (check for creds) in security/AUDIT_SUMMARY.md: sqlite:///[^\s]+',......
  - [FAIL] SQLite path (check for creds) in security/AUDIT_SUMMARY.md: sqlite:///[^\s]+',......
  - [FAIL] PostgreSQL connection string in security/AUDIT_SUMMARY.md: postgresql://[^@...
  - [FAIL] PostgreSQL connection string in security/AUDIT_SUMMARY.md: postgresql://user:password@...
  - [FAIL] PostgreSQL connection string in security/AUDIT_SUMMARY.md: postgresql://[^@...
  - [FAIL] PostgreSQL connection string in security/AUDIT_SUMMARY.md: postgresql://user:password@...
  - [FAIL] Redis connection string in security/AUDIT_SUMMARY.md: redis://[^@...
  - [FAIL] Redis connection string in security/AUDIT_SUMMARY.md: redis://[^@...
  - [FAIL] PostgreSQL connection string in fixes/secrets.py: postgresql://user:password@...
  - [INFO] No .env.example found

## All Findings

### Exposed Secrets (FAIL)

**Severity:** CRITICAL

Found 2 issue(s), 16 secret pattern match(es)

**Details:**

- [FAIL] No .gitignore file found
- [PASS] .env not tracked by git
- [FAIL] SQLite path (check for creds) in checks/secrets.py: sqlite:///[^\s]+',...
- [FAIL] PostgreSQL connection string in checks/secrets.py: postgresql://[^@...
- [FAIL] Redis connection string in checks/secrets.py: redis://[^@...
- [FAIL] SQLite path (check for creds) in security/audit-results.json: sqlite:///[^\\s]+',...",...
- [FAIL] PostgreSQL connection string in security/audit-results.json: postgresql://[^@...
- [FAIL] PostgreSQL connection string in security/audit-results.json: postgresql://user:password@...
- [FAIL] Redis connection string in security/audit-results.json: redis://[^@...
- [FAIL] SQLite path (check for creds) in security/AUDIT_SUMMARY.md: sqlite:///[^\s]+',......
- [FAIL] SQLite path (check for creds) in security/AUDIT_SUMMARY.md: sqlite:///[^\s]+',......
- [FAIL] PostgreSQL connection string in security/AUDIT_SUMMARY.md: postgresql://[^@...
- [FAIL] PostgreSQL connection string in security/AUDIT_SUMMARY.md: postgresql://user:password@...
- [FAIL] PostgreSQL connection string in security/AUDIT_SUMMARY.md: postgresql://[^@...
- [FAIL] PostgreSQL connection string in security/AUDIT_SUMMARY.md: postgresql://user:password@...
- [FAIL] Redis connection string in security/AUDIT_SUMMARY.md: redis://[^@...
- [FAIL] Redis connection string in security/AUDIT_SUMMARY.md: redis://[^@...
- [FAIL] PostgreSQL connection string in fixes/secrets.py: postgresql://user:password@...
- [INFO] No .env.example found

---

### Database Access Control (PASS)

**Severity:** LOW

No database access issues found

**Details:**

- [INFO] No Supabase config found (N/A if not using Supabase)
- [INFO] No Firebase config found (N/A if not using Firebase)
- [INFO] checks/database.py uses .raw( (verify RLS not bypassed)
- [INFO] checks/database.py uses .query( (verify RLS not bypassed)
- [INFO] checks/database.py uses execute( (verify RLS not bypassed)
- [INFO] checks/database.py uses .sql( (verify RLS not bypassed)
- [INFO] checks/database.py uses prisma.$queryRaw (verify RLS not bypassed)
- [INFO] checks/sqli.py uses .raw( (verify RLS not bypassed)
- [INFO] checks/sqli.py uses prisma.$queryRaw (verify RLS not bypassed)
- [INFO] security/audit-results.json uses .raw( (verify RLS not bypassed)
- [INFO] security/audit-results.json uses .query( (verify RLS not bypassed)
- [INFO] security/audit-results.json uses execute( (verify RLS not bypassed)
- [INFO] security/audit-results.json uses .sql( (verify RLS not bypassed)
- [INFO] security/audit-results.json uses prisma.$queryRaw (verify RLS not bypassed)
- [INFO] security/AUDIT_SUMMARY.md uses .raw( (verify RLS not bypassed)
- [INFO] security/AUDIT_SUMMARY.md uses .query( (verify RLS not bypassed)
- [INFO] security/AUDIT_SUMMARY.md uses execute( (verify RLS not bypassed)
- [INFO] security/AUDIT_SUMMARY.md uses .sql( (verify RLS not bypassed)
- [INFO] security/AUDIT_SUMMARY.md uses prisma.$queryRaw (verify RLS not bypassed)
- [INFO] fixes/webhooks.py uses .raw( (verify RLS not bypassed)
- [PASS] No database access issues detected

---

### Auth Middleware (PASS)

**Severity:** LOW

Auth middleware appears present

**Details:**

- [PASS] Auth middleware/references found in 19 file(s)
-   - audit.py uses: middleware
-   - checks/file_upload.py uses: middleware
-   - checks/headers.py uses: middleware
-   - checks/errors.py uses: middleware
-   - checks/rate_limiting.py uses: middleware
- [INFO] Found route definitions in 2 file(s)
-   - fixes/rate_limiting.py: Express route
-   - fixes/rate_limiting.py: Express router
-   - fixes/rate_limiting.py: FastAPI router
-   - fixes/rate_limiting.py: Django/Flask view
-   - fixes/webhooks.py: FastAPI route
-   - fixes/webhooks.py: Express route
-   - fixes/webhooks.py: Next.js API route
-   - fixes/webhooks.py: Django/Flask view

---

### Access Control (IDOR) (PASS)

**Severity:** LOW

Ownership checks appear present

**Details:**

- [INFO] Found 1 file(s) with ID parameters (potential IDOR targets)
-   - checks/idor.py
- [PASS] Ownership checks found in 3 file(s)
-   - checks/idor.py
-   - security/audit-results.json
-   - security/AUDIT_SUMMARY.md
- [PASS] All files with ID parameters appear to have ownership checks

---

### Frontend Secrets (PASS)

**Severity:** LOW

Frontend secrets check passed

**Details:**

- [PASS] No frontend secrets detected

---

### Server-Side Request Forgery (PASS)

**Severity:** LOW

URL fetching with validation detected

**Details:**

- [INFO] Found 1 URL fetching usage(s)
-   - fixes/ssrf.py: fetch API (Node/browser)
- [PASS] IP/URL validation found in 1 file(s)
-   - fixes/ssrf.py has IP validation

---

### Cross-Site Request Forgery (PASS)

**Severity:** LOW

CSRF protection appears present

**Details:**

- [PASS] SameSite cookie settings found (Lax/Strict) in 4 file(s)
-   - checks/csrf.py
-   - fixes/csrf.py
-   - checks/csrf.py
- [INFO] SameSite=None found in 3 file(s)
- [PASS] CSRF token references found in 7 file(s)
- [INFO] Bearer token auth detected — CSRF via cookies not applicable

---

### Security Headers (PASS)

**Severity:** LOW

All required security headers found

**Details:**

- [PASS] custom security headers middleware found in audit.py
- [PASS] Content-Security-Policy referenced in checks/headers.py
- [PASS] Strict-Transport-Security referenced in checks/headers.py
- [PASS] X-Frame-Options referenced in checks/headers.py
- [PASS] X-Content-Type-Options referenced in checks/headers.py
- [PASS] Referrer-Policy referenced in checks/headers.py
- [PASS] Express/Hapi helmet middleware found in checks/headers.py
- [PASS] security middleware found in checks/headers.py
- [PASS] CSP middleware found in checks/headers.py
- [PASS] inline CSP header found in checks/headers.py
- [PASS] custom security headers middleware found in checks/headers.py
- [PASS] Nginx/other security headers found in checks/headers.py
- [PASS] Content-Security-Policy referenced in security/audit-results.json
- [PASS] Strict-Transport-Security referenced in security/audit-results.json
- [PASS] X-Frame-Options referenced in security/audit-results.json
- [PASS] X-Content-Type-Options referenced in security/audit-results.json
- [PASS] Referrer-Policy referenced in security/audit-results.json
- [PASS] Express/Hapi helmet middleware found in security/audit-results.json
- [PASS] inline CSP header found in security/audit-results.json
- [PASS] Content-Security-Policy referenced in security/AUDIT_SUMMARY.md
- [PASS] Strict-Transport-Security referenced in security/AUDIT_SUMMARY.md
- [PASS] X-Frame-Options referenced in security/AUDIT_SUMMARY.md
- [PASS] X-Content-Type-Options referenced in security/AUDIT_SUMMARY.md
- [PASS] Referrer-Policy referenced in security/AUDIT_SUMMARY.md
- [PASS] Express/Hapi helmet middleware found in security/AUDIT_SUMMARY.md
- [PASS] inline CSP header found in security/AUDIT_SUMMARY.md
- [PASS] Content-Security-Policy referenced in fixes/headers.py
- [PASS] Strict-Transport-Security referenced in fixes/headers.py
- [PASS] X-Frame-Options referenced in fixes/headers.py
- [PASS] X-Content-Type-Options referenced in fixes/headers.py
- [PASS] Referrer-Policy referenced in fixes/headers.py
- [PASS] Express/Hapi helmet middleware found in fixes/headers.py
- [PASS] inline CSP header found in fixes/headers.py
- [PASS] custom security headers middleware found in fixes/headers.py

---

### CORS Configuration (PASS)

**Severity:** LOW

CORS appears correctly configured

**Details:**

- [PASS] CORS configured in 6 file(s) without wildcards
-   - audit.py
-   - checks/cors.py
-   - security/audit-results.json
-   - security/AUDIT_SUMMARY.md
-   - fixes/fixer.py

---

### Rate Limiting (PASS)

**Severity:** LOW

Rate limiting appears present

**Details:**

- [PASS] Rate limiting: rate_limit decorator/function in audit.py
- [PASS] Rate limiting: rate_limit decorator/function in checks/rate_limiting.py
- [PASS] Rate limiting: ratelimit package in checks/rate_limiting.py
- [PASS] Rate limiting: RateLimiter class in checks/rate_limiting.py
- [PASS] Rate limiting: throttle function in checks/rate_limiting.py
- [PASS] Rate limiting: limiter middleware in checks/rate_limiting.py
- [PASS] Rate limiting: flask-limiter decorator in checks/rate_limiting.py
- [PASS] Rate limiting: SlowAPI in checks/rate_limiting.py
- [PASS] Rate limiting: express-rate-limit middleware in checks/rate_limiting.py
- [PASS] Rate limiting: rate limiting config in checks/rate_limiting.py
- [PASS] Rate limiting: rate_limit decorator/function in security/audit-results.json
- [PASS] Rate limiting: ratelimit package in security/audit-results.json
- [PASS] Rate limiting: RateLimiter class in security/audit-results.json
- [PASS] Rate limiting: throttle function in security/audit-results.json
- [PASS] Rate limiting: limiter middleware in security/audit-results.json
- [PASS] Rate limiting: SlowAPI in security/audit-results.json
- [PASS] Rate limiting: express-rate-limit middleware in security/audit-results.json
- [PASS] Rate limiting: rate_limit decorator/function in security/AUDIT_SUMMARY.md
- [PASS] Rate limiting: ratelimit package in security/AUDIT_SUMMARY.md
- [PASS] Rate limiting: RateLimiter class in security/AUDIT_SUMMARY.md
- [PASS] Rate limiting: throttle function in security/AUDIT_SUMMARY.md
- [PASS] Rate limiting: limiter middleware in security/AUDIT_SUMMARY.md
- [PASS] Rate limiting: SlowAPI in security/AUDIT_SUMMARY.md
- [PASS] Rate limiting: express-rate-limit middleware in security/AUDIT_SUMMARY.md
- [PASS] Rate limiting: rate_limit decorator/function in fixes/rate_limiting.py
- [PASS] Rate limiting: ratelimit package in fixes/rate_limiting.py
- [PASS] Rate limiting: limiter middleware in fixes/rate_limiting.py
- [PASS] Rate limiting: SlowAPI in fixes/rate_limiting.py
- [PASS] Rate limiting: express-rate-limit middleware in fixes/rate_limiting.py
- [PASS] Rate limiting: rate_limit decorator/function in fixes/fixer.py
- [PASS] Rate limiting middleware detected
- [INFO] Found auth-related endpoints in 5 file(s)
-   - checks/rate_limiting.py: login
-   - checks/rate_limiting.py: signin
-   - checks/rate_limiting.py: sign-up
-   - checks/rate_limiting.py: register
-   - checks/rate_limiting.py: signup

---

### SQL Injection (FAIL)

**Severity:** HIGH

Found 1 SQL injection risk(s)

**Details:**

- [INFO] checks/database.py uses .raw( (verify parameterization)
- [INFO] checks/database.py uses prisma.$queryRaw (verify parameterization)
- [INFO] checks/sqli.py uses .raw( (verify parameterization)
- [INFO] checks/sqli.py uses .query_raw (verify parameterization)
- [INFO] checks/sqli.py uses prisma.$queryRaw (verify parameterization)
- [INFO] security/audit-results.json uses .raw( (verify parameterization)
- [INFO] security/audit-results.json uses .query_raw (verify parameterization)
- [INFO] security/audit-results.json uses prisma.$queryRaw (verify parameterization)
- [INFO] security/AUDIT_SUMMARY.md uses .raw( (verify parameterization)
- [INFO] security/AUDIT_SUMMARY.md uses .query_raw (verify parameterization)
- [INFO] security/AUDIT_SUMMARY.md uses prisma.$queryRaw (verify parameterization)
- [FAIL] f-string with SQL DELETE in fixes/webhooks.py
- [INFO] fixes/webhooks.py uses .raw( (verify parameterization)

---

### Cross-Site Scripting (FAIL)

**Severity:** HIGH

Found 1 XSS risk(s)

**Details:**

- [FAIL] React dangerouslySetInnerHTML in checks/xss.py
- [FAIL] Vue v-html directive in checks/xss.py
- [FAIL] jQuery .html() in checks/xss.py
- [FAIL] insertAdjacentHTML in checks/xss.py
- [FAIL] React dangerouslySetInnerHTML in security/audit-results.json
- [FAIL] Vue v-html directive in security/audit-results.json
- [FAIL] jQuery .html() in security/audit-results.json
- [FAIL] insertAdjacentHTML in security/audit-results.json
- [FAIL] React dangerouslySetInnerHTML in security/AUDIT_SUMMARY.md
- [FAIL] Vue v-html directive in security/AUDIT_SUMMARY.md
- [PASS] XSS sanitization libraries found in 1 file(s)
- [INFO] Frameworks with auto-escaping: Next.js, Vue, React

---

### Payment Webhooks (PASS)

**Severity:** LOW

Payment webhooks appear secure

**Details:**

- [INFO] Stripe/payment references found in 20 file(s)
- [PASS] Webhook signature verification detected
- [PASS] Idempotency handling detected
- [INFO] Event handlers: Past due subscription handler, Payment failure handler, Subscription cancellation handler, Payment success handler

---

### File Uploads (PASS)

**Severity:** LOW

File uploads appear secured

**Details:**

- [INFO] File upload references found in 27 file(s)
-   - audit.py: File upload endpoint
-   - audit.py: upload reference
-   - checks/file_upload.py: File upload endpoint
-   - checks/file_upload.py: Multer middleware (Node.js uploads)
-   - checks/file_upload.py: Django file field
-   - checks/file_upload.py: Django REST file field
-   - checks/file_upload.py: File upload component
-   - checks/file_upload.py: upload_file function
-   - checks/file_upload.py: multipart form data
-   - checks/file_upload.py: multipart upload
- [PASS] Security measures found: 22 reference(s)

---

### Error Handling (FAIL)

**Severity:** MEDIUM

Found 3 error handling issue(s)

**Details:**

- [FAIL] Debug mode enabled (Django/Flask) in fixes/errors.py
- [FAIL] Debug mode enabled (Node/Django) in fixes/errors.py
- [FAIL] Node.js development mode in fixes/secrets.py
- [PASS] Error handling mechanisms found: Exception handler class, Try/except block, Global error handler, Express error middleware, Error handler middleware, Exception handler, Catch block, Generic error response, Production mode, Error middleware
-   - audit.py: Exception handler
-   - scanner.py: Exception handler
-   - checks/passwords.py: Exception handler
-   - checks/file_upload.py: Exception handler
-   - checks/headers.py: Exception handler

---

### Password Hashing (PASS)

**Severity:** LOW

Using third-party auth provider — password hashing N/A

**Details:**

- [INFO] Third-party auth provider(s) detected: Supabase Auth, next-auth, Clerk, Auth0, auth.js, Auth.js, Passport, Firebase Auth, oauth, NextAuth
- [INFO] Password hashing handled by provider (N/A)

---

### Dependencies (PASS)

**Severity:** LOW

No dependencies to check

**Details:**

- [INFO] No package dependency files found

---

