# ZKNET Audit Toolkit v1

Automated security audit and remediation for vibe-coded applications in production. Probes codebases for 17 vulnerability categories, then applies targeted fixes.

Built for the ZKNetwork ecosystem. Zero external dependencies — pure Python stdlib (optional npm for dep audits).

---

## Quick Start

```
$ git clone https://github.com/ethrx-dev/zknet-audit-toolkit.git
$ cd zknet-audit-toolkit
$ ln -sf "$PWD/run-audit" ~/.local/bin/zknet-audit

# Scan anything
$ zknet-audit /path/to/project -o ./reports

# Preview fixes (dry-run — no files touched)
$ zknet-audit fix ./reports/audit-results.json /path/to/project --dry-run

# Apply fixes
$ zknet-audit fix ./reports/audit-results.json /path/to/project
```

---

## 17 Security Checks

| # | Check | Severity | What It Finds |
|---|-------|----------|---------------|
| 1 | Exposed Secrets | **CRITICAL** | .env in git, hard-coded keys, .env.example with real values |
| 2 | Database Access Control | LOW | Supabase RLS, Firebase rules bypassed |
| 3 | Auth Middleware | **CRITICAL** | Missing auth guards on API routes |
| 4 | Access Control (IDOR) | LOW | Missing ownership checks on user data |
| 5 | Frontend Secrets | LOW | `NEXT_PUBLIC_` / `VITE_` env vars with secrets |
| 6 | SSRF | **HIGH** | URL fetching without private-IP validation |
| 7 | CSRF | **HIGH** | Missing SameSite or CSRF tokens on cookies |
| 8 | Security Headers | MEDIUM | CSP, HSTS, XFO, XCTO, Referrer-Policy |
| 9 | CORS | LOW | Wildcard ACAO, creds + wildcard |
| 10 | Rate Limiting | **HIGH** | No limits on auth endpoints |
| 11 | SQL Injection | **HIGH** | f-string SQL, string concat in execute() |
| 12 | XSS | **HIGH** | dangerouslySetInnerHTML, v-html, innerHTML |
| 13 | Payment Webhooks | LOW | Missing Stripe sig verification |
| 14 | File Uploads | MEDIUM | No magic-byte check, no UUID rename |
| 15 | Error Handling | MEDIUM | Stack traces exposed, debug mode in prod |
| 16 | Password Hashing | LOW | MD5/SHA1 for passwords |
| 17 | Dependencies | MEDIUM | Unpinned ^/~ versions, no lockfile, vulns |

---

## Automated Fix Modules

When a check fails, `zknet-audit fix` applies targeted remediation:

| Module | What It Does |
|--------|-------------|
| secrets | Creates .gitignore, .env.example, ensures .env is untracked |
| headers | Generates security-headers middleware (Express, FastAPI, Flask) or HTML meta tags |
| cors | Restricts ACAO to explicit origin allowlist |
| csrf | Adds SameSite cookies, CSRF token middleware |
| rate_limiting | Generates rate-limit middleware |
| errors | Disables DEBUG, adds generic error handler |
| passwords | Replaces weak hashing with bcrypt/argon2 utils |
| uploads | Adds magic-byte validation, UUID renaming |
| webhooks | Generates Stripe webhook with sig verification |
| ssrf | Adds private-IP blocklist before URL fetch |
| dependencies | Pins exact versions, runs npm audit fix |

Framework auto-detection: Express, Next.js, FastAPI, Flask, Django, React, Vue, static HTML. Each fix is tailored to the detected stack.

---

## Output Reports

```
$ tree ./reports/
├── AUDIT_SUMMARY.md     ← Human-readable markdown
├── audit-results.json   ← Machine-readable JSON (feeds fix tool)
├── FIX_REPORT.md        ← Post-fix summary
└── fix-results.json     ← Machine-readable fix log
```

---

## Architecture

```
zknet-audit-toolkit/
├── run-audit              CLI entry point (subcommand-aware)
├── audit.py               Scanner orchestrator
├── scanner.py             Centralized file iterator
├── checks/                17 check modules
│   ├── secrets.py         database.py         auth_middleware.py
│   ├── idor.py            frontend_secrets    ssrf.py
│   ├── csrf.py            headers.py          cors.py
│   ├── rate_limiting.py   sqli.py             xss.py
│   ├── webhooks.py        file_upload.py      errors.py
│   ├── passwords.py       dependencies.py
├── fixes/                 11 fix modules + framework detector
│   ├── fixer.py           Orchestrator
│   ├── framework.py       Auto-detect stack
│   └── *.py               One fix module per category
├── reporters/             Report rendering
├── security/              Latest audit output on zknetwork-client
│   ├── AUDIT_SUMMARY.md
│   └── audit-results.json
└── README.md              You are here
```



---

## Closing note: 

Built for the ZKNet ecosystem

---

*"Trust, but verify." — every vibe needs a check.*
