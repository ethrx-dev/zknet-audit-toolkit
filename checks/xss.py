from pathlib import Path
from scanner import iter_source_files, relative_to
import re


XSS_PATTERNS = [
    (r'dangerouslySetInnerHTML', 'React dangerouslySetInnerHTML'),
    (r'v-html', 'Vue v-html directive'),
    (r'innerHTML\s*=', 'innerHTML assignment'),
    (r'\.html\(', 'jQuery .html()'),
    (r'\.append\(.*html', 'jQuery .append() with HTML'),
    (r'insertAdjacentHTML', 'insertAdjacentHTML'),
    (r'DOMPurify\.sanitize', 'DOMPurify sanitization [GOOD]'),
    (r'sanitizeHtml', 'sanitize-html [GOOD]'),
    (r'xss\(', 'xss library [GOOD]'),
    (r'escape\(', 'escape function [GOOD]'),
    (r'\{\.\.\.props\}', 'React props spread (potential XSS)'),
]

SANITIZERS = ['DOMPurify', 'sanitizeHtml', 'xss', 'escape', 'sanitize']


def check_xss(target, verbose=False):
    target = Path(target)
    details = []
    findings = []
    severity = "LOW"

    raw_html_usage = []
    sanitizer_usage = []
    frameworks_with_autoescape = []

    for fpath in iter_source_files(target):
        try:
            text = fpath.read_text(errors='ignore')
            rel = relative_to(fpath, target)

            for pattern, desc in XSS_PATTERNS:
                if re.search(pattern, text):
                    if '[GOOD]' in desc:
                        sanitizer_usage.append((rel, desc))
                    else:
                        raw_html_usage.append((rel, desc))

            # Detect frameworks with auto-escaping
            ext = fpath.suffix
            for fw in ['React', 'Next.js', 'Vue', 'Svelte', 'Solid', 'Preact']:
                if fw.lower() in text.lower() and ext in ('.json', '.js', '.ts', '.jsx', '.tsx'):
                    frameworks_with_autoescape.append(fw)

        except (PermissionError, UnicodeDecodeError):
            continue

    if raw_html_usage:
        # Separate dangerous from sanitized
        dangerous = [(f, d) for f, d in raw_html_usage if 'DOMPurify' not in d and 'sanitize' not in d.lower()]
        with_sanitizer = [(f, d) for f, d in raw_html_usage if 'DOMPurify' in d or 'sanitize' in d.lower()]

        if dangerous:
            findings.append(f"Found {len(dangerous)} raw HTML rendering(s) without sanitization")
            for f, d in dangerous[:10]:
                details.append(f"[FAIL] {d} in {f}")
            severity = "HIGH"
        if with_sanitizer:
            details.append(f"[PASS] {len(with_sanitizer)} raw HTML usage(s) with sanitization")
    else:
        details.append("[PASS] No raw HTML rendering detected")

    if sanitizer_usage:
        details.append(f"[PASS] XSS sanitization libraries found in {len(set(str(f) for f, _ in sanitizer_usage))} file(s)")

    if frameworks_with_autoescape:
        details.append(f"[INFO] Frameworks with auto-escaping: {', '.join(set(frameworks_with_autoescape))}")

    # Check for template engines without autoescaping
    for fpath in iter_source_files(target):
        if fpath.suffix not in ('.html', '.hbs', '.handlebars'):
            continue
        try:
            text = fpath.read_text(errors='ignore')
            if '{{{' in text or '{{{' in text:
                rel = relative_to(fpath, target)
                details.append(f"[INFO] {rel} uses triple braces (unescaped output)")
        except (PermissionError, UnicodeDecodeError):
            continue

    summary = f"Found {len(findings)} XSS risk(s)" if findings else "No XSS risks detected"
    return {
        "id": "XSS",
        "name": "Cross-Site Scripting",
        "status": "FAIL" if findings else "PASS",
        "severity": severity,
        "summary": summary,
        "details": details,
        "findings": findings,
    }
