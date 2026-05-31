from pathlib import Path


SSRF_UTILITY = """# SSRF protection utility (auto-generated)
# Usage:
#   from middleware.ssrf import validate_url, safe_fetch
#
#   result = validate_url(user_url)
#   if result["valid"]:
#       data = safe_fetch(user_url)
#   else:
#       return {"error": result["reason"]}

import socket
from urllib.parse import urlparse
import ipaddress
import httpx


PRIVATE_RANGES = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]


def is_private_ip(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(hostname)
        for private_range in PRIVATE_RANGES:
            if ip in ipaddress.ip_network(private_range, strict=False):
                return True
        return False
    except ValueError:
        return False


def validate_url(url: str) -> dict:
    if not url or not isinstance(url, str):
        return {"valid": False, "reason": "No URL provided"}

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"valid": False, "reason": f"Scheme '{parsed.scheme}' not allowed (only http/https)"}

    try:
        hostname = parsed.hostname or ""
        resolved_ip = socket.getaddrinfo(hostname, 80)[0][4][0]
        if is_private_ip(resolved_ip):
            return {"valid": False, "reason": f"URL resolves to private IP: {resolved_ip}"}
    except (socket.gaierror, IndexError):
        return {"valid": False, "reason": "Could not resolve hostname"}

    return {"valid": True}


async def safe_fetch(url: str, timeout: float = 10.0) -> dict:
    validation = validate_url(url)
    if not validation["valid"]:
        return {"error": validation["reason"]}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, follow_redirects=True)
            return {"status": response.status_code, "content": response.text[:1024 * 1024]}
    except Exception as e:
        return {"error": str(e)}
"""


def fix_ssrf(target, framework, dry_run=False, verbose=False):
    target = Path(target)
    outcome = {"fixed": [], "created": [], "warnings": [], "message": ""}
    src_dir = target / (framework.get("src_dir") or ".")

    if framework["language"] == "python":
        mw_dir = src_dir / "middleware" if src_dir != target else target / "middleware"
        if not mw_dir.exists():
            if not dry_run:
                mw_dir.mkdir(parents=True, exist_ok=True)
        ssrf_file = mw_dir / "ssrf.py"
        if not ssrf_file.exists():
            if not dry_run:
                ssrf_file.write_text(SSRF_UTILITY)
            outcome["created"].append("middleware/ssrf.py")
            outcome["warnings"].append("Use: from middleware.ssrf import safe_fetch instead of direct URL fetching")
            outcome["warnings"].append("Install: pip install httpx")
        else:
            outcome["fixed"].append("middleware/ssrf.py already exists")

    elif framework["has_express"] or framework["has_next"]:
        outcome["warnings"].append("Add URL validation before fetch: block private IPs, allow only http/https")
        outcome["warnings"].append("Use a library like ssrf-req-filter or is-internal-ip")

    else:
        outcome["message"] = "Block private/internal IP ranges before making any user-supplied URL requests"

    return outcome
