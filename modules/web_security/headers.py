"""Security-header analysis (pure function, no I/O).

Maps an HTTP response's headers to a list of findings aligned with the OWASP
Secure Headers project and common OWASP Top 10 configuration weaknesses.
"""

from __future__ import annotations

import re

from core.models import Finding

MODULE = "web_security"
_VERSION_IN_SERVER = re.compile(r"\d+\.\d+")


def analyze_headers(url: str, status: int, headers: dict[str, str], is_https: bool) -> list[Finding]:
    """Return findings for missing or weak security headers."""
    findings: list[Finding] = []

    def add(severity: str, title: str, recommendation: str, evidence: str = "") -> None:
        findings.append(Finding(MODULE, "headers", severity, title, url,
                                evidence=evidence, recommendation=recommendation,
                                reference="https://owasp.org/www-project-secure-headers/"))

    csp = headers.get("content-security-policy", "")
    if is_https and "strict-transport-security" not in headers:
        add("medium", "Missing HTTP Strict-Transport-Security (HSTS)",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.")
    if not csp:
        add("medium", "Missing Content-Security-Policy",
            "Define a Content-Security-Policy to limit script and resource origins.")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        add("low", "No clickjacking protection (X-Frame-Options / frame-ancestors)",
            "Set 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.")
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        add("low", "Missing X-Content-Type-Options: nosniff",
            "Set 'X-Content-Type-Options: nosniff' to stop MIME sniffing.")
    if "referrer-policy" not in headers:
        add("info", "Missing Referrer-Policy",
            "Set a Referrer-Policy such as 'strict-origin-when-cross-origin'.")
    if "permissions-policy" not in headers:
        add("info", "Missing Permissions-Policy",
            "Restrict powerful browser features with a Permissions-Policy header.")

    server = headers.get("server", "")
    if server and _VERSION_IN_SERVER.search(server):
        add("low", "Server version disclosed in the Server header",
            "Remove or generalise the Server header to avoid version disclosure.", evidence=server)
    powered = headers.get("x-powered-by", "")
    if powered:
        add("low", "Technology disclosed in X-Powered-By",
            "Remove the X-Powered-By header.", evidence=powered)

    cookie = headers.get("set-cookie", "")
    if cookie:
        low = cookie.lower()
        if is_https and "secure" not in low:
            add("low", "Session cookie without the Secure attribute",
                "Add 'Secure' to cookies so they are only sent over HTTPS.", evidence=cookie[:120])
        if "httponly" not in low:
            add("low", "Cookie without the HttpOnly attribute",
                "Add 'HttpOnly' to cookies that do not need JavaScript access.", evidence=cookie[:120])
    return findings
