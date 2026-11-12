"""Authorized in-process network access.

Some checks (HTTP security headers, TLS configuration, OSINT certificate
lookups) are done in Python rather than by an external binary. They still must
obey the scope, so they go through ``AuthorizedHttpClient``, which refuses any
host that is not the authorized target and records every request in the audit
trail - the same discipline the subprocess manager enforces for binaries.

``IntelHttpClient`` is separate: it talks only to a fixed allowlist of public
vulnerability-database hosts (NVD, EPSS, CISA KEV). Those are reference data
sources, not assessment targets, so they are not subject to the scope; instead
the actions that use them ask the operator for consent first.
"""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from core.logger import AuditLogger
from core.models import Target, TargetKind
from core.permissions import Authorization
from core.validator import url_host

USER_AGENT = "KSIF/0.2 (+security-assessment; authorized use only)"
DEFAULT_TIMEOUT = 15
MAX_BYTES = 2_000_000
INTEL_HOSTS = frozenset(
    {"services.nvd.nist.gov", "api.first.org", "www.cisa.gov", "cisa.gov"}
)


class NetworkTargetError(PermissionError):
    """The requested host is not the authorized target."""


class NetworkError(RuntimeError):
    """The request could not be completed."""


@dataclass
class HttpResponse:
    """A fetched HTTP response (body capped at ``MAX_BYTES``)."""

    url: str
    status: int
    headers: dict[str, str]
    body: str
    final_url: str


@dataclass
class TlsInfo:
    """Summary of a TLS endpoint."""

    host: str
    port: int
    protocol: str
    cipher: str
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = field(default_factory=list)
    error: str = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Block redirects: a redirect could send the request to an out-of-scope host."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _authorized_host(authorization: Authorization) -> str:
    target = authorization.target
    if target.kind is TargetKind.URL:
        return url_host(target)
    if target.kind in (TargetKind.DOMAIN, TargetKind.IPV4, TargetKind.IPV6):
        return target.value.lower()
    raise NetworkTargetError(f"{target.kind.value} targets cannot be used for HTTP/TLS")


class AuthorizedHttpClient:
    """HTTP/TLS client locked to the authorized target."""

    def __init__(self, audit: AuditLogger, *, timeout: int = DEFAULT_TIMEOUT) -> None:
        self._audit = audit
        self._timeout = timeout

    def _check_host(self, authorization: Authorization, url: str) -> None:
        allowed = _authorized_host(authorization)
        host = (urlsplit(url).hostname or "").lower()
        if host != allowed:
            raise NetworkTargetError(f"{host or url!r} is not the authorized target {allowed!r}")

    def base_url(self, authorization: Authorization, scheme: str = "https") -> str:
        """The default URL for a domain/IP target, or the URL target itself."""
        if authorization.target.kind is TargetKind.URL:
            return authorization.target.value
        return f"{scheme}://{authorization.target.value}/"

    def fetch(
        self,
        url: str,
        authorization: Authorization,
        *,
        method: str = "GET",
        timeout: int | None = None,
    ) -> HttpResponse:
        """Fetch *url* (must be the authorized host). Redirects are not followed."""
        self._check_host(authorization, url)
        request = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
        opener = urllib.request.build_opener(_NoRedirect)
        self._audit.record("http_request", operator=authorization.operator, url=url, method=method)
        try:
            with opener.open(request, timeout=timeout or self._timeout) as response:
                raw = response.read(MAX_BYTES)
                return HttpResponse(
                    url=url, status=response.status,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    body=raw.decode("utf-8", errors="replace"),
                    final_url=response.geturl(),
                )
        except urllib.error.HTTPError as exc:  # a 4xx/5xx is still a real response
            return HttpResponse(
                url=url, status=exc.code,
                headers={k.lower(): v for k, v in (exc.headers or {}).items()},
                body="", final_url=url,
            )
        except (urllib.error.URLError, ssl.SSLError, OSError) as exc:
            raise NetworkError(f"request to {url} failed: {exc}") from exc

    def tls_info(self, authorization: Authorization, port: int = 443) -> TlsInfo:
        """Inspect the TLS certificate and negotiated parameters of the target."""
        host = _authorized_host(authorization)
        self._audit.record("tls_inspect", operator=authorization.operator, host=host, port=port)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # we report problems, we do not reject
        try:
            with socket.create_connection((host, port), timeout=self._timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    cipher = tls.cipher() or ("", "", 0)
                    return _tls_info_from(host, port, tls.version() or "", cipher[0], cert)
        except (ssl.SSLError, OSError) as exc:
            return TlsInfo(host=host, port=port, protocol="", cipher="", error=str(exc))


def _tls_info_from(host: str, port: int, version: str, cipher: str, cert: Any) -> TlsInfo:
    info = TlsInfo(host=host, port=port, protocol=version, cipher=cipher)
    if not cert:
        return info
    info.subject = _name(cert.get("subject"))
    info.issuer = _name(cert.get("issuer"))
    info.not_before = cert.get("notBefore", "")
    info.not_after = cert.get("notAfter", "")
    info.san = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    return info


def _name(rdn: Any) -> str:
    if not rdn:
        return ""
    parts = [f"{key}={value}" for group in rdn for key, value in group]
    return ", ".join(parts)


class IntelHttpClient:
    """Read-only JSON client for a fixed allowlist of vulnerability databases."""

    def __init__(self, audit: AuditLogger, *, timeout: int = DEFAULT_TIMEOUT) -> None:
        self._audit = audit
        self._timeout = timeout

    def get_json(self, url: str, operator: str = "system") -> Any:
        """GET *url* (must be an allowlisted intel host) and parse JSON."""
        host = (urlsplit(url).hostname or "").lower()
        if host not in INTEL_HOSTS:
            raise NetworkTargetError(f"{host!r} is not an allowed intelligence source")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        self._audit.record("intel_request", operator=operator, url=url)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                return json.loads(response.read(MAX_BYTES).decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise NetworkError(f"intel request to {url} failed: HTTP {exc.code}") from exc
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise NetworkError(f"intel request to {url} failed: {exc}") from exc


def days_until(not_after: str) -> int | None:
    """Days until a certificate's ``notAfter`` (negative = already expired)."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            expiry = datetime.strptime(not_after, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
        return (expiry - datetime.now(UTC)).days
    return None
