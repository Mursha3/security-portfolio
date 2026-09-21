"""Network layer: a small, dependency-free HTTP client that records metadata.

The auditor only ever issues ``GET``/``OPTIONS`` requests and reads public
resources. It never submits forms, never sends credentials and never mutates
remote state, which is why the tool is safe to point at hosts you own or are
authorised to assess.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

USER_AGENT = "webaudit/0.1 (+passive security posture audit)"
MAX_BODY_BYTES = 2 * 1024 * 1024
REDIRECT_STATUSES = (301, 302, 303, 307, 308)


@dataclass
class TLSInfo:
    """Transport details captured from the negotiated TLS session."""

    version: Optional[str] = None
    cipher: Optional[str] = None
    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_to_expiry: Optional[int] = None
    sans: List[str] = field(default_factory=list)
    key_bits: Optional[int] = None
    verified: Optional[bool] = None
    verify_error: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "cipher": self.cipher,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_to_expiry": self.days_to_expiry,
            "sans": self.sans,
            "key_bits": self.key_bits,
            "verified": self.verified,
            "verify_error": self.verify_error,
        }


@dataclass
class Hop:
    """One request/response exchange in the redirect chain."""

    url: str
    status: int
    headers: List[Tuple[str, str]]
    location: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "location": self.location,
        }


@dataclass
class FetchResult:
    """Everything a check could possibly need about one target."""

    requested_url: str
    final_url: str
    hops: List[Hop] = field(default_factory=list)
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: str = ""
    tls: Optional[TLSInfo] = None
    resolved_ips: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def status(self) -> int:
        return self.hops[-1].status if self.hops else 0

    def as_dict(self) -> dict:
        return {
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "status": self.status,
            "resolved_ips": self.resolved_ips,
            "error": self.error,
            "tls": self.tls.as_dict() if self.tls else None,
            "hops": [h.as_dict() for h in self.hops],
        }


def normalize_url(raw: str) -> str:
    """Add a scheme to bare hosts; leave anything else untouched."""
    raw = raw.strip()
    if "://" not in raw:
        return f"https://{raw}"
    return raw


def resolve(host: str) -> Tuple[List[str], Optional[str]]:
    """All A/AAAA records for a host, plus an error string when resolution fails."""
    if not host:
        return [], "empty hostname"
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return [], str(exc)
    return sorted({info[4][0] for info in infos}), None


def _header_value(headers: Sequence[Tuple[str, str]], name: str) -> Optional[str]:
    target = name.lower()
    for key, value in headers:
        if key.lower() == target:
            return value
    return None


def _key_bits(der_cert: Optional[bytes]) -> Optional[int]:
    """Public key size, when the optional ``cryptography`` package is installed."""
    if not der_cert:
        return None
    try:  # pragma: no cover - depends on an optional dependency
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import (
            dsa,
            ec,
            ed25519,
            ed448,
            rsa,
        )

        key = x509.load_der_x509_certificate(der_cert).public_key()
        if isinstance(key, rsa.RSAPublicKey):
            return key.key_size
        if isinstance(key, dsa.DSAPublicKey):
            return key.key_size
        if isinstance(key, ec.EllipticCurvePublicKey):
            return key.curve.key_size
        if isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            return 256
    except Exception:  # pragma: no cover - never let key inspection break an audit
        return None
    return None


def _tls_info(sock: Optional[socket.socket]) -> Optional[TLSInfo]:
    """Read everything the negotiated socket exposes about the certificate."""
    if sock is None or not isinstance(sock, ssl.SSLSocket):
        return None

    info = TLSInfo()
    info.version = sock.version()
    cipher = sock.cipher()
    if cipher:
        info.cipher = cipher[0]

    cert = sock.getpeercert() or {}
    if cert:
        info.subject = dict(entry[0] for entry in cert.get("subject", ()))
        info.issuer = dict(entry[0] for entry in cert.get("issuer", ()))
        info.not_before = cert.get("notBefore")
        info.not_after = cert.get("notAfter")
        info.sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
        if info.not_after:
            expires_at = ssl.cert_time_to_seconds(info.not_after)
            info.days_to_expiry = int((expires_at - time.time()) // 86400)
        info.key_bits = _key_bits(sock.getpeercert(binary_form=True))

    return info


def _ssl_context(verify: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _request(
    url: str,
    timeout: float,
    verify: bool,
) -> Tuple[int, List[Tuple[str, str]], bytes, Optional[TLSInfo]]:
    """Single exchange. Raises on transport failure."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    scheme = parts.scheme or "https"
    port = parts.port or (443 if scheme == "https" else 80)
    path = urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, ""))

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }

    if scheme == "https":
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            host, port, timeout=timeout, context=_ssl_context(verify)
        )
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    try:
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        body = response.read(MAX_BODY_BYTES)
        tls = _tls_info(conn.sock) if scheme == "https" else None
        return response.status, response.getheaders(), body, tls
    finally:
        conn.close()


def fetch(
    url: str,
    timeout: float = 15.0,
    max_redirects: int = 10,
) -> FetchResult:
    """Follow the redirect chain and return the final response plus transport info.

    A certificate that fails verification is not fatal: the request is retried
    once without verification so the report can still describe the certificate
    and state exactly why validation failed.
    """
    url = normalize_url(url)
    hops: List[Hop] = []
    headers: List[Tuple[str, str]] = []
    body = b""
    tls: Optional[TLSInfo] = None
    error: Optional[str] = None
    current = url

    for _ in range(max_redirects + 1):
        try:
            status, headers, body, tls = _request(current, timeout, verify=True)
        except ssl.SSLCertVerificationError as exc:
            try:
                status, headers, body, tls = _request(current, timeout, verify=False)
                if tls is not None:
                    tls.verified = False
                    tls.verify_error = str(exc.verify_message or exc)
            except Exception as retry_exc:  # noqa: BLE001 - reported, never raised
                error = f"{type(retry_exc).__name__}: {retry_exc}"
                break
        except Exception as exc:  # noqa: BLE001 - any transport failure is a result
            error = f"{type(exc).__name__}: {exc}"
            break

        location = _header_value(headers, "location")
        hops.append(Hop(current, status, headers, location))

        if status in REDIRECT_STATUSES and location:
            current = urllib.parse.urljoin(current, location)
            continue
        break

    if tls is not None and tls.verified is None:
        tls.verified = urllib.parse.urlsplit(hops[-1].url).scheme == "https"

    host = urllib.parse.urlsplit(url).hostname or ""
    ips, dns_error = resolve(host)

    return FetchResult(
        requested_url=url,
        final_url=hops[-1].url if hops else url,
        hops=hops,
        headers=headers,
        body=body.decode("utf-8", errors="replace"),
        tls=tls,
        resolved_ips=ips,
        error=error or dns_error,
    )


def fetch_text(url: str, timeout: float = 10.0, limit: int = 65536) -> Optional[str]:
    """Fetch a small public text file (security.txt, robots.txt); ``None`` on failure.

    A non-2xx response means the file is absent, so its error page is discarded
    rather than parsed as content.
    """
    try:
        status, _, body, _ = _request(normalize_url(url), timeout, verify=True)
    except Exception:  # noqa: BLE001 - absence is the normal case
        return None
    if not 200 <= status < 300:
        return None
    return body[:limit].decode("utf-8", errors="replace")


def fetch_allowed_methods(url: str, timeout: float = 10.0) -> Optional[str]:
    """``Allow`` header from an ``OPTIONS`` request, or ``None`` when unavailable."""
    parts = urllib.parse.urlsplit(normalize_url(url))
    host = parts.hostname or ""
    scheme = parts.scheme or "https"
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"

    try:
        if scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=_ssl_context(True)
            )
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("OPTIONS", path, headers={"User-Agent": USER_AGENT})
            response = conn.getresponse()
            response.read(4096)
            allow = response.getheader("Allow")
            return allow
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 - OPTIONS support is optional
        return None
