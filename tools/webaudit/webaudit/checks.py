"""Pure analysis: raw HTTP data in, findings out.

Every function in this module is deterministic and performs no I/O, so the whole
detection and scoring layer is unit-testable without a fixture server. The
network lives in :mod:`webaudit.fetch`.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .fetch import FetchResult
from .models import SEVERITY_ORDER, Finding

HeaderMap = Dict[str, str]

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
)

_LEAKY_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-runtime",
    "x-version",
)

# Heuristic: cookie names that usually carry a session. Deliberately broad -
# a false positive here costs one line of noise, a false negative costs a finding.
_SESSION_COOKIE_RE = re.compile(
    r"(sess|sid|auth|token|jwt|csrf|xsrf|login|remember)",
    re.I,
)

# A <script> tag without a src attribute is inline code; the lookahead keeps
# external tags out of the inline-script check.
_INLINE_SCRIPT_RE = re.compile(
    r"<script\b(?![^>]*\bsrc\s*=)(?P<attrs>[^>]*)>(?P<body>.*?)</script\s*>", re.I | re.S
)
_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>", re.I)
_RESOURCE_ATTR_RE = re.compile(
    r"<(?:script|img|iframe|link|form|object|embed|source|video|audio)\b[^>]*?"
    r"\b(?:src|href|action|data)\s*=\s*[\"'](http://[^\"']+)[\"']",
    re.I,
)
_BLANK_TARGET_RE = re.compile(r"<a\b(?P<attrs>[^>]*\btarget\s*=\s*[\"']_blank[\"'][^>]*)>", re.I)
_FORM_RE = re.compile(r"<form\b(?P<attrs>[^>]*)>", re.I)
_COMMENT_RE = re.compile(r"<!--(?P<body>.*?)-->", re.S)
_META_GENERATOR_RE = re.compile(
    r"<meta\b[^>]*\bname\s*=\s*[\"']generator[\"'][^>]*\bcontent\s*=\s*[\"']([^\"']+)[\"']",
    re.I,
)
_HREF_ATTR_RE = re.compile(r"\b(?:src|href|action|data)\s*=\s*[\"']([^\"']+)[\"']", re.I)

_COMMENT_KEYWORDS = (
    "todo",
    "fixme",
    "hack",
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "debug",
    "staging",
    "internal",
    "remove before",
    "do not ship",
)

_SENSITIVE_ROBOTS_RE = re.compile(
    r"(admin|backup|\.git|\.env|\.svn|config|api|internal|staging|test|debug"
    r"|secret|private|upload|dump|sql|old)",
    re.I,
)

_WEAK_TLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")

# --------------------------------------------------------------------------- registry

CHECK_REGISTRY: Dict[str, str] = {
    "unreachable": "Target reachability",
    "dns-resolution": "DNS resolution",
    "transport-https": "HTTPS availability",
    "transport-downgrade": "Redirect chain downgrade",
    "tls-invalid": "TLS certificate validation",
    "tls-version": "TLS protocol version",
    "tls-expiry": "TLS certificate expiry",
    "tls-key": "TLS public key strength",
    "hsts": "HTTP Strict Transport Security present",
    "hsts-max-age": "HSTS max-age",
    "hsts-subdomains": "HSTS includeSubDomains",
    "csp": "Content-Security-Policy present",
    "csp-default-src": "CSP default-src fallback",
    "csp-wildcard": "CSP source list tightness",
    "csp-unsafe": "CSP unsafe-inline / unsafe-eval",
    "csp-object-src": "CSP object-src",
    "csp-base-uri": "CSP base-uri",
    "clickjacking": "Framing protection",
    "nosniff": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "coop": "Cross-Origin-Opener-Policy",
    "info-leak-headers": "Version disclosure in headers",
    "cookie-secure": "Cookie Secure flag",
    "cookie-httponly": "Cookie HttpOnly flag",
    "cookie-samesite": "Cookie SameSite attribute",
    "cookie-none-insecure": "SameSite=None without Secure",
    "mixed-content": "Mixed content",
    "form-http": "Forms posting over plaintext",
    "inline-script": "Inline script vs CSP",
    "sri": "Subresource Integrity on third-party scripts",
    "target-blank": "tabnabbing: target=_blank without rel=noopener",
    "html-comment": "Sensitive content in HTML comments",
    "meta-generator": "Technology disclosure in <meta generator>",
    "security-txt": "security.txt contact",
    "robots-sensitive": "Sensitive paths exposed in robots.txt",
    "methods-trace": "HTTP TRACE enabled",
    "methods-write": "Write methods advertised",
}

_ALL_CHECKS: Tuple[str, ...] = tuple(CHECK_REGISTRY)


# --------------------------------------------------------------------------- helpers


def header_map(headers: Sequence[Tuple[str, str]]) -> HeaderMap:
    """Case-insensitive lookup map; repeated headers are comma-joined."""
    out: HeaderMap = {}
    for name, value in headers:
        key = name.lower()
        out[key] = f"{out[key]}, {value}" if key in out else value
    return out


def header_values(headers: Sequence[Tuple[str, str]], name: str) -> List[str]:
    """Every value seen for a header, in order (used for repeated Set-Cookie)."""
    target = name.lower()
    return [value for key, value in headers if key.lower() == target]


def _finding(
    check_id: str,
    title: str,
    severity: str,
    category: str,
    detail: str,
    evidence: str = "",
    remediation: str = "",
    references: Sequence[str] = (),
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        category=category,
        detail=detail,
        evidence=evidence,
        remediation=remediation,
        references=tuple(references),
    )


def _truncate(text: str, limit: int = 200) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def parse_csp(value: str) -> Dict[str, List[str]]:
    """Parse a CSP header into ``{directive: [sources]}`` with lower-cased tokens."""
    directives: Dict[str, List[str]] = {}
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        bits = chunk.split()
        directives[bits[0].lower()] = [token.lower() for token in bits[1:]]
    return directives


def parse_cookie(raw: str) -> Tuple[str, Dict[str, Optional[str]]]:
    """Split a Set-Cookie value into ``(name, {attribute: value})``."""
    parts = [part.strip() for part in raw.split(";") if part.strip()]
    if not parts:
        return "", {}
    name = parts[0].split("=", 1)[0].strip()
    attributes: Dict[str, Optional[str]] = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            # Attribute values are lower-cased: SameSite=Lax and samesite=none must
            # compare identically downstream.
            attributes[key.strip().lower()] = value.strip().lower()
        else:
            attributes[part.strip().lower()] = None
    return name, attributes


def is_session_cookie(name: str) -> bool:
    return bool(_SESSION_COOKIE_RE.search(name))


def parse_robots(text: str) -> List[str]:
    """All ``Disallow``/``Allow`` paths declared in a robots.txt body."""
    paths: List[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        field, _, value = line.partition(":")
        if field.strip().lower() in ("disallow", "allow"):
            value = value.strip()
            if value and value != "/":
                paths.append(value)
    return paths


# --------------------------------------------------------------------------- transport


def analyze_transport(result: FetchResult) -> List[Finding]:
    """Reachability, DNS, HTTPS availability, redirect downgrades and TLS."""
    findings: List[Finding] = []

    if result.error and not result.hops:
        return [
            _finding(
                "unreachable",
                "Target could not be reached",
                "critical",
                "transport",
                "No HTTP response was received, so no posture data could be collected.",
                evidence=_truncate(result.error),
                remediation="Confirm the hostname resolves and the service is listening.",
            )
        ]

    if not result.resolved_ips:
        findings.append(
            _finding(
                "dns-resolution",
                "Hostname did not resolve",
                "critical",
                "transport",
                "The target hostname has no A/AAAA records from this vantage point.",
                evidence=_truncate(result.error or ""),
                remediation="Verify the DNS records and the resolver used for the audit.",
            )
        )

    schemes = [urlsplit(hop.url).scheme for hop in result.hops]
    final_scheme = urlsplit(result.final_url).scheme

    if final_scheme != "https":
        findings.append(
            _finding(
                "transport-https",
                "Site is not served over HTTPS",
                "high",
                "transport",
                "The audited URL terminated on plaintext HTTP; every request and "
                "response can be read and modified in transit.",
                evidence=f"final url: {result.final_url}",
                remediation="Serve the site over TLS and redirect all HTTP traffic to HTTPS.",
                references=("https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",),
            )
        )

    # A chain that reaches HTTPS and then falls back to plaintext loses the
    # protection it had already established.
    downgraded = any(
        scheme == "https" and "http" in schemes[index + 1 :]
        for index, scheme in enumerate(schemes)
    )
    if downgraded:
        findings.append(
            _finding(
                "transport-downgrade",
                "Redirect chain drops back to plaintext HTTP",
                "medium",
                "transport",
                "The chain reaches HTTPS but a later hop is served over HTTP, so part "
                "of the session can be intercepted.",
                evidence=" -> ".join(hop.url for hop in result.hops),
                remediation="Terminate every hop over HTTPS and remove the plaintext redirect.",
            )
        )

    findings.extend(analyze_tls(result))
    return findings


def analyze_tls(result: FetchResult) -> List[Finding]:
    """Certificate validity, protocol version, key strength and expiry."""
    findings: List[Finding] = []
    tls = result.tls
    if tls is None or urlsplit(result.final_url).scheme != "https":
        return findings

    if tls.verified is False:
        findings.append(
            _finding(
                "tls-invalid",
                "TLS certificate failed validation",
                "high",
                "transport",
                "The certificate presented by the server is not trusted for this "
                "hostname, so users are exposed to interception and will see browser "
                "interstitial warnings.",
                evidence=_truncate(tls.verify_error or "certificate verification failed"),
                remediation="Install a certificate issued for this hostname by a trusted CA, "
                "with the full chain included.",
            )
        )

    if tls.version and tls.version in _WEAK_TLS:
        findings.append(
            _finding(
                "tls-version",
                f"Obsolete TLS protocol negotiated ({tls.version})",
                "high",
                "transport",
                "TLS 1.0/1.1 and SSL are deprecated and carry known weaknesses.",
                evidence=f"negotiated: {tls.version}, cipher: {tls.cipher}",
                remediation="Require TLS 1.2 as a floor and prefer TLS 1.3.",
            )
        )

    if tls.days_to_expiry is not None:
        if tls.days_to_expiry < 0:
            findings.append(
                _finding(
                    "tls-expiry",
                    "TLS certificate has expired",
                    "critical",
                    "transport",
                    "An expired certificate breaks the TLS trust chain and blocks users.",
                    evidence=f"expired {abs(tls.days_to_expiry)} day(s) ago ({tls.not_after})",
                    remediation="Renew the certificate and automate renewal.",
                )
            )
        elif tls.days_to_expiry <= 21:
            findings.append(
                _finding(
                    "tls-expiry",
                    "TLS certificate expires soon",
                    "medium",
                    "transport",
                    "A certificate close to expiry risks an outage if renewal fails.",
                    evidence=f"expires in {tls.days_to_expiry} day(s) ({tls.not_after})",
                    remediation="Renew now and set up automated renewal with monitoring.",
                )
            )

    if tls.key_bits is not None and tls.key_bits < 2048:
        findings.append(
            _finding(
                "tls-key",
                f"TLS public key is only {tls.key_bits} bits",
                "high",
                "transport",
                "Sub-2048-bit RSA keys are considered brute-forceable with modern resources.",
                evidence=f"key size: {tls.key_bits} bits",
                remediation="Reissue the certificate with at least RSA 2048 (or ECDSA P-256).",
            )
        )

    return findings


# --------------------------------------------------------------------------- headers


def analyze_headers(result: FetchResult) -> List[Finding]:
    """Security header presence and content, plus version disclosure."""
    findings: List[Finding] = []
    headers = header_map(result.headers)
    if not result.hops:
        return findings

    is_https = urlsplit(result.final_url).scheme == "https"

    if is_https:
        findings.extend(_check_hsts(headers))

    findings.extend(_check_csp(headers))

    if "x-frame-options" not in headers and not _csp_has_frame_ancestors(headers):
        findings.append(
            _finding(
                "clickjacking",
                "No framing protection",
                "medium",
                "headers",
                "Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so "
                "the page can be embedded in a hostile frame for clickjacking.",
                remediation="Send Content-Security-Policy: frame-ancestors 'self' "
                "(or X-Frame-Options: DENY for legacy clients).",
                references=("https://owasp.org/www-community/attacks/Clickjacking",),
            )
        )

    if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
        findings.append(
            _finding(
                "nosniff",
                "X-Content-Type-Options is not nosniff",
                "low",
                "headers",
                "Without nosniff some browsers MIME-sniff responses, which can turn an "
                "uploaded file into executable script.",
                evidence=f"x-content-type-options: {headers.get('x-content-type-options', '<absent>')}",
                remediation="Send X-Content-Type-Options: nosniff on every response.",
            )
        )

    if "referrer-policy" not in headers:
        findings.append(
            _finding(
                "referrer-policy",
                "Missing Referrer-Policy",
                "low",
                "headers",
                "Full URLs (including tokens in query strings) leak to third parties via "
                "the Referer header.",
                remediation="Send Referrer-Policy: strict-origin-when-cross-origin.",
            )
        )

    if "permissions-policy" not in headers:
        findings.append(
            _finding(
                "permissions-policy",
                "Missing Permissions-Policy",
                "info",
                "headers",
                "No explicit policy restricts powerful browser features (camera, "
                "microphone, geolocation) for the origin and its frames.",
                remediation="Send a deny-by-default Permissions-Policy, enabling only "
                "features the app actually uses.",
            )
        )

    if "cross-origin-opener-policy" not in headers:
        findings.append(
            _finding(
                "coop",
                "Missing Cross-Origin-Opener-Policy",
                "info",
                "headers",
                "Without COOP a cross-origin popup keeps a handle on the window, which "
                "widens cross-window scripting attacks.",
                remediation="Send Cross-Origin-Opener-Policy: same-origin.",
            )
        )

    leaked = {
        name: headers[name]
        for name in _LEAKY_HEADERS
        if headers.get(name) and len(headers[name]) < 120
    }
    if leaked:
        findings.append(
            _finding(
                "info-leak-headers",
                "Technology and version disclosed in response headers",
                "low",
                "headers",
                "Header values disclose the server software and versions, which lets an "
                "attacker match the target against known exploits.",
                evidence="; ".join(f"{k}: {v}" for k, v in leaked.items()),
                remediation="Strip or genericise these headers at the reverse proxy.",
            )
        )

    return findings


def _check_hsts(headers: HeaderMap) -> List[Finding]:
    findings: List[Finding] = []
    value = headers.get("strict-transport-security")
    if not value:
        findings.append(
            _finding(
                "hsts",
                "Missing HTTP Strict-Transport-Security",
                "medium",
                "headers",
                "Without HSTS the first request over HTTP is unprotected and an "
                "attacker on the network can strip the redirect to HTTPS.",
                remediation="Send Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains (roll out with a short max-age first).",
                references=("https://owasp.org/www-project-secure-headers/",),
            )
        )
        return findings

    match = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    max_age = int(match.group(1)) if match else 0
    if max_age < 15552000:  # 180 days
        findings.append(
            _finding(
                "hsts-max-age",
                "HSTS max-age is shorter than 180 days",
                "low",
                "headers",
                "A short max-age gives an attacker a recurring window to downgrade "
                "connections between visits.",
                evidence=f"strict-transport-security: {value}",
                remediation="Raise max-age to at least 15552000, ideally 31536000.",
            )
        )
    if "includesubdomains" not in value.lower():
        findings.append(
            _finding(
                "hsts-subdomains",
                "HSTS does not cover subdomains",
                "low",
                "headers",
                "Subdomains remain reachable over plaintext HTTP and can be used to set "
                "cookies that override the parent domain.",
                evidence=f"strict-transport-security: {value}",
                remediation="Add includeSubDomains once every subdomain serves HTTPS.",
            )
        )
    return findings


def _csp_has_frame_ancestors(headers: HeaderMap) -> bool:
    value = headers.get("content-security-policy", "")
    return "frame-ancestors" in parse_csp(value)


def _check_csp(headers: HeaderMap) -> List[Finding]:
    value = headers.get("content-security-policy")
    if not value:
        return [
            _finding(
                "csp",
                "Missing Content-Security-Policy",
                "medium",
                "headers",
                "No CSP is set, so the browser applies no restriction on where scripts "
                "may load from. Any HTML injection becomes script execution.",
                remediation="Deploy a policy built from a report-only baseline: "
                "default-src 'self'; object-src 'none'; base-uri 'none'.",
                references=("https://developer.mozilla.org/docs/Web/HTTP/CSP",),
            )
        ]

    findings: List[Finding] = []
    directives = parse_csp(value)
    effective_script = directives.get("script-src") or directives.get("default-src") or []

    if not directives.get("default-src"):
        findings.append(
            _finding(
                "csp-default-src",
                "CSP has no default-src fallback",
                "low",
                "headers",
                "Directives not listed explicitly fall back to an unrestricted state "
                "when default-src is absent.",
                evidence=_truncate(value),
                remediation="Add default-src 'none' and allow only what each directive needs.",
            )
        )

    loose = [token for token in effective_script if token in ("*", "http:", "https:", "data:", "blob:")]
    if loose:
        findings.append(
            _finding(
                "csp-wildcard",
                "CSP allows unrestricted script sources",
                "high",
                "headers",
                "A wildcard or scheme-only source in the script policy lets an attacker "
                "load code from any host, so the policy provides no XSS protection.",
                evidence=_truncate(value),
                remediation="Replace wildcards with explicit origin allowlists or nonces.",
            )
        )

    unsafe = [token for token in effective_script if token in ("'unsafe-inline'", "'unsafe-eval'")]
    if unsafe:
        findings.append(
            _finding(
                "csp-unsafe",
                f"CSP script policy allows {', '.join(unsafe)}",
                "medium",
                "headers",
                "'unsafe-inline' re-enables inline event handlers and inline scripts, "
                "which is the exact vector CSP exists to block; 'unsafe-eval' allows "
                "string-to-code conversion.",
                evidence=_truncate(value),
                remediation="Use per-response nonces or hashes and drop 'unsafe-inline'.",
            )
        )

    if directives.get("object-src") != ["'none'"]:
        findings.append(
            _finding(
                "csp-object-src",
                "CSP does not lock object-src to 'none'",
                "low",
                "headers",
                "Legacy plugin content can be used to bypass script restrictions.",
                evidence=f"object-src: {directives.get('object-src', '<absent>')}",
                remediation="Add object-src 'none'.",
            )
        )

    if "base-uri" not in directives:
        findings.append(
            _finding(
                "csp-base-uri",
                "CSP does not restrict base-uri",
                "low",
                "headers",
                "An injected <base> tag can redirect every relative URL on the page, "
                "including script loads.",
                remediation="Add base-uri 'none' (or 'self').",
            )
        )

    return findings


# --------------------------------------------------------------------------- cookies


def analyze_cookies(result: FetchResult) -> List[Finding]:
    """Flag cookies missing Secure / HttpOnly / SameSite."""
    secure_missing: List[str] = []
    httponly_missing: List[str] = []
    samesite_missing: List[str] = []
    none_insecure: List[str] = []

    for raw in header_values(result.headers, "set-cookie"):
        name, attrs = parse_cookie(raw)
        if not name:
            continue
        if "secure" not in attrs:
            secure_missing.append(name)
        if "httponly" not in attrs and is_session_cookie(name):
            httponly_missing.append(name)
        if "samesite" not in attrs:
            samesite_missing.append(name)
        elif (attrs.get("samesite") or "").lower() == "none" and "secure" not in attrs:
            none_insecure.append(name)

    findings: List[Finding] = []
    if secure_missing:
        session = [n for n in secure_missing if is_session_cookie(n)]
        findings.append(
            _finding(
                "cookie-secure",
                "Cookies set without the Secure flag",
                "high" if session else "low",
                "cookies",
                "A cookie without Secure is transmitted over plaintext HTTP, so it can "
                "be captured by anyone on the network path.",
                evidence=f"{len(secure_missing)} cookie(s): {_truncate(', '.join(secure_missing))}",
                remediation="Add the Secure attribute to every Set-Cookie.",
            )
        )
    if httponly_missing:
        findings.append(
            _finding(
                "cookie-httponly",
                "Session cookies readable from JavaScript",
                "medium",
                "cookies",
                "Session-like cookies without HttpOnly are exposed to any script running "
                "on the page, which turns an XSS into full account takeover.",
                evidence=f"{len(httponly_missing)} cookie(s): {_truncate(', '.join(httponly_missing))}",
                remediation="Add HttpOnly to session cookies that the frontend does not need.",
            )
        )
    if samesite_missing:
        findings.append(
            _finding(
                "cookie-samesite",
                "Cookies without a SameSite attribute",
                "medium",
                "cookies",
                "Modern browsers fall back to Lax, but older ones send the cookie on "
                "cross-site requests, which enables CSRF.",
                evidence=f"{len(samesite_missing)} cookie(s): {_truncate(', '.join(samesite_missing))}",
                remediation="Set SameSite=Lax on session cookies, SameSite=Strict where possible.",
            )
        )
    if none_insecure:
        findings.append(
            _finding(
                "cookie-none-insecure",
                "SameSite=None without Secure",
                "high",
                "cookies",
                "Browsers reject this combination, so the cookie silently disappears; "
                "where it is accepted it is sent cross-site over plaintext.",
                evidence=_truncate(", ".join(none_insecure)),
                remediation="Pair SameSite=None with Secure, or switch to Lax/Strict.",
            )
        )
    return findings


# --------------------------------------------------------------------------- HTML


def analyze_html(result: FetchResult) -> List[Finding]:
    """Static analysis of the served markup (only for HTML responses)."""
    findings: List[Finding] = []
    content_type = header_map(result.headers).get("content-type", "")
    body = result.body
    if not body or "html" not in content_type.lower():
        return findings

    is_https = urlsplit(result.final_url).scheme == "https"
    csp = header_map(result.headers).get("content-security-policy", "")

    insecure_urls = [match.group(1) for match in _RESOURCE_ATTR_RE.finditer(body)]
    if is_https and insecure_urls:
        findings.append(
            _finding(
                "mixed-content",
                "HTTPS page loads resources over plaintext HTTP",
                "medium",
                "content",
                "Mixed content is blocked or flagged by modern browsers and can be "
                "modified in transit to inject code into the page.",
                evidence=_truncate("; ".join(insecure_urls[:5])),
                remediation="Rewrite every resource URL to https:// and add a CSP "
                "upgrade-insecure-requests directive.",
            )
        )

    for form_match in _FORM_RE.finditer(body):
        action = re.search(r"\baction\s*=\s*[\"']([^\"']*)[\"']", form_match.group("attrs"), re.I)
        if action and action.group(1).lower().startswith("http://"):
            findings.append(
                _finding(
                    "form-http",
                    "Form submits to a plaintext HTTP endpoint",
                    "high",
                    "content",
                    "Credentials and form data are sent in the clear to this action URL.",
                    evidence=_truncate(action.group(1)),
                    remediation="Point the form action at an HTTPS endpoint and require TLS.",
                )
            )
            break

    inline_scripts = [
        match.group("body")
        for match in _INLINE_SCRIPT_RE.finditer(body)
        if _is_executable_script(match.group("attrs"))
    ]
    if inline_scripts and not csp:
        findings.append(
            _finding(
                "inline-script",
                "Inline scripts without a Content-Security-Policy",
                "low",
                "content",
                f"{len(inline_scripts)} inline script block(s) execute with no CSP, so "
                "any HTML injection point becomes script execution.",
                evidence=_truncate(" ".join(script.strip() for script in inline_scripts[:2])),
                remediation="Move inline code into external files and add a nonce-based CSP.",
            )
        )

    host = urlsplit(result.final_url).hostname or ""
    for match in _SCRIPT_SRC_RE.finditer(body):
        src = match.group(1)
        if "integrity=" in match.group(0).lower():
            continue
        src_host = urlsplit(src).hostname or host
        if src_host != host:
            findings.append(
                _finding(
                    "sri",
                    "Third-party script loaded without Subresource Integrity",
                    "medium",
                    "content",
                    "A script from another origin executes with full page privileges; "
                    "without an integrity hash a compromise of that origin compromises "
                    "this page.",
                    evidence=_truncate(src),
                    remediation="Add integrity=\"sha384-...\" and crossorigin=\"anonymous\" "
                    "to third-party script tags, or self-host the dependency.",
                )
            )
            break

    for match in _BLANK_TARGET_RE.finditer(body):
        attrs = match.group("attrs").lower()
        if "rel=" not in attrs or not any(
            token in attrs for token in ("noopener", "noreferrer")
        ):
            findings.append(
                _finding(
                    "target-blank",
                    "Links open with target=_blank without rel=noopener",
                    "low",
                    "content",
                    "The opened page gets a handle on the opener window and can navigate "
                    "it to a phishing page (tabnabbing).",
                    evidence=_truncate(attrs),
                    remediation="Add rel=\"noopener noreferrer\" to outbound links, or use "
                    "rel=\"noopener\" on internal ones.",
                )
            )
            break

    suspicious_comments = []
    for match in _COMMENT_RE.finditer(body):
        body_text = match.group("body")
        lowered = body_text.lower()
        if any(keyword in lowered for keyword in _COMMENT_KEYWORDS):
            suspicious_comments.append(body_text)
    if suspicious_comments:
        findings.append(
            _finding(
                "html-comment",
                "HTML comments contain sensitive-looking content",
                "low",
                "content",
                "Comments ship to every visitor and often carry credentials, internal "
                "hostnames or unfinished security work.",
                evidence=_truncate(" ".join(suspicious_comments[:3])),
                remediation="Strip comments from production builds.",
            )
        )

    generator = _META_GENERATOR_RE.search(body)
    if generator:
        findings.append(
            _finding(
                "meta-generator",
                "Generator meta tag discloses the technology stack",
                "info",
                "content",
                "The framework and version are published in the markup, which helps an "
                "attacker pick matching exploits.",
                evidence=_truncate(generator.group(0)),
                remediation="Remove the generator meta tag from production templates.",
            )
        )

    return findings


def _is_executable_script(attrs: str) -> bool:
    """False for data blocks such as ``type="application/json"``."""
    match = re.search(r"\btype\s*=\s*[\"']([^\"']+)[\"']", attrs, re.I)
    if not match:
        return True
    value = match.group(1).strip().lower()
    return value in ("", "text/javascript", "application/javascript", "module", "text/ecmascript")


# --------------------------------------------------------------------------- well-known


def analyze_security_txt(content: Optional[str]) -> List[Finding]:
    """A reachable, complete ``/.well-known/security.txt`` is a strong signal."""
    if content is None:
        return [
            _finding(
                "security-txt",
                "No /.well-known/security.txt",
                "info",
                "policy",
                "A security.txt tells researchers where to report a vulnerability. "
                "Without it reports go nowhere and findings get published uncoordinated.",
                remediation="Publish /.well-known/security.txt with a Contact field and an "
                "Expires date (see RFC 9116).",
                references=("https://www.rfc-editor.org/rfc/rfc9116",),
            )
        ]

    findings: List[Finding] = []
    lowered = content.lower()
    if "contact:" not in lowered:
        findings.append(
            _finding(
                "security-txt",
                "security.txt has no Contact field",
                "low",
                "policy",
                "The file is published but does not say where to send a report, so "
                "researchers fall back to guessing.",
                evidence=_truncate(content),
                remediation="Add at least one Contact: entry (mailto: or https: URL).",
            )
        )
    if "expires:" not in lowered:
        findings.append(
            _finding(
                "security-txt",
                "security.txt has no Expires field",
                "info",
                "policy",
                "RFC 9116 requires an Expires field; without it the file is treated as "
                "stale by tooling.",
                evidence=_truncate(content),
                remediation="Add an Expires: field less than a year in the future.",
            )
        )
    return findings


def analyze_robots(content: Optional[str]) -> List[Finding]:
    """robots.txt is public; entries in it are published, not hidden."""
    if not content:
        return []
    interesting = [path for path in parse_robots(content) if _SENSITIVE_ROBOTS_RE.search(path)]
    if not interesting:
        return []
    return [
        _finding(
            "robots-sensitive",
            "robots.txt advertises sensitive-looking paths",
            "low",
            "disclosure",
            "robots.txt is public and unauthenticated; listing paths here hands an "
            "attacker a target list rather than hiding anything.",
            evidence=_truncate(", ".join(interesting[:10])),
            remediation="Protect those paths with authentication instead of relying on "
            "robots.txt, and remove them from the file.",
        )
    ]


def analyze_methods(allow: Optional[str]) -> List[Finding]:
    """Findings for methods advertised by an OPTIONS response."""
    if not allow:
        return []
    methods = {token.strip().upper() for token in allow.split(",") if token.strip()}
    findings: List[Finding] = []
    if "TRACE" in methods:
        findings.append(
            _finding(
                "methods-trace",
                "HTTP TRACE method is enabled",
                "medium",
                "policy",
                "TRACE echoes the request back and historically enabled cross-site "
                "tracing attacks against credentials in headers.",
                evidence=f"Allow: {allow}",
                remediation="Disable TRACE at the web server or reverse proxy.",
            )
        )
    write_methods = sorted(methods & {"PUT", "DELETE", "PATCH", "PROPFIND"})
    if write_methods:
        findings.append(
            _finding(
                "methods-write",
                f"Write methods advertised: {', '.join(write_methods)}",
                "info",
                "policy",
                "The endpoint confirms which state-changing verbs it accepts, which "
                "narrows the search space for an attacker.",
                evidence=f"Allow: {allow}",
                remediation="Restrict methods per route where the app does not need them.",
            )
        )
    return findings


# --------------------------------------------------------------------------- entry point


def audit(
    result: FetchResult,
    security_txt: Optional[str] = None,
    robots: Optional[str] = None,
    allow_header: Optional[str] = None,
) -> List[Finding]:
    """Run every check and return findings ordered by severity."""
    findings: List[Finding] = []
    findings.extend(analyze_transport(result))
    findings.extend(analyze_headers(result))
    findings.extend(analyze_cookies(result))
    findings.extend(analyze_html(result))
    findings.extend(analyze_security_txt(security_txt))
    findings.extend(analyze_robots(robots))
    findings.extend(analyze_methods(allow_header))

    order = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: (order.get(f.severity, len(order)), f.check_id))
    return findings


COOKIE_CHECKS = (
    "cookie-secure",
    "cookie-httponly",
    "cookie-samesite",
    "cookie-none-insecure",
)

HTML_CHECKS = (
    "mixed-content",
    "form-http",
    "inline-script",
    "sri",
    "target-blank",
    "html-comment",
    "meta-generator",
)

TLS_CHECKS = ("tls-invalid", "tls-version", "tls-expiry", "tls-key")


def clean_checks(
    findings: Iterable[Finding],
    result: Optional[FetchResult] = None,
) -> List[Tuple[str, str]]:
    """Registry entries whose check ran and produced no finding.

    Pass the audited ``result`` to exclude checks that had no input to work with
    (no cookies set, no HTML body, no TLS metadata). Reporting those as passes
    would overstate the result.
    """
    fired = {finding.check_id for finding in findings}
    fired |= _implied_passes(fired, result)
    return [(cid, title) for cid, title in CHECK_REGISTRY.items() if cid not in fired]


def _implied_passes(fired: set, result: Optional[FetchResult] = None) -> set:
    """Checks that were not evaluated, either because an earlier finding made them
    moot or because there was no input for them to inspect."""
    implied = set()
    if "unreachable" in fired:
        return set(_ALL_CHECKS)
    if "transport-https" in fired:
        implied.update(
            {
                "hsts",
                "hsts-max-age",
                "hsts-subdomains",
                "transport-downgrade",
                "mixed-content",
            }
            | set(TLS_CHECKS)
        )
    if "hsts" in fired:
        implied.update({"hsts-max-age", "hsts-subdomains"})
    if "csp" in fired:
        implied.update({"csp-default-src", "csp-wildcard", "csp-unsafe", "csp-object-src", "csp-base-uri"})

    if result is not None:
        if result.tls is None:
            implied.update(TLS_CHECKS)
        if not header_values(result.headers, "set-cookie"):
            implied.update(COOKIE_CHECKS)
        content_type = header_map(result.headers).get("content-type", "")
        if not result.body or "html" not in content_type.lower():
            implied.update(HTML_CHECKS)
    return implied
