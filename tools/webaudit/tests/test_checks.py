"""Unit tests for the analysis layer.

The checks take plain data, so a FetchResult is assembled by hand and no socket
is ever opened. That keeps the whole security decision surface testable.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Tuple

import pytest

from webaudit.checks import (
    analyze_cookies,
    analyze_headers,
    analyze_html,
    analyze_methods,
    analyze_robots,
    analyze_security_txt,
    analyze_transport,
    audit,
    clean_checks,
    header_map,
    is_session_cookie,
    parse_cookie,
    parse_csp,
    parse_robots,
)
from webaudit.fetch import FetchResult, Hop, TLSInfo
from webaudit.models import Finding, grade, score

HARDENED_HEADERS: Sequence[Tuple[str, str]] = (
    ("strict-transport-security", "max-age=63072000; includeSubDomains; preload"),
    (
        "content-security-policy",
        "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'",
    ),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    ("permissions-policy", "geolocation=()"),
    ("cross-origin-opener-policy", "same-origin"),
    ("content-type", "text/html; charset=utf-8"),
)


def make_result(
    url: str = "https://example.com/",
    headers: Sequence[Tuple[str, str]] = (),
    body: str = "",
    hops: Optional[List[Hop]] = None,
    tls: Optional[TLSInfo] = None,
    resolved: Sequence[str] = ("93.184.216.34",),
    error: Optional[str] = None,
) -> FetchResult:
    hop_list = hops if hops is not None else [Hop(url, 200, list(headers))]
    return FetchResult(
        requested_url=url,
        final_url=hop_list[-1].url if hop_list else url,
        hops=hop_list,
        headers=list(headers),
        body=body,
        tls=tls,
        resolved_ips=list(resolved),
        error=error,
    )


def ids(findings: Iterable[Finding]) -> List[str]:
    return [finding.check_id for finding in findings]


# --------------------------------------------------------------------- helpers


def test_header_map_is_case_insensitive_and_joins_duplicates():
    mapped = header_map([("Set-Cookie", "a=1"), ("set-cookie", "b=2"), ("Server", "nginx")])
    assert mapped["set-cookie"] == "a=1, b=2"
    assert mapped["server"] == "nginx"


def test_parse_csp_lowercases_directives_and_sources():
    parsed = parse_csp("Default-Src 'Self'; script-src https://cdn.example.com")
    assert parsed["default-src"] == ["'self'"]
    assert parsed["script-src"] == ["https://cdn.example.com"]


def test_parse_cookie_splits_name_and_flags():
    name, attrs = parse_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert name == "sid"
    assert attrs["path"] == "/"
    assert "secure" in attrs and "httponly" in attrs
    assert attrs["samesite"] == "lax"


@pytest.mark.parametrize("name", ["PHPSESSID", "session_id", "auth_token", "JSESSIONID", "csrf-token"])
def test_session_cookie_names_are_recognised(name):
    assert is_session_cookie(name)


@pytest.mark.parametrize("name", ["theme", "lang", "consent", "visitor"])
def test_non_session_cookie_names_are_ignored(name):
    assert not is_session_cookie(name)


def test_parse_robots_keeps_paths_and_drops_the_root():
    paths = parse_robots("User-agent: *\nDisallow: /\nDisallow: /admin\nAllow: /public\n")
    assert paths == ["/admin", "/public"]


# --------------------------------------------------------------------- headers


def test_hardened_headers_produce_no_header_findings():
    findings = analyze_headers(make_result(headers=HARDENED_HEADERS))
    assert findings == []


def test_missing_headers_are_reported_with_expected_severity():
    findings = analyze_headers(make_result(headers=()))
    by_id = {finding.check_id: finding.severity for finding in findings}
    assert by_id["hsts"] == "medium"
    assert by_id["csp"] == "medium"
    assert by_id["clickjacking"] == "medium"
    assert by_id["nosniff"] == "low"
    assert by_id["referrer-policy"] == "low"


def test_short_hsts_max_age_and_missing_subdomains_are_flagged():
    headers = (("strict-transport-security", "max-age=600"),)
    assert set(ids(analyze_headers(make_result(headers=headers)))) >= {"hsts-max-age", "hsts-subdomains"}


def test_frame_ancestors_satisfies_clickjacking_check():
    headers = (("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),)
    assert "clickjacking" not in ids(analyze_headers(make_result(headers=headers)))


def test_wildcard_script_source_is_high():
    headers = (("content-security-policy", "default-src *"),)
    findings = analyze_headers(make_result(headers=headers))
    wildcard = [f for f in findings if f.check_id == "csp-wildcard"]
    assert wildcard and wildcard[0].severity == "high"


def test_unsafe_inline_is_flagged():
    headers = (("content-security-policy", "default-src 'self'; script-src 'self' 'unsafe-inline'"),)
    assert "csp-unsafe" in ids(analyze_headers(make_result(headers=headers)))


def test_object_src_and_base_uri_are_enforced():
    headers = (("content-security-policy", "default-src 'self'; script-src 'self'"),)
    found = set(ids(analyze_headers(make_result(headers=headers))))
    assert {"csp-object-src", "csp-base-uri"} <= found


def test_version_disclosure_is_reported():
    headers = (("server", "nginx/1.18.0"), ("x-powered-by", "PHP/7.4.3"))
    findings = analyze_headers(make_result(headers=headers))
    leak = [f for f in findings if f.check_id == "info-leak-headers"]
    assert leak and "PHP/7.4.3" in leak[0].evidence


def test_headers_are_not_evaluated_without_a_response():
    assert analyze_headers(make_result(hops=[])) == []


# --------------------------------------------------------------------- cookies


def test_session_cookie_without_flags_is_high_severity():
    headers = (("set-cookie", "session_id=abc; Path=/"),)
    findings = analyze_cookies(make_result(headers=headers))
    by_id = {finding.check_id: finding.severity for finding in findings}
    assert by_id["cookie-secure"] == "high"
    assert by_id["cookie-httponly"] == "medium"
    assert by_id["cookie-samesite"] == "medium"


def test_samesite_none_without_secure_is_high():
    # Browsers drop SameSite=None without Secure, so this silently breaks the session.
    headers = (("set-cookie", "sid=abc; SameSite=None"),)
    findings = analyze_cookies(make_result(headers=headers))
    assert "cookie-none-insecure" in ids(findings)


def test_samesite_none_with_secure_is_accepted():
    headers = (("set-cookie", "sid=abc; Secure; HttpOnly; SameSite=None"),)
    assert "cookie-none-insecure" not in ids(analyze_cookies(make_result(headers=headers)))


def test_fully_flagged_cookies_pass():
    headers = (("set-cookie", "sid=abc; Secure; HttpOnly; SameSite=Strict; Path=/"),)
    assert analyze_cookies(make_result(headers=headers)) == []


def test_non_session_cookie_missing_httponly_is_not_reported():
    headers = (("set-cookie", "theme=dark; Secure; SameSite=Lax"),)
    assert "cookie-httponly" not in ids(analyze_cookies(make_result(headers=headers)))


# ------------------------------------------------------------------------ html


def test_mixed_content_on_https_page_is_flagged():
    body = '<html><body><img src="http://cdn.example.com/a.png"></body></html>'
    headers = (("content-type", "text/html"),)
    assert "mixed-content" in ids(analyze_html(make_result(headers=headers, body=body)))


def test_http_form_action_is_high():
    body = '<form action="http://example.com/login" method="post"></form>'
    headers = (("content-type", "text/html"),)
    findings = analyze_html(make_result(headers=headers, body=body))
    form = [f for f in findings if f.check_id == "form-http"]
    assert form and form[0].severity == "high"


def test_inline_script_without_csp_is_flagged():
    body = "<html><script>var a = 1;</script></html>"
    headers = (("content-type", "text/html"),)
    assert "inline-script" in ids(analyze_html(make_result(headers=headers, body=body)))


def test_json_script_block_is_not_treated_as_inline_code():
    body = '<html><script type="application/json">{"a": 1}</script></html>'
    headers = (("content-type", "text/html"),)
    assert "inline-script" not in ids(analyze_html(make_result(headers=headers, body=body)))


def test_third_party_script_without_integrity_is_flagged():
    body = '<html><script src="https://cdn.example.net/lib.js"></script></html>'
    headers = (("content-type", "text/html"),)
    assert "sri" in ids(analyze_html(make_result(headers=headers, body=body)))


def test_third_party_script_with_integrity_passes():
    body = (
        '<html><script src="https://cdn.example.net/lib.js" '
        'integrity="sha384-abc" crossorigin="anonymous"></script></html>'
    )
    headers = (("content-type", "text/html"),)
    assert "sri" not in ids(analyze_html(make_result(headers=headers, body=body)))


def test_target_blank_without_rel_is_flagged():
    body = '<html><a href="https://ext.example" target="_blank">x</a></html>'
    headers = (("content-type", "text/html"),)
    assert "target-blank" in ids(analyze_html(make_result(headers=headers, body=body)))


def test_sensitive_comment_is_flagged():
    body = "<html><!-- TODO: remove the staging password before release --></html>"
    headers = (("content-type", "text/html"),)
    findings = analyze_html(make_result(headers=headers, body=body))
    comment = [f for f in findings if f.check_id == "html-comment"]
    assert comment and "staging password" in comment[0].evidence


def test_generator_meta_is_reported():
    body = '<html><head><meta name="generator" content="WordPress 6.4"></head></html>'
    headers = (("content-type", "text/html"),)
    assert "meta-generator" in ids(analyze_html(make_result(headers=headers, body=body)))


def test_non_html_body_is_ignored():
    body = '{"error": "not html"}'
    headers = (("content-type", "application/json"),)
    assert analyze_html(make_result(headers=headers, body=body)) == []


# ------------------------------------------------------------------- transport


def test_plaintext_site_is_high():
    findings = analyze_transport(make_result(url="http://example.com/"))
    plaintext = [f for f in findings if f.check_id == "transport-https"]
    assert plaintext and plaintext[0].severity == "high"


def test_weak_tls_version_and_expiry_are_flagged():
    tls = TLSInfo(version="TLSv1.1", cipher="AES128-SHA", days_to_expiry=5, verified=True)
    found = ids(analyze_transport(make_result(tls=tls)))
    assert {"tls-version", "tls-expiry"} <= set(found)


def test_expired_certificate_is_critical():
    tls = TLSInfo(version="TLSv1.3", days_to_expiry=-3, verified=False, verify_error="expired")
    findings = analyze_transport(make_result(tls=tls))
    expired = [f for f in findings if f.check_id == "tls-expiry"]
    assert expired and expired[0].severity == "critical"
    assert "tls-invalid" in ids(findings)


def test_healthy_tls_produces_no_transport_findings():
    tls = TLSInfo(version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", days_to_expiry=200, verified=True)
    assert analyze_transport(make_result(tls=tls)) == []


def test_unreachable_target_is_critical_single_finding():
    findings = analyze_transport(make_result(hops=[], error="gaierror: Name or service not known"))
    assert ids(findings) == ["unreachable"]
    assert findings[0].severity == "critical"


def test_https_redirect_chain_downgrade_is_flagged():
    hops = [Hop("https://example.com/", 301, [], "http://example.com/"), Hop("http://example.com/", 200, [])]
    findings = analyze_transport(make_result(hops=hops))
    assert "transport-downgrade" in ids(findings)


# ------------------------------------------------------------- policy artefacts


def test_missing_security_txt_is_informational():
    findings = analyze_security_txt(None)
    assert findings[0].check_id == "security-txt"
    assert findings[0].severity == "info"


def test_security_txt_without_contact_is_flagged():
    assert "security-txt" in ids(analyze_security_txt("Expires: 2027-01-01T00:00:00Z"))


def test_complete_security_txt_passes():
    content = "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z"
    assert analyze_security_txt(content) == []


def test_robots_with_sensitive_paths_is_flagged():
    assert "robots-sensitive" in ids(analyze_robots("User-agent: *\nDisallow: /admin\nDisallow: /.env"))


def test_robots_without_sensitive_paths_is_quiet():
    assert analyze_robots("User-agent: *\nDisallow: /cart\n") == []


def test_trace_method_is_medium():
    findings = analyze_methods("GET, POST, OPTIONS, TRACE")
    trace = [f for f in findings if f.check_id == "methods-trace"]
    assert trace and trace[0].severity == "medium"


def test_write_methods_are_informational():
    findings = analyze_methods("GET, PUT, DELETE")
    assert ids(findings) == ["methods-write"]


def test_no_allow_header_means_no_findings():
    assert analyze_methods(None) == []


# ---------------------------------------------------------------------- scoring


def test_clean_target_scores_an_a():
    findings = audit(
        make_result(headers=HARDENED_HEADERS, body="<html><body>ok</body></html>"),
        security_txt="Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z",
        robots="",
        allow_header="GET",
    )
    assert findings == []
    assert score(findings) == 100
    assert grade(100) == "A"


def test_score_never_goes_below_zero():
    findings = [Finding("x", "t", severity, "c", "d") for severity in ("critical",) * 5]
    assert score(findings) == 0
    assert grade(0) == "F"


@pytest.mark.parametrize(
    "value,expected",
    [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (70, "C"), (55, "D"), (41, "E"), (40, "E"), (10, "F")],
)
def test_grade_bands(value, expected):
    assert grade(value) == expected


def test_audit_sorts_by_severity_then_check_id():
    findings = audit(make_result(headers=(), body=""), security_txt=None, robots=None)
    severities = [f.severity for f in findings]
    order = {name: index for index, name in enumerate(("critical", "high", "medium", "low", "info"))}
    assert severities == sorted(severities, key=lambda s: order[s])


def test_clean_checks_excludes_unrun_subchecks():
    findings = audit(make_result(headers=()), security_txt=None, robots=None)
    passed = dict(clean_checks(findings))
    # No CSP header at all means the CSP sub-checks never ran.
    assert "csp-wildcard" not in passed
    assert "csp" not in passed
    # A check with no precondition was genuinely evaluated and passed.
    assert "methods-trace" in passed


def test_unreachable_target_marks_every_check_as_unrun():
    findings = audit(make_result(hops=[], error="connection refused"))
    assert clean_checks(findings) == []


def test_checks_without_input_are_not_reported_as_passes():
    result = make_result(headers=HARDENED_HEADERS)
    passed = dict(clean_checks(audit(result), result))
    # No cookies on the response, so the cookie checks never had data to inspect.
    assert "cookie-secure" not in passed
    assert "cookie-samesite" not in passed
    # These two were evaluated against real headers and genuinely passed.
    assert "csp" in passed
    assert "hsts" in passed


def test_tls_checks_are_not_reported_as_passes_without_tls_metadata():
    result = make_result(headers=HARDENED_HEADERS)  # tls=None: nothing negotiated
    passed = dict(clean_checks(audit(result), result))
    assert "tls-version" not in passed
    assert "tls-expiry" not in passed
