"""Unit tests for the WordPress passive analyzer (WB-P7d)."""

from __future__ import annotations

from uuid import uuid4

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    EvidenceTier,
    FindingCategory,
    FindingStatus,
)
from src.web_workbench.checks.wordpress import (
    WordpressFinding,
    analyze,
    detect_fingerprint,
    detect_version,
    wordpress_finding_to_dto,
    wordpress_findings_to_dtos,
)
from src.web_workbench.checks.severity import CheckSeverity
from src.web_workbench.proxy.transport import NormalizedRequest, NormalizedResponse


def _request(
    method: str = "GET",
    target: str = "/",
    headers: tuple[tuple[str, str], ...] = (),
) -> NormalizedRequest:
    return NormalizedRequest(
        method=method,
        target=target,
        http_version="HTTP/1.1",
        headers=(("Host", "blog.test"), *headers),
    )


def _response(status: int = 200, headers: tuple[tuple[str, str], ...] = ()) -> NormalizedResponse:
    return NormalizedResponse(
        http_version="HTTP/1.1",
        status_code=status,
        reason="",
        headers=headers,
    )


def _codes(findings: list[WordpressFinding]) -> set[str]:
    return {f.code for f in findings}


# --------------------------------------------------------------------------- #
# Fingerprint                                                                 #
# --------------------------------------------------------------------------- #


def test_fingerprint_via_wp_content_reference() -> None:
    body = b'<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
    marker = detect_fingerprint(_request(), _response(), body.decode())
    assert marker == "/wp-content|/wp-includes reference"


def test_fingerprint_via_pingback_header() -> None:
    resp = _response(headers=(("X-Pingback", "https://blog.test/xmlrpc.php"),))
    assert detect_fingerprint(_request(), resp, "") == "X-Pingback header"


def test_fingerprint_via_api_link_header() -> None:
    resp = _response(headers=(("Link", '<https://blog.test/wp-json/>; rel="https://api.w.org/"'),))
    assert detect_fingerprint(_request(), resp, "") == "Link: rel=api.w.org"


def test_fingerprint_cookie_name_only_no_value_leak() -> None:
    resp = _response(headers=(("Set-Cookie", "wordpress_logged_in_abc=secretvalue; Path=/"),))
    marker = detect_fingerprint(_request(), resp, "")
    assert marker == "wordpress_* cookie"
    assert "secretvalue" not in (marker or "")


def test_no_fingerprint_on_plain_site() -> None:
    assert detect_fingerprint(_request(), _response(), "<html><body>hello</body></html>") is None


# --------------------------------------------------------------------------- #
# Version disclosure                                                          #
# --------------------------------------------------------------------------- #


def test_version_from_generator_meta() -> None:
    body = '<meta name="generator" content="WordPress 6.4.2" />'
    assert detect_version(_request(), body) == ("6.4.2", "generator-meta")


def test_version_from_feed_generator() -> None:
    body = "<generator>https://wordpress.org/?v=5.9.1</generator>"
    assert detect_version(_request(), body) == ("5.9.1", "feed-generator")


def test_version_from_readme_only_on_readme_path() -> None:
    body = "<h1>WordPress</h1><p>Version 6.1</p>"
    assert detect_version(_request(target="/readme.html"), body) == ("6.1", "readme.html")
    # Same body on a different path must not trigger the readme heuristic.
    assert detect_version(_request(target="/"), body) is None


def test_version_finding_is_confirmed_misconfig() -> None:
    body = b'<meta name="generator" content="WordPress 6.4.2">'
    findings = analyze(_request(), _response(), body)
    version = next(f for f in findings if f.code == "wordpress-version-disclosed")
    assert version.category is FindingCategory.MISCONFIG
    assert version.confidence is ConfidenceLevel.CONFIRMED
    assert "6.4.2" in version.evidence


# --------------------------------------------------------------------------- #
# Misconfigurations                                                           #
# --------------------------------------------------------------------------- #


def test_rest_user_enumeration() -> None:
    body = b'[{"id":1,"name":"Admin","slug":"admin"}]'
    findings = analyze(_request(target="/wp-json/wp/v2/users"), _response(200), body)
    finding = next(f for f in findings if f.code == "wordpress-user-enumeration")
    assert finding.severity is CheckSeverity.MEDIUM
    assert finding.confidence is ConfidenceLevel.CONFIRMED
    # The enumerated slug value must not leak into evidence.
    assert "admin" not in finding.evidence


def test_author_redirect_enumeration() -> None:
    resp = _response(302, headers=(("Location", "https://blog.test/author/john/"),))
    findings = analyze(_request(target="/?author=1"), resp, b"")
    assert "wordpress-author-enumeration" in _codes(findings)
    finding = next(f for f in findings if f.code == "wordpress-author-enumeration")
    assert finding.confidence is ConfidenceLevel.LIKELY
    assert "john" not in finding.evidence


def test_xmlrpc_enabled_via_405() -> None:
    findings = analyze(_request(target="/xmlrpc.php"), _response(405), b"")
    assert "wordpress-xmlrpc-enabled" in _codes(findings)


def test_xmlrpc_enabled_via_body_marker() -> None:
    body = b"XML-RPC server accepts POST requests only."
    findings = analyze(_request(target="/xmlrpc.php"), _response(200), body)
    assert "wordpress-xmlrpc-enabled" in _codes(findings)


def test_debug_log_exposed_is_secret_leak() -> None:
    body = b"[01-Jan-2026] PHP Notice: undefined var in /var/www/wp-content/..."
    findings = analyze(_request(target="/wp-content/debug.log"), _response(200), body)
    finding = next(f for f in findings if f.code == "wordpress-debug-log-exposed")
    assert finding.category is FindingCategory.SECRET_LEAK
    assert finding.severity is CheckSeverity.HIGH
    assert finding.confidence is ConfidenceLevel.CONFIRMED


def test_debug_log_404_not_flagged() -> None:
    findings = analyze(_request(target="/wp-content/debug.log"), _response(404), b"Not Found")
    assert "wordpress-debug-log-exposed" not in _codes(findings)


def test_directory_listing_flagged() -> None:
    body = b"<title>Index of /wp-content/uploads</title>"
    findings = analyze(_request(target="/wp-content/uploads/"), _response(200), body)
    assert "wordpress-directory-listing" in _codes(findings)


# --------------------------------------------------------------------------- #
# Aggregation & no-false-positive                                             #
# --------------------------------------------------------------------------- #


def test_clean_response_yields_no_findings() -> None:
    assert analyze(_request(), _response(), b"<html>nothing here</html>") == []


def test_findings_deduplicated_by_code() -> None:
    body = b'<meta name="generator" content="WordPress 6.4.2">' b'<link href="/wp-content/x.css">'
    findings = analyze(_request(), _response(), body)
    codes = [f.code for f in findings]
    assert len(codes) == len(set(codes))
    assert "wordpress-detected" in codes
    assert "wordpress-version-disclosed" in codes


# --------------------------------------------------------------------------- #
# FindingDTO bridge                                                           #
# --------------------------------------------------------------------------- #


def test_dto_bridge_confirmed_maps_to_confirmed_tier() -> None:
    finding = WordpressFinding(
        code="wordpress-debug-log-exposed",
        category=FindingCategory.SECRET_LEAK,
        severity=CheckSeverity.HIGH,
        confidence=ConfidenceLevel.CONFIRMED,
        cwe=532,
        title="t",
        detail="d",
        evidence="e",
        location="GET /x",
    )
    dto = wordpress_finding_to_dto(
        finding,
        tenant_id=uuid4(),
        scan_id=uuid4(),
        asset_id=uuid4(),
        tool_run_id=uuid4(),
    )
    assert dto.category is FindingCategory.SECRET_LEAK
    assert dto.cwe == [532]
    assert dto.status is FindingStatus.NEW
    assert dto.evidence_tier is EvidenceTier.CONFIRMED
    assert dto.cvss_v3_score == 7.5


def test_dto_bridge_likely_maps_to_suspected_tier() -> None:
    finding = WordpressFinding(
        code="wordpress-detected",
        category=FindingCategory.INFO,
        severity=CheckSeverity.INFO,
        confidence=ConfidenceLevel.LIKELY,
        cwe=200,
        title="t",
        detail="d",
        evidence="e",
        location="GET /",
    )
    dto = wordpress_finding_to_dto(
        finding,
        tenant_id=uuid4(),
        scan_id=uuid4(),
        asset_id=uuid4(),
        tool_run_id=uuid4(),
    )
    assert dto.evidence_tier is EvidenceTier.SUSPECTED


def test_dto_batch_unique_ids() -> None:
    body = b'<meta name="generator" content="WordPress 6.4.2"><link href="/wp-content/x">'
    findings = analyze(_request(), _response(), body)
    dtos = wordpress_findings_to_dtos(
        findings,
        tenant_id=uuid4(),
        scan_id=uuid4(),
        asset_id=uuid4(),
        tool_run_id=uuid4(),
    )
    assert len({d.id for d in dtos}) == len(dtos) == len(findings)
