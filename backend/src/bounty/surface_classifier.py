"""Attack surface classifier — maps scope items to surface categories."""

from __future__ import annotations

import re

from src.bounty.schemas import ClassifiedSurface, SurfaceType

_SURFACE_PATTERNS: dict[SurfaceType, list[str]] = {
    SurfaceType.WEB_APP: [
        r"https?://", r"www\.", r"\.com$", r"\.io$", r"\.net$",
    ],
    SurfaceType.API: [
        r"/api", r"api\.", r"rest\.", r"graphql", r"\.json$",
    ],
    SurfaceType.ADMIN_PANEL: [
        r"admin\.", r"/admin", r"dashboard\.", r"console\.",
    ],
    SurfaceType.AUTH_SYSTEM: [
        r"auth\.", r"login\.", r"sso\.", r"oauth", r"id\.",
    ],
    SurfaceType.MOBILE: [
        r"android", r"ios", r"mobile\.", r"app\.", r"\.apk", r"\.ipa",
    ],
    SurfaceType.CLOUD_INFRA: [
        r"s3\.amazonaws", r"storage\.googleapis", r"blob\.core\.windows",
    ],
    SurfaceType.SUBDOMAIN: [
        r"\*\.", r"[a-z]+\.[a-z]+\.[a-z]+",
    ],
    SurfaceType.CDN_ASSETS: [
        r"cdn\.", r"static\.", r"assets\.", r"media\.",
    ],
}

_SURFACE_TEST_STEPS: dict[SurfaceType, list[str]] = {
    SurfaceType.WEB_APP: [
        "Enumerate all endpoints via crawl / sitemap.xml / robots.txt",
        "Run ARGUS recon module: headers, tech stack, CVE lookup",
        "Test authentication flows: login, registration, password reset",
        "Map all forms and test for XSS (stored > reflected > DOM)",
        "Test all input fields for SQL injection",
        "Check CORS configuration with evil.example.com origin",
        "Test CSRF on state-changing operations",
        "Check for forced browsing to admin/debug endpoints",
        "Review JavaScript files for API keys, endpoints, logic",
        "Test file upload endpoints for dangerous extensions",
    ],
    SurfaceType.API: [
        "Run ARGUS API checks module",
        "Test all endpoints for BOLA/IDOR with sequential IDs",
        "Check for missing authentication on API endpoints",
        "Test rate limiting on all sensitive endpoints",
        "Look for mass assignment via extra POST parameters",
        "Test for excessive data exposure in responses",
        "Check GraphQL introspection for hidden fields",
        "Test for HTTP verb tampering (GET vs POST vs PUT)",
        "Fuzz parameter types (string→int, int→string, null, array)",
        "Check API versioning — test deprecated versions",
    ],
    SurfaceType.AUTH_SYSTEM: [
        "Run ARGUS auth audit module",
        "Test account lockout policy (brute force protection)",
        "Test JWT tokens: alg:none, HS256/RS256 confusion, weak secret",
        "Test OAuth flows for state CSRF, open redirect, token leakage",
        "Check password reset: token expiry, predictability, account enum",
        "Test MFA bypass techniques: backup codes, race conditions",
        "Check session invalidation on logout",
        "Test account takeover via email change flow",
        "Check for username enumeration via response timing/content",
        "Test SSO/SAML for signature bypass",
    ],
    SurfaceType.ADMIN_PANEL: [
        "Test default credentials (admin/admin, admin/password)",
        "Check for unauthenticated access to admin routes",
        "Test vertical privilege escalation from user to admin",
        "Look for IDOR in admin functions referencing user objects",
        "Test admin API endpoints without admin JWT",
        "Check for reflected/stored XSS in admin dashboard inputs",
        "Test CSV/export functionality for injection",
        "Check for unrestricted file read/write in admin file manager",
    ],
    SurfaceType.MOBILE: [
        "Decompile APK/IPA and search for hardcoded secrets",
        "Intercept traffic via Burp proxy (install CA cert)",
        "Check SSL pinning implementation",
        "Test for insecure data storage (SharedPreferences, SQLite, logs)",
        "Test deep links for open redirect and parameter injection",
        "Check exported activities/content providers",
        "Test for intent hijacking",
        "Analyze JavaScript in WebView for XSS",
    ],
    SurfaceType.CLOUD_INFRA: [
        "Test S3 bucket for public read/write access",
        "Check bucket enumeration via common naming patterns",
        "Test for Azure blob / GCS bucket misconfigurations",
        "Look for exposed cloud credentials in JS / config files",
        "Test metadata service access (169.254.169.254) via SSRF",
    ],
    SurfaceType.SUBDOMAIN: [
        "Run ARGUS subdomain enumeration module (crt.sh + DNS)",
        "Screenshot all discovered assets with gowitness",
        "Probe each subdomain for HTTP/HTTPS services",
        "Check for subdomain takeover on CNAMEs pointing to expired services",
    ],
    SurfaceType.CDN_ASSETS: [
        "Check for CORS misconfiguration on asset domains",
        "Test for cache poisoning via unkeyed headers",
        "Look for sensitive data exposure in static files",
    ],
}

_SURFACE_PRIORITY: dict[SurfaceType, str] = {
    SurfaceType.AUTH_SYSTEM: "FIRST",
    SurfaceType.API: "HIGH",
    SurfaceType.ADMIN_PANEL: "HIGH",
    SurfaceType.WEB_APP: "MEDIUM",
    SurfaceType.MOBILE: "MEDIUM",
    SurfaceType.CLOUD_INFRA: "MEDIUM",
    SurfaceType.SUBDOMAIN: "LOW",
    SurfaceType.CDN_ASSETS: "LOW",
}

_SURFACE_SCAN_MODE: dict[SurfaceType, str] = {
    SurfaceType.AUTH_SYSTEM: "auth",
    SurfaceType.API: "api",
    SurfaceType.ADMIN_PANEL: "bola",
    SurfaceType.WEB_APP: "full",
    SurfaceType.MOBILE: "recon",
    SurfaceType.CLOUD_INFRA: "recon",
    SurfaceType.SUBDOMAIN: "enum",
    SurfaceType.CDN_ASSETS: "recon",
}


def classify_surfaces(scope_items: list[str]) -> list[ClassifiedSurface]:
    """Classify scope items into attack surface categories."""
    surfaces: dict[SurfaceType, list[str]] = {}
    for item in scope_items:
        matched = False
        for surface_type, patterns in _SURFACE_PATTERNS.items():
            if any(re.search(p, item, re.IGNORECASE) for p in patterns):
                surfaces.setdefault(surface_type, []).append(item)
                matched = True
                break
        if not matched:
            surfaces.setdefault(SurfaceType.WEB_APP, []).append(item)

    result: list[ClassifiedSurface] = []
    for surface_type, targets in surfaces.items():
        cs = ClassifiedSurface(
            surface_type=surface_type,
            targets=targets,
            priority=_SURFACE_PRIORITY.get(surface_type, "MEDIUM"),
            test_steps=_SURFACE_TEST_STEPS.get(surface_type, []),
            recommended_mode=_SURFACE_SCAN_MODE.get(surface_type, "standard"),
            recommended_scan_options={"mode": _SURFACE_SCAN_MODE.get(surface_type, "standard")},
        )
        result.append(cs)

    return result