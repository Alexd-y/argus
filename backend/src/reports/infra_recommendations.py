"""VHQ-011 — Infrastructure-specific recommendation engine for Valhalla reports.

Generates concrete configuration snippets, TLS hardening checklists, and
per-technology-stack remediation guidance instead of generic "validate input" advice.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Per-technology config snippets for common stacks
_NGINX_HEADERS_SNIPPET = """# nginx.conf — security headers
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
"""

_APACHE_HEADERS_SNIPPET = """# .htaccess or httpd.conf — security headers
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
"""

_CLOUDFRONT_HEADERS_SNIPPET = """# AWS CloudFront Distribution — Response Headers Policy
# AWS Console → CloudFront → Policies → Response Headers Policy → Create
# Or use AWS CLI:
#   aws cloudfront create-response-headers-policy --response-headers-policy-config file://policy.json
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()

# Rollback: CloudFront → Policies → Response Headers Policy → Delete custom policy
# Verification: curl -sS -D- -o /dev/null https://licensespring.com/ | grep -i 'content-security-policy'
"""

_NEXTJS_HEADERS_SNIPPET = """// next.config.js — Security headers for Next.js deployment
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=(), payment=()' },
          // Note: CSP and HSTS should be set at CloudFront/CDN level for maximum effectiveness
        ],
      },
    ],
  },
}

// Rollback: Remove headers array from next.config.js → redeploy
// Verification: curl -sS -D- -o /dev/null http://localhost:3000/ | grep X-Content-Type-Options
"""

_CLOUDFLARE_HEADERS_SNIPPET = """# Cloudflare — Security Headers via Transform Rules
# Cloudflare Dashboard → Rules → Transform Rules → Modify Response Header
# Add headers:
#   Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
#   X-Content-Type-Options: nosniff
#   X-Frame-Options: DENY
#   Referrer-Policy: strict-origin-when-cross-origin
#   Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()
#   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload (use Cloudflare HSTS setting instead if enabled)
#
# Rollback: Cloudflare Dashboard → Rules → Transform Rules → Delete the rule
# Verification: curl -sS -D- -o /dev/null https://target/ | grep -i 'content-security-policy'
"""

_TLS_HARDENING = """# TLS Hardening Checklist
# 1. Disable TLS 1.0 and 1.1 (nginx: ssl_protocols TLSv1.2 TLSv1.3;)
# 2. Disable weak ciphers (RC4, DES, 3DES, EXPORT, NULL, aNULL, eNULL, MD5)
# 3. Prioritize ECDHE ciphers for forward secrecy
# 4. HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
# 5. OCSP stapling enabled
# 6. Certificate key size >= 2048-bit RSA or ECDSA P-256+
# 7. TLS certificate from trusted CA (not self-signed for production)

# Verification commands:
openssl s_client -connect target:443 -tls1_2 -servername target | openssl x509 -noout -text
nmap --script ssl-enum-ciphers -p 443 target
testssl.sh --severity HIGH target
"""

_TECH_STACK_RECOMMENDATIONS: dict[str, str] = {
    "ddos-guard": """# ddos-guard / CDN/WAF Recommendations
# 1. Verify WAF rules cover OWASP Top 10 injection attacks
# 2. Ensure origin server is not directly accessible (IP whitelisting)
# 3. Configure rate limiting at WAF layer for login endpoints
# 4. Enable bot protection / JS challenge for suspicious requests""",
    "cloudfront": _CLOUDFRONT_HEADERS_SNIPPET + "\n# Also verify: Distribution cache behavior, origin access identity, geographic restrictions",
    "nginx": _NGINX_HEADERS_SNIPPET + "\n# Also verify: ssl_protocols, ssl_ciphers, client_max_body_size, limit_req_zone",
    "apache": _APACHE_HEADERS_SNIPPET + "\n# Also verify: SSLCipherSuite, SSLProtocol, LimitRequestBody, mod_evasive",
    "cloudflare": _CLOUDFLARE_HEADERS_SNIPPET,
    "wordpress": """# WordPress Hardening
# 1. Keep WordPress core, themes, plugins updated
# 2. Use Wordfence or Sucuri WAF plugin
# 3. Disable XML-RPC if not needed: add_filter('xmlrpc_enabled', '__return_false');
# 4. Move wp-config.php one directory up
# 5. Set DISALLOW_FILE_EDIT to true in wp-config.php""",
    "node.js": """# Node.js / Express Hardening
# 1. Use helmet.js middleware for security headers
# 2. Set cookie: { httpOnly: true, secure: true, sameSite: 'strict' }
# 3. Rate-limit login endpoints with express-rate-limit
# 4. Use parameterized queries (no string concatenation for SQL)""",
    "next": _NEXTJS_HEADERS_SNIPPET,
    "nextjs": _NEXTJS_HEADERS_SNIPPET,
    "django": """# Django Hardening
# 1. Set SECURE_HSTS_SECONDS, SECURE_SSL_REDIRECT, SESSION_COOKIE_SECURE, CSRF_COOKIE_SECURE = True
# 2. Use django-axes for login rate limiting
# 3. Enable Content-Security-Policy via django-csp
# 4. Set DEBUG=False, ALLOWED_HOSTS correctly""",
}


def generate_infra_recommendations(
    tech_stack: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    ssl_tls: dict[str, Any] | None,
    security_headers: dict[str, Any] | None,
) -> dict[str, Any]:
    """Generate infrastructure-specific fix recommendations.

    Returns a dict with:
        - config_snippets: list of (technology, snippet_text) tuples
        - tls_hardening: str or None
        - header_recommendations: list of per-header config lines
        - owasp_gap_roadmap: list of missing categories with manual test suggestions
    """
    result: dict[str, Any] = {
        "config_snippets": [],
        "tls_hardening": None,
        "header_recommendations": [],
        "owasp_gap_roadmap": [],
    }

    # Per-tech config snippets
    if isinstance(tech_stack, dict):
        structured = tech_stack.get("structured", tech_stack)
        web_server = str(structured.get("web_server", "") or "").lower()
        frameworks = str(structured.get("frameworks", "") or "").lower()
        cms = str(structured.get("cms", "") or "").lower()
        matched = False
        for tech_key, snippet in _TECH_STACK_RECOMMENDATIONS.items():
            if tech_key in web_server or tech_key in frameworks or tech_key in cms:
                result["config_snippets"].append((tech_key, snippet))
                matched = True
        # If CloudFront detected as CDN, always include CloudFront snippet
        if "cloudfront" in web_server and not any(k == "cloudfront" for k, _ in result["config_snippets"]):
            result["config_snippets"].append(("cloudfront", _CLOUDFRONT_HEADERS_SNIPPET))
            matched = True
        # If Next.js detected, always include Next.js snippet
        if "next" in frameworks and not any(k.startswith("next") for k, _ in result["config_snippets"]):
            result["config_snippets"].append(("next", _NEXTJS_HEADERS_SNIPPET))
            matched = True
        if not result["config_snippets"]:
            result["config_snippets"].append(("generic", _NGINX_HEADERS_SNIPPET))

    # TLS hardening if SSL/TLS data shows gaps
    if isinstance(ssl_tls, dict):
        weak_protocols = ssl_tls.get("weak_protocols", []) or []
        weak_ciphers = ssl_tls.get("weak_ciphers", []) or []
        has_hsts = ssl_tls.get("hsts") or False
        if weak_protocols or weak_ciphers or not has_hsts:
            result["tls_hardening"] = _TLS_HARDENING

    # Per-header configuration lines
    if isinstance(security_headers, dict):
        headers_list = security_headers.get("headers", []) or []
        for h in headers_list:
            if isinstance(h, dict) and h.get("status") == "missing":
                name = h.get("header", "")
                if name:
                    result["header_recommendations"].append(
                        f"add_header {name} '<value>' always;  # Currently missing"
                    )

    # OWASP gap closure roadmap
    owasp = tech_stack.get("owasp_compliance_table", []) if isinstance(tech_stack, dict) else []
    for row in (owasp or []):
        if isinstance(row, dict) and row.get("assessed") == "No":
            category = row.get("category", "")
            result["owasp_gap_roadmap"].append({
                "category": category,
                "manual_test_hint": _owasp_manual_test_hint(category),
                "priority": "high" if row.get("result") == "Not assessed" else "medium",
            })

    return result


def _owasp_manual_test_hint(category: str) -> str:
    hints = {
        "A02:2021": "Manual TLS/crypto audit: check cipher suites, certificate validity, HSTS, cookie flags. Use testssl.sh and openssl s_client.",
        "A04:2021": "Review architecture diagrams and threat model. Check for missing CSRF tokens, improper CORS, weak password policies.",
        "A06:2021": "Run dependency scanner (trivy, npm audit, pip audit) and check component versions against NVD.",
        "A08:2021": "Verify CI/CD pipeline integrity, signed commits/tags, and deserialization safeguards.",
        "A09:2021": "Check SIEM/logging coverage, alert thresholds, and incident response playbooks.",
        "A10:2021": "Test SSRF with OAST (Burp Collaborator, interactsh) on all URL input fields.",
    }
    for key, hint in hints.items():
        if key.lower() in category.lower():
            return hint
    return f"Manual penetration testing recommended for {category}. Consult OWASP Testing Guide v4.2."


def build_verification_commands(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Generate specific verification commands for each finding."""
    commands = []
    for f in findings[:30]:
        if not isinstance(f, dict):
            continue
        fid = f.get("finding_id") or f.get("id", "")
        title = str(f.get("title", "")).lower()
        endpoint = f.get("endpoint") or f.get("affected_url") or ""

        cmd = _verification_for_finding(title, endpoint)
        if cmd:
            commands.append({
                "finding_id": fid,
                "command": cmd,
                "expected_result": "Expected: see response confirming fix is applied",
            })
    return commands


def _verification_for_finding(title: str, endpoint: str) -> str | None:
    t = title.lower()
    if not endpoint:
        return None

    if "csrf" in t:
        return f"curl -sS -D- -X POST {endpoint} | grep -i 'csrf\\\\|xsrf\\\\|token'"
    if "header" in t or "security header" in t:
        return f"curl -sS -D- -o /dev/null {endpoint} | head -20"
    if "cookie" in t and "httponly" in t:
        return f"curl -sS -D- -o /dev/null {endpoint} | grep -i 'set-cookie' | grep -v 'HttpOnly'"
    if "rate limit" in t or "429" in t:
        return f"for i in $(seq 1 20); do curl -sS -o /dev/null -w '%{{http_code}}' -X POST {endpoint}; echo; done"
    if "lfi" in t or "path traversal" in t:
        return f"curl -sS {endpoint}/../../../../etc/passwd -o /dev/null -w '%{{http_code}}'"
    if "xss" in t or "cross-site scripting" in t:
        return f"""curl -sS "{endpoint}?q=<script>alert(1)</script>" | grep -c '<script>alert'"""
    if "ssrf" in t:
        return f"curl -sS '{endpoint}?url=http://169.254.169.254/latest/meta-data/' -o /dev/null -w '%{{http_code}}'"
    return f"curl -sSI {endpoint} | head -20"


def build_truthfulness_metrics(
    findings: list[dict[str, Any]],
    ai_sections: dict[str, str],
    coverage_pct: float,
) -> dict[str, Any]:
    """Calculate Truthfulness Score and Infrastructure Applicability Score.

    Truthfulness = % of findings with VALIDATED status + raw evidence.
    Infra Applicability = % of findings with concrete commands + config snippets.
    """
    total = len(findings) if findings else 0
    if total == 0:
        return {
            "truthfulness_score": 100.0,
            "truthfulness_rating": "N/A",
            "infra_applicability_score": 100.0,
            "infra_applicability_rating": "N/A",
            "validated_count": 0,
            "advisory_count": 0,
            "has_concrete_commands": 0,
            "notes": "No findings to evaluate.",
        }

    validated = sum(
        1 for f in findings
        if str(f.get("evidence_classification", f.get("status", "")) or "").upper() == "VALIDATED"
    )
    advisory = total - validated

    has_poc = sum(
        1 for f in findings
        if f.get("proof_of_concept") and
        (isinstance(f["proof_of_concept"], dict) and f["proof_of_concept"].get("payload") or
         isinstance(f["proof_of_concept"], str) and f["proof_of_concept"].strip())
    )
    has_cmd = sum(
        1 for f in findings
        if f.get("verification_command") or f.get("fix_command") or f.get("test_command")
    )

    truthfulness = (validated / total) * 100.0 if total > 0 else 100.0
    infra_score = ((has_poc + has_cmd) / (2 * total)) * 100.0 if total > 0 else 100.0

    def rating(score: float) -> str:
        if score >= 80:
            return "Strong"
        if score >= 50:
            return "Moderate"
        if score >= 25:
            return "Weak"
        return "Insufficient"

    # Count AI sections with prompt leakage
    leaked_sections = 0
    for text in ai_sections.values():
        if "ROLE:" in text or "CONSTRAINTS:" in text or "GROUNDING:" in text:
            leaked_sections += 1

    return {
        "truthfulness_score": round(truthfulness, 1),
        "truthfulness_rating": rating(truthfulness),
        "infra_applicability_score": round(infra_score, 1),
        "infra_applicability_rating": rating(infra_score),
        "validated_count": validated,
        "advisory_count": advisory,
        "has_concrete_commands": has_cmd,
        "has_poc_evidence": has_poc,
        "ai_sections_with_leakage": leaked_sections,
        "total_ai_sections": len(ai_sections),
        "wstg_coverage_pct": round(coverage_pct, 1),
        "notes": (
            f"{validated}/{total} validated ({truthfulness:.0f}%), "
            f"{has_cmd} with commands, {has_poc} with PoC, "
            f"{leaked_sections} sections with prompt leakage. "
            f"WSTG: {coverage_pct:.0f}%."
        ),
    }
