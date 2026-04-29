# Parser and Normalizer Policy

Normalize findings before report generation.

Finding source of truth:
- `cvss_score`
- `cvss_vector`
- `severity`
- `confidence`
- `validation_status`
- `evidence_refs`
- `evidence_quality`

Evidence quality:
- `none`: no usable proof or references.
- `weak`: signal only; for rate limiting, rapid GET requests or missing HTTP 429 without full authentication-flow validation.
- `moderate`: real endpoint evidence with request/response data, but incomplete validation.
- `strong`: real login POST endpoint tested, multiple failed attempts, consistent response pattern, no lockout/CAPTCHA/throttle observed, timestamps, and raw request/response evidence.

Rate limiting (login-path):
- Merge duplicate login rate-limit findings into one finding titled "Missing or insufficient rate limiting on login endpoint".
- GET `/signin` repeated a small number of times is weak evidence and cannot support confirmed status or high severity.
- Weak rate-limit evidence should be Low severity, CVSS 3.7 or lower, `validation_status=unverified`, and `confidence=possible` or `likely`.
- Do not attach rate-limit / credential-stuffing / login-POST storylines to **header-only** findings (HTTP response headers, CSP, HSTS, XFO, etc.); those are a separate class.

Header-only / passive HTTP policy gaps:
- Titles for the same host may normalize to: `Missing or incomplete HTTP security response headers` (see deduplication in pipeline). Map OWASP 2025 **A02** (Security Misconfiguration) for that class, aligned with OWASP Top 10:2021 **A05:2021** (Security Misconfiguration) for customer-facing text (not 2021 A06 for this class).
- Do not set `exploit_demonstrated=true` for passive header observations; do not treat them as RCE, SQLi, or authentication bypass in prose.
- Do not label passive header observations as significant or critical vulnerabilities without separate validated impact evidence.
- Do not emit narrative tokens: `exploit_available`, `unauthorized access` (except verbatim from source tools), or “comprehensive penetration test” unless the run matches full-scope criteria.
- Do not emit header overclaims: `significant vulnerability`, `critical headers`, `confirmed exploitability`, `exploitation is possible`, `attackers can exploit this directly`, `gain unauthorized access`, `financial losses`, or `severe consequences` unless a separate validated exploit proves that impact.
- Do not emit weak rate-limit overclaims: `absence of effective rate limiting`, `does not implement rate limiting`, `allowing attackers to perform rapid login attempts`, `confirmed vulnerability`, `account compromise`, `brute force is possible as proven`, or `unauthorized access` unless strong login POST evidence exists.

Artifact / mandatory-section hints:
- ``parser_error`` vs ``artifact_missing_body`` vs ``no_observed_items_after_parsing`` are set by the pipeline: do not rewrite them into generic "parser_error" in prose; use the reason string from the payload.
- Deduplicate multiple CWE-79/XSS entries that share the same URL and parameter when merging normalized findings.
- Drop or never elevate ``threat_model_inference`` to the same list as tool-backed findings.
