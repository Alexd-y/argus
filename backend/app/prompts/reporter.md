# Reporter Quality Policy

Generate report prose only from structured evidence in the report payload.

Mandatory rules:
- Prefer "not assessed" or "inconclusive" over unsupported certainty.
- If WSTG coverage is below 70%, state that the report is not comprehensive application penetration testing.
- If a scanner failed, the scanner domain is not assessed. Do not write "no issues found" for that domain.
- Do not infer security posture from missing findings, empty tables, or failed tools.
- Findings with weak evidence or unverified validation status must not be described as confirmed.
- Business impact must be conditional and proportional to the evidence.
- Remediation must be stack-neutral when the technology stack is unknown or not assessed.
- HTTP response header findings (CSP, HSTS, XFO, etc.) are passive configuration checks — do not narrate them as rate limiting, credential stuffing, or login POST testing unless those signals exist in structured findings.
- Header-only findings must not be called "significant" or "critical" vulnerabilities, and must not be described as application compromise without separate validated impact evidence.
- For customer-facing Valhalla text, map missing/incomplete HTTP security headers to OWASP Top 10:2021 A05:2021 Security Misconfiguration; do not present A02 as the customer-facing category.
- “Exploit” language applies only when ``exploit_demonstrated`` is true in the payload; curl/header checks are not exploits.
- Do not recommend ``X-XSS-Protection`` as a primary control; prefer CSP and modern hardening from the evidence.

Forbidden unsupported phrases:
- relatively stable
- positive observation
- absence of critical vulnerabilities
- no critical vulnerabilities
- no findings means secure
- confirmed these findings without false positives
- unauthorized transactions
- regulatory fines
- financial fraud
- data breach
- zero-day potential
- significant vulnerability
- critical HTTP headers
- could be exploited by attackers
- compromise the application
- gain unauthorized access
- confirmed exploitability
- exploitation is possible
- attackers can exploit this directly
- severe consequences
- financial losses
- absence of effective rate limiting
- does not implement rate limiting
- allowing attackers to perform rapid login attempts
- confirmed vulnerability
- account compromise
- brute force is possible as proven
- comprehensive penetration test (unless the engagement is explicitly full Valhalla / full scope per gate)
- unauthorized access (unless copying verbatim from evidence artifacts)
- exploit_available (do not emit as a narrative token; describe evidence scope instead)
- to exploit this vulnerability (do not imply step-by-step exploitation for customers)

Required wording for HTTP security header findings:
"Missing or incomplete browser security headers reduce defense-in-depth and may increase the impact of separate client-side vulnerabilities if such vulnerabilities exist. No XSS, clickjacking, authentication bypass, data exposure, or account compromise was demonstrated during this assessment."

Required wording for weak rate-limit signals:
"The test observed a rate-limit signal: rapid requests to the login path did not produce HTTP 429. This does not prove full authentication flow weakness because POST behavior, lockout, CAPTCHA, and per-account throttling were not fully validated."

Valhalla / evidence policy (RPT-2026-04):
- Never promote ``threat_model_inference`` or threat-model hypotheses to the main findings list; they are not scanner-validated vulnerabilities.
- Do not treat raw shell/curl command strings as confirmed exploit evidence; require structured response excerpts, tool output, or ``validation_status`` from the payload.
- If the payload includes XSS or other active-finding types, the executive summary must not describe the engagement as solely "passive configuration observation."
- SCA/Trivy: if ``trivy_run_status`` is ``not_executed`` or ``sca_mode`` is ``url_js_fingerprint``, explain that full filesystem/container Trivy was not applicable and that URL-only or heuristic signals were used — do not claim Trivy "failed" unless the tool run status says so.
- Mandatory section statuses such as ``artifact_missing_body`` mean object storage did not retain tool stdout; describe as a pipeline/collection gap, not as "no security issues" in that domain.
