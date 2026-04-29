# Report Validator Policy

Validate report content before render/export.

Hard failures:
- Conflicting CVSS fields (`cvss`, `cvss_score`, `cvss_base_score`) for the same finding.
- Severity label inconsistent with the canonical `cvss_score` band (CVSS 3.1: 0.0 info, 0.1–3.9 low, 4.0–6.9 medium, 7.0–8.9 high, 9.0–10.0 critical).
- High or critical finding without proof of concept and without evidence references.
- Empty or unknown finding title/description/severity.

Required downgrades or warnings:
- WSTG coverage below 70%.
- Critical scanner failure.
- Missing validation status.
- Weak or missing evidence quality.
- Finding confidence set to confirmed without moderate or strong evidence.
- Evidence text containing "unknown finding".

Structured finding fields (canonical):
- Use `cvss_score`, `cvss_vector`, `severity` (derived from score where applicable), `confidence`, `validation_status`, `evidence_quality`.
- `exploit_demonstrated` / `exploit_summary`: set `exploit_demonstrated` only when real impact or exploit reproduction was shown; passive header/TLS/curl checks are not exploits.

Expected language:
- Failed tool domain: "No conclusion can be drawn because tool execution failed."
- Low coverage: "This assessment does not represent comprehensive application penetration testing. Several OWASP WSTG categories were not assessed or were only partially assessed."

Reject or flag customer-facing strings that contain:
- Marketing / overclaim tokens: ``exploit_available``, ``to exploit this vulnerability``, ``comprehensive penetration test`` (when not full Valhalla / not in evidence), ``data breach`` as a generic claim without artifact support, ``unauthorized access`` as a generic statement not tied to cited evidence.
- Header-only overclaim tokens: ``significant vulnerability``, ``critical HTTP headers``, ``critical headers``, ``could be exploited by attackers``, ``attackers can exploit this directly``, ``confirmed exploitability``, ``exploitation is possible``, ``severe consequences``, ``financial losses``, ``gain unauthorized access``, and ``compromise the application`` unless separate validated impact evidence is cited.
- Weak rate-limit overclaim tokens: ``absence of effective rate limiting``, ``does not implement rate limiting``, ``allowing attackers to perform rapid login attempts``, ``confirmed vulnerability``, ``account compromise``, ``brute force is possible as proven``, and ``unauthorized access`` unless real login POST behavior, lockout/CAPTCHA/throttle behavior, timestamps, and raw request/response evidence are present.
- Customer-facing Valhalla OWASP mapping for missing/incomplete HTTP security headers must be A05:2021 Security Misconfiguration. Flag AI prose that presents A02 as the customer-facing category.
- Premise of "comprehensive pentest" when coverage or ``full_valhalla``-equivalent context does not support it.
- Findings with ``evidence_type=threat_model_inference`` must not appear as primary vulnerabilities; reject or move to threat-model appendices only.
- XSS (CWE-79) without response reflection, DOM evidence, or tool validation in the payload must not be labeled high/critical with "confirmed" confidence.
- Do not invent arbitrary destructive payloads or tool argv; destructive chains require lab opt-in (`ARGUS_LAB_MODE`) and explicit per-scan approval flags, not prose-only instructions.
- Executive or engagement summaries that only describe passive header/TLS review when the payload includes XSS or active-finding types.

Additional (active injection / OAST):
- Do not have the model emit free-form exploit or destructive payload strings; only select or reference catalog / policy-bound variants already defined in product code.
- Label SSRF/XXE/RCE (and similar) as `confirmed` only with an OAST / callback signal in structured evidence, not with narrative alone.
- SQLMap / commix and other destructive VA tools: never assume they ran; tie claims to `scan_approval_flags` and lab mode only when the pipeline recorded them.
