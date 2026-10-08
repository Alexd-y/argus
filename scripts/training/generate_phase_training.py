#!/usr/bin/env python3
"""
ARGUS WhiteRabbitNeo — 8-phase, report-aligned fine-tuning dataset builder.

Emits SFT records whose (system, user, assistant) match the REAL runtime phase
contracts (prompt_registry.PHASE_PROMPTS / PHASE_SCHEMAS), so a LoRA fine-tune
teaches the exact JSON ARGUS consumes and that flows into the Asgard / Midgard /
Valhalla reports.

Phases covered (ScanPhase order):
  source_analysis  -> phase_source_analysis   (missed_sinks/cross_file_taint/auth_gaps)
  recon            -> phase_recon             ({assets,subdomains,ports})
  quick_fuzz       -> (no LLM call; skipped by design)
  threat_modeling  -> phase_threat_modeling   (STRIDE threat_model{...})
  vuln_analysis    -> phase_vuln_analysis     (findings[] w/ cwe/cvss/confidence/evidence_*)
  exploitation     -> phase_exploitation      (exploits[]+evidence[]+evidence_gaps[])
  post_exploitation-> phase_post_exploitation (lateral[]/persistence[], fail-closed empties)
  reporting        -> phase_report_section    ({section:{...}})
                      phase_report_assembly   ({report:{...}})
                      phase_report_prose       (grounded prose with [CL-]/[E-] citations)

Report-flow correctness baked in:
  * provable findings use non-inference evidence_type + confidence confirmed/likely
    + populated evidence_refs  -> land in Valhalla main body (evidence_partition gate);
  * inference/low-confidence findings are NEVER claimed confirmed (teaches downgrade);
  * exploitation exploits always carry finding_id+target (EXPLOITATION_SCHEMA required);
  * post_exploitation emits empty arrays when no verified exploit (anti-hallucination);
  * prose paragraphs always cite [CL-<finding>]/[E-<evidence>] (prose_gate._REFERENCE_RE).

Targets are SYNTHETIC only (RFC 2606 / 5737 / 1918). All offensive execution is
gated by the ARGUS platform (scope / lab lease / tool-approval), not model output.

Usage:
    py scripts/training/generate_phase_training.py --count 1400 --seed 42
    py scripts/training/convert_to_jsonl.py --input-dir training_data/ --output-dir training_data/final/
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from phase_prompt_catalog import (
    EXPLOITATION_SCHEMA,
    EXPLOITATION_USER_TMPL,
    POST_EXPLOITATION_SCHEMA,
    POST_EXPLOITATION_USER_TMPL,
    RECON_SCHEMA,
    RECON_USER_TMPL,
    REPORT_ASSEMBLY_USER_TMPL,
    REPORT_PROSE_SECTION_KEYS,
    REPORT_PROSE_SYSTEM,
    REPORT_SECTION_SCHEMA,
    REPORT_SECTION_VULN_USER_TMPL,
    REPORTING_SCHEMA,
    SOURCE_ANALYSIS_LLM_SCHEMA,
    SOURCE_ANALYSIS_SYSTEM,
    SOURCE_ANALYSIS_USER_TMPL,
    SYSTEM_PROMPT_EXPLOITATION,
    SYSTEM_PROMPT_POST_EXPLOITATION,
    SYSTEM_PROMPT_RECON,
    SYSTEM_PROMPT_REPORT_ASSEMBLY,
    SYSTEM_PROMPT_REPORT_SECTION_VULN,
    SYSTEM_PROMPT_THREAT_MODELING,
    SYSTEM_PROMPT_VULN_ANALYSIS,
    THREAT_MODEL_SCHEMA,
    THREAT_MODELING_USER_TMPL,
    USING_REAL_REGISTRY,
    VULN_ANALYSIS_SCHEMA,
    VULN_ANALYSIS_USER_TMPL,
    phase_prompts,
)

# optional strict validation
try:
    import jsonschema  # type: ignore
    _HAVE_JSONSCHEMA = True
except Exception:  # noqa: BLE001
    _HAVE_JSONSCHEMA = False

# ---------------------------------------------------------------------------
# Synthetic, reserved-only corpora.
# ---------------------------------------------------------------------------
DOMAINS = [
    "example.com", "api.example.com", "app.example.org", "shop.example.net",
    "acme-corp.example", "portal.contoso.example", "dev.test-lab.example",
    "intranet.corp.example", "web.example.io", "staging.example.com",
]
IPS = ["192.0.2.10", "192.0.2.80", "198.51.100.42", "203.0.113.7", "10.10.14.7"]

# (name, version, cve_id, cve_sev, cve_desc)
TECHS = [
    ("nginx", "1.18.0", "CVE-2021-23017", "high", "nginx resolver off-by-one heap write"),
    ("Apache httpd", "2.4.49", "CVE-2021-41773", "critical", "Path traversal & RCE in mod_cgi"),
    ("OpenSSH", "8.2p1", "CVE-2020-15778", "medium", "scp command injection via filename"),
    ("PHP", "7.4.3", "CVE-2019-11043", "critical", "php-fpm underflow RCE (FPM)"),
    ("WordPress", "6.0", "CVE-2022-21664", "high", "SQLi in WP_Query/meta_query"),
    ("MySQL", "5.7.33", "CVE-2021-2154", "medium", "Server DML privilege escalation DoS"),
    ("Tomcat", "9.0.30", "CVE-2020-1938", "critical", "Ghostcat AJP file read/inclusion"),
    ("Express", "4.17.1", "CVE-2022-24999", "high", "qs prototype pollution DoS"),
]

# (title, cwe, cvss, vuln_type, payload_type, tool, owasp)
VULN_LIB = [
    ("SQL injection in id parameter", "CWE-89", 9.8, "sqli", "sqli", "sqlmap", "A03"),
    ("Reflected XSS in search parameter", "CWE-79", 6.1, "xss", "xss", "dalfox", "A03"),
    ("Path traversal in file parameter", "CWE-22", 7.5, "lfi", "lfi", "ffuf", "A01"),
    ("Server-side request forgery in url param", "CWE-918", 8.6, "ssrf", "ssrf", "nuclei", "A10"),
    ("OS command injection in host param", "CWE-78", 9.8, "cmdi", "rce", "commix", "A03"),
    ("Open redirect in next parameter", "CWE-601", 5.4, "open_redirect", "other", "nuclei", "A01"),
    ("IDOR on /api/users/{id}", "CWE-639", 7.5, "idor", "auth_bypass", "ffuf", "A01"),
    ("Security misconfiguration: exposed .git", "CWE-538", 7.5, "exposure", "other", "httpx", "A05"),
    ("Outdated component with known CVE", "CWE-1035", 7.3, "outdated", "other", "nuclei", "A06"),
    ("Missing security headers (CSP/HSTS)", "CWE-693", 4.3, "headers", "other", "nuclei", "A05"),
]

MITRE = {
    "sqli": "T1190", "xss": "T1059.007", "lfi": "T1083", "ssrf": "T1190",
    "cmdi": "T1059", "open_redirect": "T1204", "idor": "T1083",
    "exposure": "T1083", "outdated": "T1190", "headers": "T1190",
}


def _is_ip(t: str) -> bool:
    return t[0].isdigit()


def _url(target: str) -> str:
    return f"http://{target}" if _is_ip(target) else f"https://{target}"


def _validate(obj: dict, schema: dict) -> None:
    if _HAVE_JSONSCHEMA:
        jsonschema.validate(obj, schema)
        return
    # minimal required-keys check
    for key in schema.get("required", []):
        if key not in obj:
            raise ValueError(f"missing required key: {key}")


def _record(system: str, user: str, assistant: str, task: str, phase: str,
            tool_ids: list[str], cwe_ids: list[int]) -> dict:
    return {
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "metadata": {
            "task": task, "source": "synthetic", "license": "internal",
            "argus_phase": phase, "argus_tool_ids": tool_ids,
            "argus_payload_families": [], "cwe_ids": cwe_ids,
        },
    }


def _cwe_num(cwe: str) -> int:
    try:
        return int(cwe.split("-")[1])
    except Exception:  # noqa: BLE001
        return 0


# ---------------------------------------------------------------------------
# Shared scenario: a coherent per-target set of findings reused across phases.
# ---------------------------------------------------------------------------
def scenario(rng: random.Random, target: str) -> dict:
    techs = rng.sample(TECHS, k=rng.randint(2, 4))
    vulns = rng.sample(VULN_LIB, k=rng.randint(2, 4))
    findings = []
    for i, (title, cwe, cvss, vtype, ptype, tool, owasp) in enumerate(vulns, 1):
        fid = f"VA-{i:04d}"
        # provable vs inference split
        provable = vtype in ("sqli", "xss", "lfi", "ssrf", "cmdi", "idor", "exposure")
        if provable:
            conf = rng.choice(["confirmed", "likely"])
            etype = rng.choice(["tool_output", "observed", "version_match"])
            erefs = [f"E-{i:04d}"]
        else:
            conf = rng.choice(["possible", "advisory"])
            etype = "threat_model_inference"
            erefs = []
        sev = ("critical" if cvss >= 9 else "high" if cvss >= 7
               else "medium" if cvss >= 4 else "low")
        findings.append({
            "finding_id": fid, "title": title, "severity": sev, "cwe": cwe,
            "cvss": cvss, "vuln_type": vtype, "payload_type": ptype, "tool": tool,
            "owasp": owasp, "confidence": conf, "evidence_type": etype,
            "evidence_refs": erefs,
            "affected_url": f"{_url(target)}/?{ 'id' if vtype=='sqli' else 'q' }=1",
            "parameter": "id" if vtype == "sqli" else "q",
        })
    return {"target": target, "techs": techs, "findings": findings}


# ---------------------------------------------------------------------------
# Per-phase builders -> list[record]
# ---------------------------------------------------------------------------
def build_recon(rng: random.Random, target: str) -> dict:
    sys_p, user_t = phase_prompts().get("recon", (SYSTEM_PROMPT_RECON, RECON_USER_TMPL))
    subs = [] if _is_ip(target) else [f"{p}.{target}" for p in rng.sample(
        ["www", "api", "dev", "mail", "admin", "vpn", "staging"], k=rng.randint(2, 4))]
    ports = rng.sample([22, 80, 443, 3306, 8080, 8443, 6379, 5432], k=rng.randint(2, 4))
    ports = sorted(set(ports))
    tech_lines = "\n".join(f"{t[0]}/{t[1]}" for t in rng.sample(TECHS, 3))
    tool_results = (
        f"# nmap -sV {target}\n"
        + "\n".join(f"{p}/tcp open {'http' if p in (80,8080) else 'https' if p in (443,8443) else 'svc'}"
                    for p in ports)
        + f"\n# httpx {_url(target)}\n{_url(target)} [200] [{tech_lines}]\n"
        + ("" if _is_ip(target) else "# subfinder\n" + "\n".join(subs) + "\n")
    )
    user = user_t.format(target=target, options="{'mode': 'full', 'scope': 'all'}",
                         tool_results=tool_results)
    assets = [target] + ([] if _is_ip(target) else subs[:1])
    out = {"assets": assets, "subdomains": subs, "ports": ports}
    _validate(out, RECON_SCHEMA)
    return _record(sys_p, user, json.dumps(out, ensure_ascii=False),
                   "phase_recon", "recon", ["nmap", "httpx", "subfinder"], [])


def build_threat_modeling(rng: random.Random, target: str) -> dict:
    sys_p, user_t = phase_prompts().get(
        "threat_modeling", (SYSTEM_PROMPT_THREAT_MODELING, THREAT_MODELING_USER_TMPL))
    sc = scenario(rng, target)
    techs = sc["techs"]
    nvd = "\n".join(f"{t[0]} {t[1]}: {t[2]} ({t[3]}) {t[4]}" for t in techs)
    recon_ctx = json.dumps({"assets": [target], "technologies": [f"{t[0]}/{t[1]}" for t in techs]})
    attack_surface = [
        {"component": "login form", "type": "web_form", "exposure_level": "external",
         "url": f"{_url(target)}/login"},
        {"component": "REST API", "type": "api_endpoint", "exposure_level": "external",
         "url": f"{_url(target)}/api/"},
    ]
    threats = [
        {"category": "T", "description": "Tampering with request params enables injection",
         "component": "REST API", "likelihood": "high", "impact": "high"},
        {"category": "I", "description": "Info disclosure via verbose errors",
         "component": "login form", "likelihood": "medium", "impact": "medium"},
        {"category": "E", "description": "Privilege escalation via IDOR",
         "component": "REST API", "likelihood": "medium", "impact": "high"},
    ]
    cves = [{"cve_id": t[2], "technology": f"{t[0]} {t[1]}", "severity": t[3],
             "description": t[4]} for t in techs]
    mitigations = [
        {"threat_ref": "T", "recommendation": "Parameterize queries; validate input on the REST API",
         "priority": "high"},
        {"threat_ref": "I", "recommendation": "Disable verbose errors on the login form", "priority": "medium"},
    ]
    out = {"threat_model": {"attack_surface": attack_surface, "threats": threats,
                            "cves": cves, "mitigations": mitigations}}
    _validate(out, THREAT_MODEL_SCHEMA)
    user = user_t.format(assets=json.dumps([target]), recon_context=recon_ctx, nvd_data=nvd)
    return _record(sys_p, user, json.dumps(out, ensure_ascii=False),
                   "phase_threat_modeling", "threat_modeling", ["nuclei"],
                   sorted({_cwe_num(v[1]) for v in VULN_LIB[:3]}))


def build_vuln_analysis(rng: random.Random, target: str) -> dict:
    sys_p, user_t = phase_prompts().get(
        "vuln_analysis", (SYSTEM_PROMPT_VULN_ANALYSIS, VULN_ANALYSIS_USER_TMPL))
    sc = scenario(rng, target)
    findings = []
    for f in sc["findings"]:
        findings.append({
            "severity": f["severity"], "title": f["title"], "cwe": f["cwe"],
            "cvss": f["cvss"], "description": f"{f['title']} detected on {f['affected_url']}.",
            "affected_asset": target, "affected_url": f["affected_url"],
            "parameter": f["parameter"],
            "remediation": "Validate/encode input; apply least privilege; patch component.",
            "confidence": f["confidence"], "evidence_type": f["evidence_type"],
            "evidence_refs": f["evidence_refs"],
            "reproducible_steps": f"Send crafted request to {f['affected_url']} and observe tool output."
            if f["evidence_refs"] else "",
            "applicability_notes": "" if f["evidence_refs"] else "Inference from threat model; needs active re-test.",
            "finding_id": f["finding_id"], "vuln_type": f["vuln_type"],
        })
    out = {"findings": findings}
    _validate(out, VULN_ANALYSIS_SCHEMA)
    active_ctx = ("=== ACTIVE SCAN CONTEXT ===\n"
                  + "\n".join(f"{f['tool']}: {f['title']} @ {f['affected_url']}" for f in sc["findings"])
                  + "\n=== END ===\n")
    tm = json.dumps({"threats": [{"component": "REST API", "category": "T"}]})
    user = user_t.format(threat_model=tm, assets=json.dumps([target]), active_scan_context=active_ctx)
    return _record(sys_p, user, json.dumps(out, ensure_ascii=False),
                   "phase_vuln_analysis", "vuln_analysis",
                   sorted({f["tool"] for f in sc["findings"]}),
                   sorted({_cwe_num(f["cwe"]) for f in sc["findings"]}))


def build_exploitation(rng: random.Random, target: str) -> dict:
    sys_p, user_t = phase_prompts().get(
        "exploitation", (SYSTEM_PROMPT_EXPLOITATION, EXPLOITATION_USER_TMPL))
    sc = scenario(rng, target)
    exploits, evidence, gaps = [], [], []
    for f in sc["findings"]:
        provable = bool(f["evidence_refs"])
        status = "verified" if provable else "theoretical"
        exploits.append({
            "finding_id": f["finding_id"], "target": f["affected_url"], "status": status,
            "title": f["title"], "technique": MITRE.get(f["vuln_type"], "T1190"),
            "tool": f["tool"], "args": ["-u", f["affected_url"], "--batch"],
            "payload": {"sqli": "' OR '1'='1", "xss": "<script>alert(1)</script>",
                        "lfi": "../../etc/passwd", "ssrf": "http://169.254.169.254/",
                        "rce": ";id", "other": "payload"}.get(f["payload_type"], "payload"),
            "payload_type": f["payload_type"],
            "description": f"Validate {f['title']} with {f['tool']}.",
            "impact": "Data exposure / code execution" if provable else "Potential impact — unverified",
            "difficulty": rng.choice(["easy", "medium", "hard"]),
            "evidence_gap": "" if provable else "missing_poc",
            "expected_response": "tool confirms exploitability" if provable else "n/a",
        })
        if provable:
            evidence.append({"type": "tool_output", "path": f"s3://argus-reports/{f['evidence_refs'][0]}.txt",
                             "finding_id": f["finding_id"]})
        else:
            gaps.append({"gap_finding_id": f["finding_id"], "gap_type": "missing_poc",
                         "recommended_action": f"Run {f['tool']} against {f['affected_url']}",
                         "priority": "high" if f["severity"] in ("critical", "high") else "medium"})
    out = {"exploits": exploits, "evidence": evidence, "evidence_gaps": gaps}
    _validate(out, EXPLOITATION_SCHEMA)
    user = user_t.format(findings=json.dumps(
        [{"finding_id": f["finding_id"], "title": f["title"], "vuln_type": f["vuln_type"],
          "affected_url": f["affected_url"], "confidence": f["confidence"]} for f in sc["findings"]]))
    return _record(sys_p, user, json.dumps(out, ensure_ascii=False),
                   "phase_exploitation", "exploitation",
                   sorted({f["tool"] for f in sc["findings"]}),
                   sorted({_cwe_num(f["cwe"]) for f in sc["findings"]}))


def build_post_exploitation(rng: random.Random, target: str, verified: bool) -> dict:
    sys_p, user_t = phase_prompts().get(
        "post_exploitation", (SYSTEM_PROMPT_POST_EXPLOITATION, POST_EXPLOITATION_USER_TMPL))
    if verified:
        exploits = [{"finding_id": "VA-0001", "status": "verified",
                     "title": "OS command injection", "payload_type": "rce",
                     "target": f"{_url(target)}/?host=1"}]
        lateral = [{"technique": "T1021 Remote Services",
                    "description": "Pivot to internal host via obtained RCE shell",
                    "from_exploit": "VA-0001"}]
        persistence = [{"type": "cron job", "description": "Scheduled reverse shell callback",
                        "risk_level": "high"}]
    else:
        # fail-closed: no verified access -> no fabricated post-exploitation
        exploits = [{"finding_id": "VA-0002", "status": "theoretical",
                     "title": "Reflected XSS", "payload_type": "xss",
                     "target": f"{_url(target)}/?q=1"}]
        lateral, persistence = [], []
    out = {"lateral": lateral, "persistence": persistence}
    _validate(out, POST_EXPLOITATION_SCHEMA)
    user = user_t.format(exploits=json.dumps(exploits))
    return _record(sys_p, user, json.dumps(out, ensure_ascii=False),
                   "phase_post_exploitation", "post_exploitation", [], [])


def build_source_analysis(rng: random.Random, target: str) -> dict:
    lang, fw, ext = rng.choice([("python", "flask", "py"), ("php", "laravel", "php"),
                                ("javascript", "express", "js"), ("java", "spring", "java")])
    app = target.split(".")[0].replace("-", "_")
    module = rng.choice(["user", "admin", "api", "auth", "payment", "upload", "search"])
    sink_file = f"{app}/{rng.choice(['routes','controllers','services'])}/{module}.{ext}"
    source_file = f"{app}/{rng.choice(['http','input','web'])}/request.{ext}"
    line = rng.randint(20, 400)
    sink_type = rng.choice(["sql_query", "os_command", "file_read", "deserialize", "template_render"])
    snippet = {
        "sql_query": "db.execute(f\"SELECT * FROM u WHERE id={request.args['id']}\")",
        "os_command": "os.system('ping ' + request.args.get('host'))",
        "file_read": "open(request.args.get('path')).read()",
        "deserialize": "pickle.loads(base64.b64decode(data))",
        "template_render": "render_template_string(request.args.get('q'))",
    }[sink_type]
    cwe_for = {"sql_query": 89, "os_command": 78, "file_read": 22,
               "deserialize": 502, "template_render": 94}[sink_type]
    entry_points = rng.sample(["/login", "/api/users", "/admin", "/upload",
                               "/search", "/payment", "/reset", "/export"], k=rng.randint(3, 5))
    missed = [{"file_path": sink_file, "line_number": line, "sink_type": sink_type,
               "code_snippet": snippet, "severity": rng.choice(["high", "medium", "low"])}]
    taint = [{"source_file": source_file, "source_function": "get_param",
              "sink_file": sink_file, "sink_function": module + "_handler"}]
    gaps = [{"type": "missing_authz_check", "file_path": f"{app}/routes/admin.{ext}",
             "description": f"{module} route lacks role verification before action"}]
    out = {"missed_sinks": missed, "cross_file_taint": taint, "auth_gaps": gaps}
    _validate(out, SOURCE_ANALYSIS_LLM_SCHEMA)
    user = SOURCE_ANALYSIS_USER_TMPL.format(
        language=lang, framework=fw,
        known_sinks=json.dumps([{"file": sink_file, "sink": "run_raw_sql"},
                                {"file": source_file, "source": "get_param"}]),
        entry_points=json.dumps(entry_points)) + f"\nRepository: {app} ({target})"
    return _record(SOURCE_ANALYSIS_SYSTEM, user, json.dumps(out, ensure_ascii=False),
                   "phase_source_analysis", "source_analysis", ["semgrep", "bandit"],
                   [cwe_for])


def build_report_section(rng: random.Random, target: str) -> dict:
    sc = scenario(rng, target)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    idx = []
    for f in sc["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        idx.append({"finding_id": f["finding_id"], "title": f["title"], "cwe": f["cwe"],
                    "cvss": f["cvss"], "severity": f["severity"], "confidence": f["confidence"],
                    "evidence_type": f["evidence_type"], "owasp": f["owasp"]})
    owasp_cov = {}
    for f in sc["findings"]:
        owasp_cov[f["owasp"]] = owasp_cov.get(f["owasp"], 0) + 1
    out = {"section": {"findings_index": idx, "severity_distribution": counts,
                       "owasp_coverage": owasp_cov,
                       "vuln_analysis_summary": f"{len(idx)} findings across {len(owasp_cov)} OWASP categories on {target}."}}
    _validate(out, REPORT_SECTION_SCHEMA)
    phase_data = json.dumps({"findings": idx}, ensure_ascii=False)
    user = REPORT_SECTION_VULN_USER_TMPL.format(phase_data=phase_data)
    return _record(SYSTEM_PROMPT_REPORT_SECTION_VULN, user, json.dumps(out, ensure_ascii=False),
                   "phase_report_section", "reporting", [],
                   sorted({_cwe_num(f["cwe"]) for f in sc["findings"]}))


def build_report_assembly(rng: random.Random, target: str) -> dict:
    sc = scenario(rng, target)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in sc["findings"]:
        counts[f["severity"]] += 1
    risk = ("Critical" if counts["critical"] else "High" if counts["high"]
            else "Medium" if counts["medium"] else "Low")
    details = [{"severity": f["severity"], "description": f["title"],
                "impact": "Confirmed exploitable" if f["evidence_refs"] else "Potential — unverified",
                "remediation": "Patch and validate input."} for f in sc["findings"]]
    out = {"report": {"summary": {**counts, "risk_rating": risk},
                      "executive_summary": f"Assessment of {target} identified {len(sc['findings'])} findings; overall risk {risk}.",
                      "sections": ["scope", "methodology", "findings", "recommendations"],
                      "findings_detail": details,
                      "ai_insights": [f"Prioritize the {risk.lower()}-risk injection findings for remediation."]}}
    _validate(out, REPORTING_SCHEMA)
    user = REPORT_ASSEMBLY_USER_TMPL.format(
        target=target,
        recon_summary=f"Assets and ports enumerated for {target}.",
        threat_model_summary="STRIDE threats mapped to API and login form.",
        vuln_summary=f"{len(sc['findings'])} findings with CWE/CVSS assigned.",
        exploit_summary="Verified injection exploits with tool evidence.",
        post_exploit_summary="No confirmed lateral movement.")
    return _record(SYSTEM_PROMPT_REPORT_ASSEMBLY, user, json.dumps(out, ensure_ascii=False),
                   "phase_report_assembly", "reporting", [],
                   sorted({_cwe_num(f["cwe"]) for f in sc["findings"]}))


def build_report_prose(rng: random.Random, target: str, section_key: str) -> dict:
    """PROSE with mandatory [CL-<finding>]/[E-<evidence>] citations (prose_gate)."""
    sc = scenario(rng, target)
    # build evidence-reference labels like evidence_references.build_evidence_reference_index
    ctx_findings = []
    cl_for = {}
    e_for = {}
    for i, f in enumerate(sc["findings"], 1):
        cl = f"CL-{i:04d}"
        cl_for[f["finding_id"]] = cl
        ev = f["evidence_refs"][0] if f["evidence_refs"] else None
        if ev:
            e_for[f["finding_id"]] = f"E-{i:04d}"
        ctx_findings.append({
            "finding_id": f["finding_id"], "title": f["title"], "severity": f["severity"],
            "cwe": f["cwe"], "owasp": f["owasp"], "url": f["affected_url"],
            "parameter": f["parameter"], "evidence_type": f["evidence_type"],
            "validation_status": "validated" if f["evidence_refs"] else "unverified",
            "confidence": f["confidence"], "evidence": f["evidence_refs"],
        })
    # prose: one grounded, cited paragraph per provable finding
    paras = []
    for f in sc["findings"]:
        marker = f"[{cl_for[f['finding_id']]}" + (f" / {e_for[f['finding_id']]}" if f["finding_id"] in e_for else "") + "]"
        if f["evidence_refs"]:
            paras.append(
                f"The assessment confirmed a {f['title'].lower()} on the {f['parameter']} parameter "
                f"at {f['affected_url']} ({f['cwe']}, CVSS {f['cvss']}). The sandbox tool output "
                f"recorded the injected request and the resulting response, establishing exploitability. {marker}")
        else:
            paras.append(
                f"A {f['title'].lower()} is hypothesised on {f['affected_url']} from threat-model "
                f"inference; it is not yet validated and must be re-tested before it is treated as confirmed. {marker}")
    if section_key == "executive_summary":
        provable = sum(1 for f in sc["findings"] if f["evidence_refs"])
        body = (f"The engagement against {target} produced {len(sc['findings'])} findings, of which "
                f"{provable} are evidence-backed and exploitable. " + paras[0])
    elif section_key == "remediation_step":
        body = ("Remediate the confirmed injection by switching the affected endpoint to parameterised "
                "queries and server-side input validation. " + paras[0])
    else:
        body = "\n\n".join(paras)
    assistant = body  # PROSE, JSON-exempt
    user = (json.dumps({"schema_version": "report_section_input_v1", "section_key": section_key,
                        "findings": ctx_findings}, ensure_ascii=False)
            + f"\n\nWrite the '{section_key}' section. Cite [CL-]/[E-] markers on every factual paragraph.")
    return _record(REPORT_PROSE_SYSTEM, user, assistant,
                   "phase_report_prose", "reporting", [],
                   sorted({_cwe_num(f["cwe"]) for f in sc["findings"]}))


# ---------------------------------------------------------------------------
def generate(count: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    recs: list[dict] = []
    targets = DOMAINS + IPS

    for target in targets:
        recs.append(build_recon(rng, target))
        recs.append(build_threat_modeling(rng, target))
        recs.append(build_vuln_analysis(rng, target))
        recs.append(build_exploitation(rng, target))
        recs.append(build_post_exploitation(rng, target, verified=True))
        recs.append(build_post_exploitation(rng, target, verified=False))
        recs.append(build_source_analysis(rng, target))
        recs.append(build_report_section(rng, target))
        recs.append(build_report_assembly(rng, target))
        for sk in REPORT_PROSE_SECTION_KEYS:
            recs.append(build_report_prose(rng, target, sk))

    # multiple scenario variants per phase for volume/variety
    extra_rounds = 6
    for _ in range(extra_rounds):
        for target in targets:
            recs.append(build_vuln_analysis(rng, target))
            recs.append(build_exploitation(rng, target))
            recs.append(build_threat_modeling(rng, target))
            recs.append(build_recon(rng, target))
            recs.append(build_report_section(rng, target))
            recs.append(build_report_assembly(rng, target))
            recs.append(build_source_analysis(rng, target))
            recs.append(build_report_prose(rng, target, rng.choice(REPORT_PROSE_SECTION_KEYS)))

    # dedup by (task,user)
    seen: set[tuple[str, str]] = set()
    uniq: list[dict] = []
    for r in recs:
        key = (r["metadata"]["task"], r["messages"][1]["content"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)

    rng.shuffle(uniq)
    if count and len(uniq) > count:
        uniq = uniq[:count]
    return uniq


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="training_data/phase_training.jsonl")
    ap.add_argument("--count", type=int, default=1400, help="Cap (0 = no cap).")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    recs = generate(args.count, args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    by_task: dict[str, int] = {}
    for r in recs:
        t = r["metadata"]["task"]
        by_task[t] = by_task.get(t, 0) + 1
    print(f"[done] wrote {len(recs)} phase-aligned examples -> {out}")
    print(f"  prompt source: {'REAL prompt_registry (byte-exact)' if USING_REAL_REGISTRY else 'embedded faithful copy'}")
    print(f"  jsonschema validation: {'on' if _HAVE_JSONSCHEMA else 'required-keys only'}")
    for t in sorted(by_task):
        print(f"    {t}: {by_task[t]}")
    print("  next: py scripts/training/convert_to_jsonl.py "
          "--input-dir training_data/ --output-dir training_data/final/")


if __name__ == "__main__":
    main()
