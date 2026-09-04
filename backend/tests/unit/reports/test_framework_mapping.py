"""Block 4.2 — ISO 27001 / SOC 2 framework mapping tests."""

from __future__ import annotations

from src.reports.finding_metadata import apply_default_finding_metadata
from src.reports.framework_mapping import map_finding_frameworks


def _frameworks(mapped):
    return {m["framework"] for m in mapped}


def _control_ids(mapped, framework):
    return {m["control_id"] for m in mapped if m["framework"] == framework}


def test_cwe_mapping_xss():
    m = map_finding_frameworks({"cwe": "CWE-79"})
    assert _frameworks(m) == {"iso27001", "soc2"}
    assert "A.8.25" in _control_ids(m, "iso27001")
    assert "CC6.1" in _control_ids(m, "soc2")


def test_cwe_mapping_tls_crypto():
    m = map_finding_frameworks({"cwe": "326"})
    assert "A.8.24" in _control_ids(m, "iso27001")
    assert "CC6.7" in _control_ids(m, "soc2")


def test_control_names_resolved():
    m = map_finding_frameworks({"cwe": "CWE-350"})
    dnssec = next(x for x in m if x["control_id"] == "A.8.9")
    assert dnssec["control_name"] == "Configuration management"


def test_vuln_type_fallback_when_no_cwe():
    m = map_finding_frameworks({"vuln_type": "credential_exposure"})
    assert "A.5.34" in _control_ids(m, "iso27001")


def test_default_when_unknown():
    m = map_finding_frameworks({"title": "something", "cwe": "CWE-99999"})
    # Unknown CWE falls through to default mapping.
    assert "A.8.8" in _control_ids(m, "iso27001")
    assert "CC7.1" in _control_ids(m, "soc2")


def test_metadata_annotates_compliance():
    f = {"title": "SQL injection", "cwe": "CWE-89", "severity": "high"}
    apply_default_finding_metadata(f)
    assert f.get("compliance")
    assert any(c["framework"] == "iso27001" for c in f["compliance"])


def test_metadata_does_not_overwrite_explicit_compliance():
    explicit = [{"framework": "iso27001", "control_id": "X", "control_name": "custom"}]
    f = {"title": "x", "cwe": "CWE-89", "compliance": explicit}
    apply_default_finding_metadata(f)
    assert f["compliance"] == explicit
