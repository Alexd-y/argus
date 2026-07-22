"""P6-CHECKLIST-006 unit tests.

Covers:
* Nuclei ``argus-*`` positive / negative JSONL fixtures → intel finding row.
* ``az0x7_classified.yaml`` structural + provenance validity (category A-F).
* "no verbatim copying" heuristic on ``normalized_check`` (SI-6).
* Category-D proposed payload families do not collide with existing families.
* ``argus-*`` template structural validity (proxy for ``nuclei -validate`` when
  the binary is unavailable).
* ``build_nuclei_va_argv`` G-6 fix: safe ``-t`` argus dir, arbitrary paths rejected.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from src.recon.schemas.base import FindingType
from src.recon.vulnerability_analysis.active_scan.nuclei_va_adapter import (
    ARGUS_NUCLEI_TEMPLATES_DIR,
    build_nuclei_va_argv,
    normalize_nuclei_findings,
    parse_nuclei_stdout,
    resolve_argus_templates_dir,
)

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_CHECKLIST = _BACKEND_ROOT / "config" / "checklist" / "az0x7_classified.yaml"
_TEMPLATES_DIR = _BACKEND_ROOT / "config" / "nuclei-templates" / "argus"
_PAYLOAD_INDEX = _BACKEND_ROOT / "config" / "payloads" / "payload_catalog_index.json"

_VALID_CATEGORIES = frozenset("ABCDEF")
_VALID_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_ARGUS_TEMPLATE_IDS = frozenset(
    {
        "argus-django-debug-exposure",
        "argus-symfony-profiler-exposure",
        "argus-aem-default-content-exposure",
        "argus-jira-unauth-dashboard",
    }
)
_MAX_TOKEN_LEN = 40
_VERBATIM_MARKERS = ("<script", "' or '1'='1", "union select", "../../", "%0d%0a")


def _load_checklist() -> dict:
    return yaml.safe_load(_CHECKLIST.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Parser fixtures
# ---------------------------------------------------------------------------


def test_positive_fixture_parses_to_intel_finding() -> None:
    raw = parse_nuclei_stdout((_FIXTURES / "argus_positive.jsonl").read_text(encoding="utf-8"))
    findings = normalize_nuclei_findings(raw)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_type"] == FindingType.VULNERABILITY
    assert finding["source_tool"] == "nuclei"
    assert finding["data"]["template_id"] == "argus-django-debug-exposure"
    assert finding["data"]["severity"] == "medium"
    assert "target.example" in finding["value"]
    assert 0.0 < finding["confidence"] <= 1.0


def test_negative_fixture_yields_no_finding() -> None:
    raw = parse_nuclei_stdout((_FIXTURES / "argus_negative.jsonl").read_text(encoding="utf-8"))
    assert normalize_nuclei_findings(raw) == []


# ---------------------------------------------------------------------------
# Classification YAML
# ---------------------------------------------------------------------------


def test_classification_yaml_valid_with_provenance() -> None:
    data = _load_checklist()
    entries = data["entries"]
    assert isinstance(entries, list) and entries

    seen_ids: set[str] = set()
    for entry in entries:
        entry_id = entry["id"]
        assert entry_id not in seen_ids, f"duplicate entry id: {entry_id}"
        seen_ids.add(entry_id)

        assert entry["category"] in _VALID_CATEGORIES

        source = entry["source"]
        assert source["url"].startswith("https://github.com/Az0x7/")
        assert isinstance(source["commit"], str) and source["commit"].strip()
        assert str(source["adapted_at"]) == "2026-07-22"

        assert str(entry["target_artifact"]).strip()
        assert str(entry["normalized_check"]).strip()


def test_normalized_check_is_paraphrase_not_verbatim() -> None:
    """SI-6 heuristic: descriptions are prose, not pasted payload/wordlist blobs."""
    data = _load_checklist()
    for entry in data["entries"]:
        text = str(entry["normalized_check"]).strip()
        tokens = text.split()
        assert len(tokens) >= 6, f"{entry['id']}: normalized_check too short to be a paraphrase"
        longest = max((len(tok) for tok in tokens), default=0)
        assert longest <= _MAX_TOKEN_LEN, f"{entry['id']}: suspicious long token (pasted blob?)"
        lowered = text.lower()
        for marker in _VERBATIM_MARKERS:
            assert marker not in lowered, f"{entry['id']}: verbatim exploit marker leaked"


def test_category_d_families_do_not_collide_with_existing_payloads() -> None:
    existing = set(json.loads(_PAYLOAD_INDEX.read_text(encoding="utf-8"))["families"])
    data = _load_checklist()
    proposed = {
        str(entry["target_artifact"])
        for entry in data["entries"]
        if entry["category"] == "D"
    }
    assert proposed, "expected at least one category-D proposed payload family"
    collisions = proposed & existing
    assert not collisions, f"proposed family_id collides with existing: {sorted(collisions)}"


def test_category_e_targets_match_argus_templates() -> None:
    data = _load_checklist()
    e_targets = {
        str(entry["target_artifact"])
        for entry in data["entries"]
        if entry["category"] == "E"
    }
    assert e_targets == _ARGUS_TEMPLATE_IDS


# ---------------------------------------------------------------------------
# Nuclei argus-* templates (structural validity)
# ---------------------------------------------------------------------------


def test_argus_templates_present_and_structurally_valid() -> None:
    files = sorted(_TEMPLATES_DIR.glob("argus-*.yaml"))
    assert {f.stem for f in files} == set(_ARGUS_TEMPLATE_IDS)

    for path in files:
        tpl = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert tpl["id"] == path.stem
        assert tpl["id"].startswith("argus-")

        info = tpl["info"]
        assert info["author"] == "argus"
        assert info["severity"] in _VALID_SEVERITIES
        assert str(info["name"]).strip()
        assert str(info["description"]).strip()
        assert str(info["tags"]).strip()

        meta = info["metadata"]
        assert meta["source_url"].startswith("https://github.com/Az0x7/")
        assert str(meta["source_commit"]).strip()
        assert str(meta["adapted_at"]) == "2026-07-22"

        requests = tpl["http"]
        assert isinstance(requests, list) and requests
        req = requests[0]
        assert req["method"] == "GET"
        assert req["matchers-condition"] == "and"

        matchers = req["matchers"]
        assert len(matchers) >= 3, f"{path.stem}: expected strict multi-signal AND matchers"
        assert any(m.get("negative") for m in matchers), f"{path.stem}: missing negative matcher"
        non_status = [m for m in matchers if m.get("type") != "status"]
        assert len(non_status) >= 2, f"{path.stem}: status matcher alone must not confirm"


# ---------------------------------------------------------------------------
# nuclei_va_adapter G-6 fix
# ---------------------------------------------------------------------------


def test_default_argv_is_backwards_compatible() -> None:
    argv = build_nuclei_va_argv("https://example.com/x")
    assert argv[:3] == ["nuclei", "-u", "https://example.com/x"]
    assert "-t" not in argv


def test_argus_templates_argv_uses_builtin_dir() -> None:
    argv = build_nuclei_va_argv("https://example.com/x", use_argus_templates=True)
    assert "-t" in argv
    template_path = Path(argv[argv.index("-t") + 1])
    assert template_path == ARGUS_NUCLEI_TEMPLATES_DIR
    assert template_path.is_dir()
    assert ARGUS_NUCLEI_TEMPLATES_DIR == ARGUS_NUCLEI_TEMPLATES_DIR.resolve()


def test_arbitrary_templates_path_is_rejected() -> None:
    argv = build_nuclei_va_argv("https://example.com/x", templates_dir="/etc")
    assert "-t" not in argv
    assert "/etc" not in argv

    traversal = str(ARGUS_NUCLEI_TEMPLATES_DIR / ".." / ".." / "secrets")
    argv_traversal = build_nuclei_va_argv("https://example.com/x", templates_dir=traversal)
    assert "-t" not in argv_traversal


def test_resolve_argus_templates_dir_contract() -> None:
    assert resolve_argus_templates_dir() == ARGUS_NUCLEI_TEMPLATES_DIR
    assert resolve_argus_templates_dir(ARGUS_NUCLEI_TEMPLATES_DIR) == ARGUS_NUCLEI_TEMPLATES_DIR
    assert resolve_argus_templates_dir("../../etc/passwd") is None
    assert resolve_argus_templates_dir("/tmp/attacker-templates") is None
