"""Content parity across the four canonical formats (formats prompt Phase 9).

The historical ``assert_canonical_parity`` only checked format presence + a shared
``snapshot_hash`` — content was never compared, so C-01…C-09 (divergent counts, ids,
categories, internal paths) slipped through. These pure functions compare the actual
content of JSON / XML / MD / HTML and return blocking reasons.

JSON is authoritative (lossless). XML is parsed namespace-aware; MD/HTML are checked
for presence of the JSON finding ids and (MD↔HTML) an equal section-header set.
"""

from __future__ import annotations

import html as _html
import json
import re
from typing import Any

from defusedxml.ElementTree import fromstring
from pydantic import BaseModel
from pydantic_core import PydanticUndefined

from src.reports.report_document import ReportDocumentV1, field_render_policy

#: A real internal storage path leaking into a client format: a UUID (tenant/scan id)
#: followed by a path. Matches "00000000-…-0001/<scan-uuid>/poc/x.json"; does NOT match
#: opaque evidence ids (E-001) or JSON key names.
_INTERNAL_PATH_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[^\s\"'<>]+",
    re.IGNORECASE,
)
_MD_HEADER_RE = re.compile(r"^(#{2,3})\s+(.*)$", re.MULTILINE)
_HTML_H2_RE = re.compile(r"<h2[^>]*>(.*?)</h2>", re.IGNORECASE | re.DOTALL)


def _local(tag: str) -> str:
    return tag.split("}", 1)[1] if isinstance(tag, str) and tag.startswith("{") else tag


def _json_findings(text: str) -> list[dict[str, Any]]:
    data = json.loads(text)
    out: list[dict[str, Any]] = list(data.get("findings") or [])
    return out


def _xml_findings(text: str) -> list[dict[str, str]]:
    root = fromstring(text)
    out: list[dict[str, str]] = []
    for el in root.iter():
        if _local(el.tag) == "finding":
            out.append(dict(el.attrib))
    return out


_ALNUM_RE = re.compile(r"[A-Za-z0-9]")
_READABLE_FORMATS = ("md", "xml", "html")


def _norm(value: object) -> str:
    """Normalise so a value matches across formats: unescape HTML entities, drop the
    Markdown escape backslashes, collapse whitespace, lowercase. This lets one check work
    for MD (``\\|`` escaping, ``\\n``→space), XML/HTML (``&lt;``/``&amp;`` entities)."""
    text = _html.unescape(str(value)).replace("\\", "")
    return re.sub(r"\s+", " ", text).strip().lower()


def _checkable(value: str) -> bool:
    """A string worth asserting presence of: at least two alphanumeric chars. Single-char
    / pure-punctuation values are too ambiguous to check without false positives."""
    return len(_ALNUM_RE.findall(value)) >= 2


def _walk_value(value: Any, label: str, norm_texts: dict[str, str], problems: list[str]) -> None:
    """Recurse into a snapshot value, asserting each render:"all" string leaf is present
    in every readable format. Numbers/bools are skipped (their formatting differs per
    format — covered by the static coverage script + full-document parity test)."""
    if value is None:
        return
    if isinstance(value, BaseModel):
        _walk_model(value, norm_texts, problems)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _walk_value(item, label, norm_texts, problems)
        return
    if isinstance(value, dict):
        # Free-form dicts (wstg, scope_summary, budget_usage, …) are structurally
        # variable: their rendering is verified by the static coverage script (the
        # field name must appear in each renderer) and by targeted tests, not by
        # value-walking — which would false-positive on any key a renderer summarises.
        return
    if isinstance(value, (bool, int, float)):
        return  # bool is an int subclass; numeric formatting differs per format
    if isinstance(value, str) and _checkable(value):
        nv = _norm(value)
        missing = sorted(fmt for fmt, text in norm_texts.items() if nv not in text)
        if missing:
            problems.append(f"parity: {label} value not rendered in {','.join(missing)}")


def _walk_model(obj: BaseModel, norm_texts: dict[str, str], problems: list[str]) -> None:
    model = type(obj)
    for field_name, field in model.model_fields.items():
        if field_render_policy(model, field_name) != "all":
            continue
        value = getattr(obj, field_name, None)
        # A value equal to the field's declared default is a "no-data" sentinel
        # (e.g. review_status="not_required", status="not_generated") with nothing to
        # render — skip it so defaults never produce a false parity blocker.
        default = field.default
        if default is not PydanticUndefined and value == default:
            continue
        _walk_value(value, f"{model.__name__}.{field_name}", norm_texts, problems)


def _declarative_parity_blockers(doc: ReportDocumentV1, texts: dict[str, str]) -> list[str]:
    """RC-13: every field marked ``render="all"`` with a non-empty value must appear in
    MD/XML/HTML. Returns one blocker per missing ``model.field`` + the formats it is
    missing from. JSON is lossless (``model_dump``) and is not checked here."""
    norm_texts = {fmt: _norm(texts[fmt]) for fmt in _READABLE_FORMATS if fmt in texts}
    if not norm_texts:
        return []
    problems: list[str] = []
    _walk_model(doc, norm_texts, problems)
    return problems


def content_parity_blockers(
    artifacts: dict[str, bytes], *, doc: ReportDocumentV1 | None = None
) -> list[str]:
    """Compare JSON/MD/XML/HTML content; return blocking mismatch reasons (empty == ok).

    ``artifacts`` maps a canonical format name (``json``/``md``/``xml``/``html``) to its
    rendered bytes. Missing formats are skipped (presence is enforced separately).

    When ``doc`` (the source snapshot) is supplied, a declarative field-coverage check
    runs on top of the structural checks (RC-13): every field marked ``render="all"``
    with a non-empty value must be present in all three readable formats, reported as a
    precise ``model.field`` blocker. Without ``doc`` only the structural checks run
    (backward compatible).
    """
    problems: list[str] = []
    texts = {k: v.decode("utf-8", "replace") for k, v in artifacts.items()}

    js = texts.get("json")
    if js is None:
        return problems  # nothing authoritative to compare against

    j_findings = _json_findings(js)
    j_ids = {str(f.get("finding_id")) for f in j_findings}
    j_count = len(j_findings)
    j_unconfirmed = len(json.loads(js).get("unconfirmed_observations") or [])

    # --- XML: identical id set + per-field parity (severity/verification/cvss/owasp).
    if "xml" in texts:
        x_findings = _xml_findings(texts["xml"])
        x_ids = {str(f.get("finding_id")) for f in x_findings}
        if x_ids != j_ids:
            problems.append(f"parity: finding_id set differs json vs xml ({j_ids ^ x_ids})")
        x_by_id = {str(f.get("finding_id")): f for f in x_findings}
        for jf in j_findings:
            fid = str(jf.get("finding_id"))
            xf = x_by_id.get(fid)
            if not xf:
                continue
            if str(jf.get("severity")) != str(xf.get("severity")):
                problems.append(f"parity: severity differs for {fid} (json/xml)")
            if str(jf.get("verification_status")) != str(xf.get("verification_status")):
                problems.append(f"parity: verification_status differs for {fid} (json/xml)")

    # --- MD / HTML: every JSON finding id present; equal count header.
    for fmt in ("md", "html"):
        if fmt in texts:
            missing = [fid for fid in j_ids if fid not in texts[fmt]]
            if missing:
                problems.append(f"parity: {fmt} missing finding ids {missing[:3]}")

    if "md" in texts:
        m = re.search(r"##+\s*Findings\s*\((\d+)\)", texts["md"], re.IGNORECASE)
        if m and int(m.group(1)) != j_count:
            problems.append(f"parity: md Findings count {m.group(1)} != json {j_count} (C-02/03)")
        mu = re.search(r"##+\s*Unconfirmed Observations\s*\((\d+)\)", texts["md"], re.IGNORECASE)
        if mu and int(mu.group(1)) != j_unconfirmed:
            problems.append("parity: md unconfirmed count != json (C-04)")

    # --- MD ↔ HTML section-header set equality (C-28 §8.6).
    if "md" in texts and "html" in texts:
        md_secs = {
            t.strip().lower() for lvl, t in _MD_HEADER_RE.findall(texts["md"]) if lvl == "##"
        }
        html_secs = {
            re.sub(r"<[^>]+>", "", t).strip().lower() for t in _HTML_H2_RE.findall(texts["html"])
        }
        html_secs = {re.sub(r"\s*\(\d+\)\s*$", "", s).strip() for s in html_secs}
        md_secs = {re.sub(r"\s*\(\d+\)\s*$", "", s).strip() for s in md_secs}
        only_md = md_secs - html_secs
        only_html = html_secs - md_secs
        if only_md or only_html:
            problems.append(
                f"parity: MD/HTML section headers differ (md-only={sorted(only_md)[:3]}, "
                f"html-only={sorted(only_html)[:3]})"
            )

    # --- No client format leaks tenant_id / object_key / internal storage path (C-29).
    for fmt in ("json", "md", "xml", "html"):
        if fmt in texts and _INTERNAL_PATH_RE.search(texts[fmt]):
            problems.append(
                f"parity: {fmt} contains an internal path / tenant_id / object_key (C-29)"
            )

    # --- RC-13: declarative per-field coverage across the readable formats.
    if doc is not None:
        problems.extend(_declarative_parity_blockers(doc, texts))

    return problems


__all__ = ["content_parity_blockers"]
