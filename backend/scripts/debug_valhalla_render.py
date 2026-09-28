#!/usr/bin/env python
"""Phase A diagnostic — reproduce the Valhalla report render exactly like prod.

Collects the export payload through the *same* path production uses
(``build_report_export_payload`` → ``generate_*``) and dumps every artifact plus a
structural summary to ``/tmp/valhalla-debug/`` (override with ``--out``). It changes
nothing in the DB or storage — read-only reproduction for the empty-PDF defect
(diagnosis D1–D5 in ``docs/diagnostics/valhalla-empty-pdf-2026-09-28.md``).

Usage:
    python scripts/debug_valhalla_render.py --report-id <uuid> [--scan-id <uuid>] \
        [--tenant-id <uuid>] [--tier valhalla] [--out /tmp/valhalla-debug]

The summary (``summary.json``) reports:
    * HTML length, number of ``<section`` tags, every ``id="…"`` anchor;
    * PDF page count (best-effort via pypdf, if installed);
    * ``len(findings)``;
    * ``ai_sections`` map (key → text length);
    * presence/non-empty fields of ``valhalla_context``;
    * ``report_quality.coverage_label`` / ``report_mode_label``;
    * which section anchors present in HTML are missing from the PDF text.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
from pathlib import Path
from typing import Any

from src.db.session import async_session_factory, set_session_tenant
from src.reports.generators import (
    generate_html,
    generate_json,
    generate_markdown,
    generate_pdf,
    generate_xml,
)
from src.services.reporting import build_report_export_payload

_ID_RE = re.compile(r'id="([^"]+)"')
_SECTION_RE = re.compile(r"<section\b", re.IGNORECASE)
_KEY_ANCHORS = (
    "findings",
    "results-overview",
    "evidence-inventory",
    "exploitation",
    "remediation-priority",
)


def _pdf_page_count(pdf_bytes: bytes) -> int | None:
    try:
        from pypdf import PdfReader
    except Exception:  # noqa: BLE001 — optional dependency
        try:
            from PyPDF2 import PdfReader  # type: ignore
        except Exception:  # noqa: BLE001
            return None
    import io

    try:
        return len(PdfReader(io.BytesIO(pdf_bytes)).pages)
    except Exception:  # noqa: BLE001
        return None


def _pdf_text(pdf_bytes: bytes) -> str:
    try:
        from pypdf import PdfReader
    except Exception:  # noqa: BLE001
        try:
            from PyPDF2 import PdfReader  # type: ignore
        except Exception:  # noqa: BLE001
            return ""
    import io

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception:  # noqa: BLE001
        return ""


def _context_key_sizes(jctx: dict[str, Any]) -> dict[str, Any]:
    sizes: dict[str, Any] = {}
    for key, value in jctx.items():
        try:
            if isinstance(value, (list, tuple, set, dict, str)):
                sizes[key] = len(value)
            else:
                sizes[key] = type(value).__name__
        except Exception:  # noqa: BLE001
            sizes[key] = "unknown"
    return sizes


async def _run(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    async with async_session_factory() as session:
        if args.tenant_id:
            await set_session_tenant(session, args.tenant_id)
        report_data, jctx = await build_report_export_payload(
            session,
            tenant_id=args.tenant_id,
            report_id=args.report_id,
            scan_id=args.scan_id,
            tier=args.tier,
            include_minio=True,
            sync_ai=True,
        )

    html = generate_html(report_data, jinja_context=jctx, tier=args.tier).decode("utf-8", "replace")
    pdf = generate_pdf(report_data, jinja_context=jctx, tier=args.tier)
    md = generate_markdown(report_data, jinja_context=jctx, tier=args.tier).decode(
        "utf-8", "replace"
    )
    json_bytes = generate_json(report_data, jinja_context=jctx)
    xml_bytes = generate_xml(report_data, jinja_context=jctx)

    (out / "report.html").write_text(html, encoding="utf-8")
    (out / "report.pdf").write_bytes(pdf)
    (out / "report.md").write_text(md, encoding="utf-8")
    (out / "report.json").write_bytes(json_bytes)
    (out / "report.xml").write_bytes(xml_bytes)
    (out / "context.keys.json").write_text(
        json.dumps(_context_key_sizes(jctx), ensure_ascii=False, indent=2), encoding="utf-8"
    )

    html_ids = _ID_RE.findall(html)
    pdf_text = _pdf_text(pdf)
    ai_sections = jctx.get("ai_sections") or {}
    vctx = jctx.get("valhalla_context") or {}
    rq = jctx.get("report_quality") or {}

    summary: dict[str, Any] = {
        "report_id": args.report_id,
        "html_length": len(html),
        "section_tags": len(_SECTION_RE.findall(html)),
        "html_ids": html_ids,
        "findings_n": len(getattr(report_data, "findings", []) or []),
        "ai_sections": (
            {k: len(str(v)) for k, v in ai_sections.items()}
            if isinstance(ai_sections, dict)
            else "not_a_dict"
        ),
        "valhalla_context_nonempty_fields": (
            [k for k, v in vctx.items() if v] if isinstance(vctx, dict) else "not_a_dict"
        ),
        "coverage_label": rq.get("coverage_label") if isinstance(rq, dict) else None,
        "report_mode_label": rq.get("report_mode_label") if isinstance(rq, dict) else None,
        "pdf_page_count": _pdf_page_count(pdf),
        "pdf_text_length": len(pdf_text),
        "key_anchors_in_html": [a for a in _KEY_ANCHORS if a in html_ids],
        "key_anchors_missing_from_pdf_text": [
            a for a in _KEY_ANCHORS if a in html_ids and a not in pdf_text
        ],
    }
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-id", required=True)
    parser.add_argument("--scan-id", default=None)
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--tier", default="valhalla")
    parser.add_argument("--out", default="/tmp/valhalla-debug")
    args = parser.parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
