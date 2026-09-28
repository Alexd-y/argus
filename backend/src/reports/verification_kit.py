"""Independent verification kit (Part II, Phase M — prompt §18).

Turns *provability* from a claim into a checkable property. Given the canonical v2
snapshot, produce a self-contained kit (returned as a ZIP byte string) that a third
party can use to re-check the report without trusting us:

* ``manifest.json`` — snapshot_hash, per-file sha256, schema/renderer versions and a
  verification instruction;
* ``evidence/`` — one redacted descriptor per evidence reference (never the raw
  secret material — only redacted derivatives, prompt EVD-05);
* ``repro/`` — one file per finding with the exact request/command **and its negative
  control**, plus the expected discriminator;
* ``checks.py`` — a non-exploiting script that reads ``repro/`` and reports
  matched/not-matched per item (it re-checks, it does not attack);
* ``README.md`` — how to verify hashes, read the evidence chain, and what the kit does
  NOT do.

The kit shares the report's ``snapshot_hash`` so it is provably the same version.
Pure module: no DB / LLM / network. Secrets are masked via ``report_text_sanitizer``.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from typing import Any

from src.reports.report_document import ReportDocumentV1, ReportFinding
from src.reports.report_text_sanitizer import sanitize_ai_report_text

_CHECKS_PY = '''#!/usr/bin/env python
"""Non-exploiting verification runner for the ARGUS verification kit.

Reads repro/*.json and prints matched / not-matched per item by comparing the
recorded discriminator against a re-run you perform manually. This script does not
send exploit payloads (it does NOT attack the target); it only structures the manual
re-check and refuses to run outside the declared scope.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent


def main() -> int:
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    scope = manifest.get("target", "")
    print(f"Verification kit for snapshot {manifest.get('snapshot_hash')}")
    print(f"Declared scope/target: {scope!r}")
    confirm = input("Type the exact target to confirm in-scope verification: ").strip()
    if confirm != scope:
        print("Target mismatch — refusing to run out of scope.")
        return 2
    repro_dir = ROOT / "repro"
    total = matched = 0
    for item in sorted(repro_dir.glob("*.json")):
        data = json.loads(item.read_text(encoding="utf-8"))
        total += 1
        print(f"\\n[{data['finding_id']}] {data['title']}")
        print(f"  request/command: {data.get('request') or data.get('command')}")
        print(f"  negative control: {data.get('negative_control')}")
        print(f"  expected discriminator: {data.get('discriminator')}")
        ans = input("  Did the re-run reproduce the discriminator? [y/N] ").strip().lower()
        if ans == "y":
            matched += 1
            print("  => MATCHED")
        else:
            print("  => NOT MATCHED")
    print(f"\\n{matched}/{total} items reproduced.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''

_README_MD = """# ARGUS Verification Kit

This kit lets you independently re-check the findings in the report **without
trusting the vendor**. It is generated from the same immutable snapshot as the
report and carries the same `snapshot_hash`.

## Verify integrity

1. Open `manifest.json`. It lists every file with its SHA-256 and the report
   `snapshot_hash`.
2. Recompute each file's SHA-256 and compare with the manifest.
3. The manifest hash chain ties every artifact to the snapshot. Note: these are
   SHA-256 digests relative to the manifest — **not** cryptographic signatures. No
   signing key was applied.

## Read the evidence chain

Each `evidence/*.json` is a **redacted** descriptor of a primary artifact
(request/response transcript, tool output, screenshot). Secrets are masked; only
redacted derivatives are included.

## Re-check findings

`repro/<finding>.json` contains the exact request/command, the **negative control**
(the same request without the payload) and the **discriminator** (what in the
response proves the defect rather than normal behaviour).

Run `python checks.py`. It confirms the target is in scope, walks each repro item and
records matched/not-matched. **It does not send exploit payloads** — you perform the
re-run and answer whether the discriminator reproduced.

## What this kit does NOT do

- It does not exploit the target or exfiltrate data.
- It does not include secrets or raw credentials.
- It does not replace a human retest; it structures independent verification.
"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _repro_for(finding: ReportFinding) -> dict[str, Any]:
    poc = finding.poc
    return {
        "finding_id": finding.finding_id,
        "title": sanitize_ai_report_text(finding.title or ""),
        "request": sanitize_ai_report_text((poc.http_request if poc else None) or ""),
        "command": sanitize_ai_report_text((poc.command if poc else None) or ""),
        "negative_control": sanitize_ai_report_text((poc.negative_control if poc else None) or ""),
        "discriminator": sanitize_ai_report_text((poc.discriminator if poc else None) or ""),
        "expected_result": "discriminator reproduced under payload, absent under control",
        "evidence_ids": list(finding.evidence_ids),
    }


def _evidence_descriptor(ref: Any) -> dict[str, Any]:
    return {
        "evidence_id": ref.evidence_id,
        "kind": ref.kind,
        "object_key": ref.object_key,
        "description": sanitize_ai_report_text(ref.description or ""),
        "note": "redacted descriptor; raw material withheld (EVD-05)",
    }


def build_verification_kit(doc: ReportDocumentV1) -> tuple[bytes, dict[str, Any]]:
    """Return ``(zip_bytes, manifest)`` for the verification kit of ``doc``.

    The manifest is also embedded in the zip as ``manifest.json``; it is returned
    separately so the caller can persist it alongside the release.
    """
    files: dict[str, bytes] = {}

    for f in doc.findings:
        payload = json.dumps(_repro_for(f), ensure_ascii=False, indent=2, sort_keys=True)
        files[f"repro/{f.finding_id}.json"] = payload.encode("utf-8")

    for ref in doc.evidence_references:
        payload = json.dumps(
            _evidence_descriptor(ref), ensure_ascii=False, indent=2, sort_keys=True
        )
        files[f"evidence/{ref.evidence_id}.json"] = payload.encode("utf-8")

    files["checks.py"] = _CHECKS_PY.encode("utf-8")
    files["README.md"] = _README_MD.encode("utf-8")

    # Manifest last: hash every other file, tie to the snapshot.
    manifest: dict[str, Any] = {
        "snapshot_hash": doc.snapshot_hash,
        "schema_version": doc.schema_version,
        "target": doc.target,
        "scan_id": doc.scan_id,
        "generated_at": doc.generated_at,
        "integrity_note": (
            "SHA-256 digests relative to this manifest; not a cryptographic signature."
        ),
        "verification_instruction": "Recompute each file's sha256 and compare; run checks.py.",
        "files": {name: _sha256(content) for name, content in sorted(files.items())},
    }
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode(
        "utf-8"
    )
    files["manifest.json"] = manifest_bytes

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            zf.writestr(name, files[name])
    return buf.getvalue(), manifest


__all__ = ["build_verification_kit"]
