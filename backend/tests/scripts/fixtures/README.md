# verapdf MRR XML fixtures (C7-T02 follow-up, DEBUG-2)

Real verapdf-cli Machine-Readable Report (MRR) XML samples used by
`backend/tests/scripts/test_verapdf_assert.py` to integration-test the
schema parser in `backend/scripts/_verapdf_assert.py`.

## Provenance

| File | Source |
| ---- | ------ |
| `verapdf_real_noncompliant.xml` | **Live capture**: `docker run --rm -v ./:/data verapdf/cli --format xml --flavour 2u /data/basic.pdf` against a `reportlab`-generated PDF, verapdf-cli **1.28.1**. |
| `verapdf_real_compliant.xml` | **Hand-crafted** against the live noncompliant capture above: same envelope, `isCompliant="true"`, no failed `<rule>` elements (verapdf only lists failed rules in the default `<details>` block — passed rules are aggregated in count attributes only). Counts updated to all-passed. |
| `verapdf_real_warning.xml` | **Hand-crafted** against the live envelope: one `<rule status="warning">` representing a policy-validation soft check. Standard PDF/A profiles in 1.28.x rarely emit `warning`, but our parser must handle it because policy / WCAG profiles do. |
| `verapdf_real_parse_failure.xml` | **Live capture** of a malformed PDF (truncated minimal PDF) — verapdf emits `<taskException>` instead of `<validationReport>`. |

The CI workflow pins `verapdf-cli 1.24.1`, but the MRR schema has been
stable across the 1.24.x → 1.30.x range; the 1.28.1 captures here are
forward and backward compatible with the pinned CI version. See the
schema reference linked from `backend/scripts/_verapdf_assert.py`'s
module docstring for the full element layout.

## How to regenerate the live captures

```powershell
# Generate a basic PDF (requires reportlab).
python -c "from reportlab.pdfgen import canvas; c=canvas.Canvas('basic.pdf'); c.drawString(100,750,'Hi'); c.save()"

# Live verapdf run (Docker, official image).
docker run --rm -v "${PWD}:/data" verapdf/cli `
  --format xml --flavour 2u /data/basic.pdf `
  > backend/tests/scripts/fixtures/verapdf_real_noncompliant.xml
```

The compliant + warning fixtures are kept hand-crafted because rendering
a true PDF/A-2u-compliant sample requires the full `pdflatex + pdfx +
colorprofiles` toolchain (TeX Live latex-extra), which is heavier than a
unit-test fixture should depend on. The hand-crafted XMLs are a faithful
mirror of the real schema — see the live `noncompliant` capture for the
authoritative envelope shape.

## Trust boundary

These fixtures live inside the test suite and are loaded with stdlib
`xml.etree.ElementTree`. They are NOT user-supplied input. If the
parser is later reused outside the trusted CI runner context, switch to
`defusedxml.ElementTree` to mitigate XML-bomb / external-entity attacks.
