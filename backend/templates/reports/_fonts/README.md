# Bundled fonts — `backend/templates/reports/_fonts/`

PDF report templates (Midgard / Asgard / Valhalla) reference these
WOFF2 font files via `@font-face` declarations in their respective
`pdf_styles.css`. WeasyPrint resolves the URLs relative to the HTML's
`base_url`, which `pdf_backend.WeasyPrintBackend.render` sets to the
template directory.

## Inventory

| File | Family | Weight | Style | License | Source |
|------|--------|--------|-------|---------|--------|
| `Inter-Regular.woff2`  | Inter      | 400 | normal | SIL OFL 1.1 | <https://rsms.me/inter/> |
| `Inter-Bold.woff2`     | Inter      | 700 | normal | SIL OFL 1.1 | <https://rsms.me/inter/> |
| `Inter-Italic.woff2`   | Inter      | 400 | italic | SIL OFL 1.1 | <https://rsms.me/inter/> |
| `DejaVuSans.woff2`     | DejaVu Sans | 400 | normal | Bitstream Vera + DejaVu changes (public-domain-ish, see <https://dejavu-fonts.github.io/License.html>) | jsDelivr `dejavu-fonts-ttf@2.37.3`, converted to WOFF2 with `fontTools` |

Total payload: ~600 KB. We deliberately bundle WOFF2 (not TTF) to keep
the repo footprint small while preserving wide Unicode coverage —
DejaVu Sans is the system fall-back when Inter cannot render a glyph
(typical for Cyrillic, Greek, mathematical symbols and some emoji).

## Replacing the bundled set

If you need to ship a customer-facing brand variant:

1. Drop the new WOFF2 files into this directory (preserving the file
   names above so the CSS does not need patching), **or**
2. Edit the `@font-face` declarations in
   `backend/templates/reports/{midgard,asgard,valhalla}/pdf_styles.css`
   to point at the new file names — keep the relative path
   `../_fonts/<file>` so PDF rendering stays portable.

After swapping fonts re-run `pytest backend/tests/integration/reports/test_pdf_branded.py`
to refresh snapshot baselines.

## Licensing notes

* **Inter** is Copyright © 2016–present The Inter Project Authors,
  released under the SIL Open Font License v1.1. The full licence text
  ships with every Inter release at
  <https://github.com/rsms/inter/blob/master/LICENSE.txt>.
* **DejaVu Sans** is derived from Bitstream Vera Fonts and released
  under the same permissive licence. See
  <https://dejavu-fonts.github.io/License.html>.

ARGUS does not modify the upstream font binaries. If you require an
audit trail for compliance (e.g. enterprise legal review), recompute
the SHA-256 of the bundled files with:

```powershell
Get-ChildItem backend\templates\reports\_fonts -Filter *.woff2 |
  ForEach-Object { Get-FileHash $_.FullName -Algorithm SHA256 }
```
