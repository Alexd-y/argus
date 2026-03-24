"""RPT-009 — shared skip logic for WeasyPrint PDF integration tests."""

import os


def weasyprint_pdf_skip() -> tuple[bool, str]:
    """Skip when CI opts out or native libs for WeasyPrint are missing."""
    if os.environ.get("ARGUS_SKIP_WEASYPRINT_PDF", "").lower() in ("1", "true", "yes"):
        return True, "ARGUS_SKIP_WEASYPRINT_PDF=1 (CI without Pango+Cairo, RPT-009)"
    try:
        import weasyprint  # noqa: F401
    except (OSError, ImportError):
        return True, "WeasyPrint unavailable (missing system libraries for RPT-009)"
    return False, ""


WSP_SKIP, WSP_REASON = weasyprint_pdf_skip()
