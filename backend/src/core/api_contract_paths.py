"""Path helpers for frontend API contract (scans / reports)."""


def is_frontend_contract_path(path: str) -> bool:
    """True for /api/v1/scans and /api/v1/reports (including subpaths), excluding path-prefix false positives."""
    if path.startswith("/api/v1/scans"):
        return path == "/api/v1/scans" or path.startswith("/api/v1/scans/")
    if path.startswith("/api/v1/reports"):
        return path == "/api/v1/reports" or path.startswith("/api/v1/reports/")
    return False
