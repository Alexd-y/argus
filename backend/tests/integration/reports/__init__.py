"""Integration tests for ARG-024 ReportService Tier 1 (Midgard) flows.

These tests exercise the full ``ReportService.render_bundle`` pipeline
against a canonical in-memory ``ReportData`` covering every machine-readable
format (JSON / CSV / SARIF / JUnit) plus snapshot byte-equality assertions
(see ``tests/snapshots/reports/``).

No DB, no FastAPI app, no network — see ``backend/tests/integration/conftest.py``.
"""
