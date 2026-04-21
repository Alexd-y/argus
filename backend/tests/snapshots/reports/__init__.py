"""Golden snapshots for ARG-024 ReportService Midgard tier outputs.

Files in this directory are *byte-equality* fixtures — any change to the
generators that alters output bytes will cause snapshot tests in
``backend/tests/integration/reports/test_midgard_tier_all_formats.py``
to fail. Refresh by running the suite with ``ARGUS_SNAPSHOT_REFRESH=1``.

Layout:
    midgard_canonical.json   — JSON tier-projected report
    midgard_canonical.csv    — CSV tier-projected report
    midgard_canonical.sarif  — SARIF v2.1.0 tier-projected report
    midgard_canonical.xml    — JUnit XML tier-projected report
"""
