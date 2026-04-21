"""Integration test root for ARGUS backend.

Tests under ``backend/tests/integration/`` exercise composed subsystems against
real on-disk artefacts (signed YAML catalog, OpenAPI snapshots, etc.) but never
spin up the full FastAPI app, a DB engine, or a network connection. The
sibling ``backend/tests/unit/`` tree handles pure-Python unit tests; this tree
is for slower fixtures that still avoid out-of-process dependencies.
"""
