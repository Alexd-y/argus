"""ARGUS pipeline package — typed contracts that flow between phases of the 6-phase
state machine and supporting orchestration units (ToolJob/ValidationJob/ExploitJob).

This package contains *only* contract types (Pydantic v2 models, enums, value objects).
Phase execution, dispatching, and side effects live in :mod:`src.orchestrator` and
:mod:`src.orchestration` (legacy). Keeping contracts in their own package allows the
control-plane (FastAPI/Celery) and the execution-plane (sandbox runners) to share a
single typed protocol without dragging in transport or storage dependencies.
"""
