"""ARGUS Backend MCP server (Backlog/dev1_md §13).

Exposes the ARGUS pentest pipeline (scans, findings, approvals, reports,
tool catalog, policy/scope evaluation) to MCP-compatible LLM clients.
The runtime entry point is :mod:`src.mcp.server`.

Side effect — circular-import warm-up
-------------------------------------
The legacy ``src.policy`` package eagerly re-exports every submodule from
its ``__init__.py``.  Combined with the deep
``policy → sandbox → pipeline.contracts → orchestrator → oast → payloads
→ policy.preflight`` dependency chain, importing ``src.policy.*`` as the
first policy-plane access from a fresh interpreter raises
``ImportError: cannot import name 'ApprovalAction' from partially
initialized module 'src.policy.approval'``.

The unit-test suite avoids this by entering the chain via
``src.pipeline.contracts.phase_io``, which forces ``src.payloads.builder``
to drive the ``src.policy`` package init from a state where
``src.policy.approval`` is not yet partially loaded.  We replicate that
ordering here, exactly once, so any consumer of ``src.mcp.*`` can safely
``from src.policy.audit import AuditLogger`` (etc.) without worrying
about Python's package-init semantics.

This is a *targeted* workaround, not a structural fix — the underlying
cycle in ``src.policy`` / ``src.payloads`` should still be resolved by
moving the ``PreflightDeniedError`` import in
``src.payloads.builder`` to a deferred / function-local import, but that
refactor is out of scope for ARG-023.
"""

from __future__ import annotations

import src.pipeline.contracts.phase_io  # noqa: F401  (warm-up; see module docstring)
