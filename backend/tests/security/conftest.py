"""Conftest for the ``backend/tests/security`` subtree.

The security suite verifies invariants that protect against real-world
abuse vectors (secret leak via logs, cardinality blow-up, etc.). Most
modules are pure-Python and do not need the full FastAPI app.

Historical note (T02 — latent cyclic policy import refactor)
-----------------------------------------------------------
This file used to ship a pre-warm hack:

    import src.pipeline.contracts.phase_io  # warm cycle

…which forced ``src.payloads.builder`` to drive the ``src.policy``
package init from a state where ``src.policy.approval`` was not yet
partially loaded. It worked around the latent cycle:

    src.policy.__init__
      -> src.policy.approval
        -> src.sandbox.signing
          -> ... -> src.payloads.builder
            -> src.policy.preflight
              -> src.policy.approval (PARTIAL)

T02 removed the cycle structurally by splitting ``src.policy.approval``
into:

* :mod:`src.policy.approval_dto` — pure pydantic DTOs (no signing /
  audit / sandbox dependencies).
* :mod:`src.policy.approval_service` — ``ApprovalService`` with the
  heavyweight crypto + audit deps.

``src.policy.preflight`` now imports the DTOs from ``approval_dto`` and
keeps ``ApprovalService`` behind a ``TYPE_CHECKING`` guard, so the
chain ``preflight -> approval_service -> sandbox.signing -> ... ->
preflight`` can no longer form. The pre-warm import here is therefore
no longer required and has been removed.

Hard requirements (do not relax):

* Set environment defaults BEFORE any ``src.*`` import.
* Keep this file side-effect free except for the documented
  ``override_auth`` neutraliser.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest


os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault(
    "JWT_SECRET",
    "test-secret-not-for-prod-but-required-by-settings",
)
os.environ.setdefault("ARGUS_TEST_MODE", "1")


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """Security tests in this tree never touch FastAPI auth."""
    yield
