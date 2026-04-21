"""OAST plane public surface (Backlog/dev1_md §11 / §12).

This package is the **only** place from which validators, the orchestrator,
and the policy preflight should import OAST plumbing. Re-exporting through
the package keeps the underlying module layout free to evolve without
churn at every import site.

Module layout:

* :mod:`src.oast.provisioner` — :class:`OASTToken`, the
  :class:`OASTProvisioner` protocol, and concrete implementations.
* :mod:`src.oast.correlator` — :class:`OASTInteraction` and the async
  correlator that bridges listeners to the verifier loop.
* :mod:`src.oast.canary` — :class:`Canary`, the generator, and the
  verifier used as a fallback when OAST is unavailable.
* :mod:`src.oast.listener_protocol` — :class:`OASTListenerProtocol` plus
  the deterministic in-process :class:`FakeOASTListener` used in tests.
* :mod:`src.oast.integration` — :class:`OASTPlane` composition + the
  :class:`EvidencePreparation` bundle produced for every validator run.
* :mod:`src.oast.redis_stream` — :class:`OASTRedisStreamBridge` (optional
  Redis Streams durability for the correlator).
"""

from __future__ import annotations

from src.oast.canary import (
    Canary,
    CanaryError,
    CanaryFailureReason,
    CanaryGenerationError,
    CanaryGenerator,
    CanaryKind,
    CanaryVerificationInputError,
    CanaryVerificationResult,
    CanaryVerifier,
)
from src.oast.correlator import (
    InteractionKind,
    OASTCorrelator,
    OASTInteraction,
)
from src.oast.integration import (
    EvidencePreparation,
    EvidenceStrategy,
    OASTIntegrationError,
    OASTPlane,
    OASTPlaneConfig,
    OASTRequiredButDisabledError,
)
from src.oast.listener_protocol import (
    BurpCollaboratorClientStub,
    FakeOASTListener,
    OASTListenerProtocol,
)
from src.oast.provisioner import (
    DisabledOASTProvisioner,
    InternalOASTProvisioner,
    OASTBackendKind,
    OASTError,
    OASTProvisioner,
    OASTProvisioningError,
    OASTToken,
    OASTUnavailableError,
)
from src.oast.redis_stream import OASTRedisStreamBridge


__all__ = [
    # canary
    "Canary",
    "CanaryError",
    "CanaryFailureReason",
    "CanaryGenerationError",
    "CanaryGenerator",
    "CanaryKind",
    "CanaryVerificationInputError",
    "CanaryVerificationResult",
    "CanaryVerifier",
    # correlator
    "InteractionKind",
    "OASTCorrelator",
    "OASTInteraction",
    # integration
    "EvidencePreparation",
    "EvidenceStrategy",
    "OASTIntegrationError",
    "OASTPlane",
    "OASTPlaneConfig",
    "OASTRequiredButDisabledError",
    # listener
    "BurpCollaboratorClientStub",
    "FakeOASTListener",
    "OASTListenerProtocol",
    # provisioner
    "DisabledOASTProvisioner",
    "InternalOASTProvisioner",
    "OASTBackendKind",
    "OASTError",
    "OASTProvisioner",
    "OASTProvisioningError",
    "OASTToken",
    "OASTUnavailableError",
    # redis streams
    "OASTRedisStreamBridge",
]
