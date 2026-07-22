"""Web Security Workbench — proxy data-plane core (WB-P2a).

Offline-testable, pure building blocks for the intercepting proxy:

* :mod:`.transport` — HTTP message normalization with byte-exact raw
  preservation (ADR-WB-3) and bounded body handling (no unbounded in-memory
  bodies — every body is digested + size-capped before retention).
* :mod:`.ca_manager` — per-tenant certificate authority: generate a CA and
  issue short-lived leaf certificates for MITM. Private-key material is never
  logged and is exported only through an explicit, guarded accessor.
* :mod:`.intercept_rules` — declarative interception rule engine (pure).
* :mod:`.forward_gate` — mandatory scope gate for every forwarded request
  (SI-WB-1), with a pluggable full-preflight hook for the live daemon.

The live mitmproxy execution-plane (``argus-web-proxy`` container), the
persistence models / migration and the traffic repository are wired in the
follow-up slices WB-P2a-2 / WB-P2b (see the plan backlog).
"""

from src.web_workbench.proxy.ca_lifecycle import (
    FernetSecretSealer,
    SealedCa,
    SecretSealer,
    build_sealer_from_settings,
    issue_ca,
    load_ca,
)
from src.web_workbench.proxy.ca_manager import (
    CaError,
    CertificateAuthority,
    IssuedLeaf,
)
from src.web_workbench.proxy.forward_gate import (
    ForwardDecision,
    ForwardGate,
    ForwardOutcome,
)
from src.web_workbench.proxy.intercept_rules import (
    InterceptAction,
    InterceptRule,
    InterceptRuleSet,
)
from src.web_workbench.proxy.transport import (
    BodyPlan,
    HttpMessageError,
    NormalizedRequest,
    NormalizedResponse,
    plan_body,
)

__all__ = [
    "BodyPlan",
    "CaError",
    "CertificateAuthority",
    "FernetSecretSealer",
    "ForwardDecision",
    "ForwardGate",
    "ForwardOutcome",
    "HttpMessageError",
    "InterceptAction",
    "InterceptRule",
    "InterceptRuleSet",
    "IssuedLeaf",
    "NormalizedRequest",
    "NormalizedResponse",
    "SealedCa",
    "SecretSealer",
    "build_sealer_from_settings",
    "issue_ca",
    "load_ca",
    "plan_body",
]
