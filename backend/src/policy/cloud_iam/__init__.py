"""Cloud-IAM ownership verifiers (ARG-043).

Public API surface — see :mod:`src.policy.ownership` for the dispatch
layer that wires these verifiers via constructor-injected mapping.

Each verifier exposes:

* ``cloud_provider`` — a static tag (``"aws"`` / ``"gcp"`` / ``"azure"``).
* ``verify(challenge: OwnershipChallenge) -> OwnershipProof`` — the
  coroutine the dispatch layer awaits.

A pair of "adapter" classes wrap the real cloud SDKs so production
code injects ``BotoStsAdapter(...)`` / ``GoogleAuthIamAdapter(...)`` /
``AzureManagedIdentityAdapter(...)`` while tests inject pure
:class:`Protocol` stubs without importing the SDKs at all.
"""

from __future__ import annotations

from src.policy.cloud_iam._common import (
    CLOUD_METHOD_METADATA,
    CLOUD_PROOF_DEFAULT_TTL,
    CloudMethodMetadata,
    CloudPrincipalDescriptor,
    constant_time_str_equal,
    descriptor_from_challenge,
    emit_cloud_attempt,
    hash_identifier,
    make_proof,
    metadata_for,
    redact_token,
    run_with_timeout,
    utcnow,
)
from src.policy.cloud_iam.aws import (
    AssumeRoleResponse,
    AwsStsVerifier,
    BotoStsAdapter,
    ParsedRoleArn,
    StsClientProtocol,
    parse_role_arn,
)
from src.policy.cloud_iam.azure import (
    AccessTokenResult,
    AzureCredentialProtocol,
    AzureManagedIdentityAdapter,
    AzureManagedIdentityVerifier,
)
from src.policy.cloud_iam.gcp import (
    GcpIamProtocol,
    GcpServiceAccountJwtVerifier,
    GoogleAuthIamAdapter,
    JwtClaims,
)

__all__ = [
    "AccessTokenResult",
    "AssumeRoleResponse",
    "AwsStsVerifier",
    "AzureCredentialProtocol",
    "AzureManagedIdentityAdapter",
    "AzureManagedIdentityVerifier",
    "BotoStsAdapter",
    "CLOUD_METHOD_METADATA",
    "CLOUD_PROOF_DEFAULT_TTL",
    "CloudMethodMetadata",
    "CloudPrincipalDescriptor",
    "GcpIamProtocol",
    "GcpServiceAccountJwtVerifier",
    "GoogleAuthIamAdapter",
    "JwtClaims",
    "ParsedRoleArn",
    "StsClientProtocol",
    "constant_time_str_equal",
    "descriptor_from_challenge",
    "emit_cloud_attempt",
    "hash_identifier",
    "make_proof",
    "metadata_for",
    "parse_role_arn",
    "redact_token",
    "run_with_timeout",
    "utcnow",
]
