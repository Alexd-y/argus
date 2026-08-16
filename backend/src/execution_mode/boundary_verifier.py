"""LAB boundary verifier — prove target belongs to LabScopeManifest."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

from src.execution_mode.lab_scope import LabScopeManifest

logger = logging.getLogger(__name__)


class BoundaryDenyCode(StrEnum):
    OUTSIDE_LAB = "DENY_OUTSIDE_LAB"
    MANIFEST_EXPIRED = "DENY_MANIFEST_EXPIRED"
    EMPTY_TARGET = "DENY_EMPTY_TARGET"
    TENANT_MISMATCH = "DENY_TENANT_MISMATCH"
    ENGAGEMENT_MISMATCH = "DENY_ENGAGEMENT_MISMATCH"
    NAMESPACE_REQUIRED = "DENY_NAMESPACE_UNBOUND"


class BoundaryVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: StrictBool
    reason: StrictStr
    deny_code: StrictStr | None = None
    matched_rule: StrictStr | None = None
    proof: StrictStr = Field(default="", max_length=128)

    @property
    def proof_token(self) -> str:
        return self.proof


@dataclass(frozen=True, slots=True)
class BoundaryCheckContext:
    tenant_id: str
    engagement_id: str
    target: str
    asset_id: str | None = None
    k8s_namespace: str | None = None
    vm_network_id: str | None = None


class LabBoundaryVerifier:
    """Deterministic LAB membership check.

    Hard conditions (master prompt §2.3):
    1. manifest present and not expired
    2. target resolves into lab asset/network/dns namespace
    3. optional runner namespace/VLAN binding when declared on manifest
    4. tenant/engagement must match (RLS never disabled)
    """

    def verify(
        self,
        target: str,
        manifest: LabScopeManifest,
        *,
        tenant_id: str | None = None,
        engagement_id: str | None = None,
        asset_id: str | None = None,
        k8s_namespace: str | None = None,
        vm_network_id: str | None = None,
    ) -> BoundaryVerdict:
        if not (target or "").strip() and not asset_id:
            return BoundaryVerdict(
                allowed=False,
                reason="empty_target",
                deny_code=BoundaryDenyCode.EMPTY_TARGET.value,
            )

        if tenant_id and tenant_id != manifest.tenant_id:
            return BoundaryVerdict(
                allowed=False,
                reason="tenant_mismatch",
                deny_code=BoundaryDenyCode.TENANT_MISMATCH.value,
            )
        if engagement_id and engagement_id != manifest.engagement_id:
            return BoundaryVerdict(
                allowed=False,
                reason="engagement_mismatch",
                deny_code=BoundaryDenyCode.ENGAGEMENT_MISMATCH.value,
            )
        if manifest.is_expired():
            return BoundaryVerdict(
                allowed=False,
                reason="manifest_expired",
                deny_code=BoundaryDenyCode.MANIFEST_EXPIRED.value,
            )

        if manifest.k8s_namespace:
            if not k8s_namespace or k8s_namespace != manifest.k8s_namespace:
                return BoundaryVerdict(
                    allowed=False,
                    reason="runner_namespace_unbound",
                    deny_code=BoundaryDenyCode.NAMESPACE_REQUIRED.value,
                )

        if manifest.vm_network_ids:
            if not vm_network_id or vm_network_id not in manifest.vm_network_ids:
                return BoundaryVerdict(
                    allowed=False,
                    reason="runner_vm_network_unbound",
                    deny_code=BoundaryDenyCode.NAMESPACE_REQUIRED.value,
                )

        if asset_id and asset_id in manifest.asset_ids:
            proof = f"asset:{asset_id}:{manifest.manifest_id[:8]}"
            return BoundaryVerdict(
                allowed=True,
                reason="matched_asset_id",
                matched_rule="asset_ids",
                proof=proof,
            )

        host = _extract_host(target)
        if host and _host_matches_dns_suffix(host, manifest.dns_suffixes):
            proof = f"dns:{host}:{manifest.manifest_id[:8]}"
            return BoundaryVerdict(
                allowed=True,
                reason="matched_dns_suffix",
                matched_rule="dns_suffixes",
                proof=proof,
            )

        ip = _try_parse_ip(host or target)
        if ip is not None and _ip_in_cidrs(ip, manifest.cidrs):
            proof = f"cidr:{ip}:{manifest.manifest_id[:8]}"
            return BoundaryVerdict(
                allowed=True,
                reason="matched_cidr",
                matched_rule="cidrs",
                proof=proof,
            )

        logger.info(
            "lab_boundary_denied",
            extra={
                "event": "lab_boundary_denied",
                "manifest_id": manifest.manifest_id,
                "tenant_id": manifest.tenant_id,
                "engagement_id": manifest.engagement_id,
                "target_present": bool(target),
            },
        )
        return BoundaryVerdict(
            allowed=False,
            reason="target_outside_lab_scope",
            deny_code=BoundaryDenyCode.OUTSIDE_LAB.value,
        )


def _extract_host(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or "").lower()
    if "/" in raw and _try_parse_ip(raw.split("/", 1)[0]) is not None:
        # CIDR-as-target is handled by IP parse of host part
        return raw.split("/", 1)[0].lower()
    if ":" in raw and raw.count(":") == 1 and not raw.startswith("["):
        # host:port
        return raw.split(":", 1)[0].lower()
    return raw.lower().rstrip(".")


def _host_matches_dns_suffix(host: str, suffixes: tuple[str, ...]) -> bool:
    h = host.lower().rstrip(".")
    for suffix in suffixes:
        s = suffix.lower().lstrip(".").rstrip(".")
        if not s:
            continue
        if h == s or h.endswith("." + s):
            return True
    return False


def _try_parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _ip_in_cidrs(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    cidrs: tuple[str, ...],
) -> bool:
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if ip in network:
            return True
    return False
