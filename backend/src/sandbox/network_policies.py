"""NetworkPolicy templates for the ARGUS sandbox driver.

Renders Kubernetes ``NetworkPolicy`` v1 manifests (``networking.k8s.io/v1``)
that get applied alongside every sandbox ``Job`` so a tool pod can only talk
to the explicit egress targets its category allows.

Hard guardrails enforced for every template (see ``Backlog/dev1_md`` §5/§15):

* Ingress is **always** denied (``ingress_blocked = True``); a sandbox pod
  must never accept inbound connections.
* DNS is the *only* port opened on top of the per-template payload ports;
  resolvers are pinned (Cloudflare ``1.1.1.1`` / Quad9 ``9.9.9.9``).
* Templates that target the scan host (``egress_target_dynamic = True``)
  REQUIRE ``target_cidr`` at render time. This makes accidental wildcard
  egress impossible in active categories.
* Pod-to-pod traffic in the sandbox namespace is blocked by selecting on
  the per-job pod label (``argus.io/job-id``).

Eleven templates are seeded (eight from ARG-003/ARG-017 plus three cloud
parity templates landed in ARG-027): ``recon-passive``,
``recon-active-tcp``, ``recon-active-udp``, ``recon-smb``,
``tls-handshake``, ``oast-egress``, ``auth-bruteforce``,
``offline-no-egress``, ``cloud-aws``, ``cloud-gcp``, ``cloud-azure``.

Per-tool overrides (ARG-027): ``render_networkpolicy_manifest`` accepts
``dns_resolvers_override`` (replaces the template defaults) and
``egress_allowlist_override`` (unioned with the template's static
allowlist). Both are validated against a denylist of private + IMDS CIDR
ranges so a misconfigured YAML cannot widen the policy onto the
intra-cluster overlay or onto a cloud metadata service.

The module is pure (no I/O, no K8s API calls) so the renderer is trivial to
unit test and reuse from CLIs / policy-audit tooling.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


NETWORK_POLICY_NAMES: Final[frozenset[str]] = frozenset(
    {
        "recon-passive",
        "recon-active-tcp",
        "recon-active-udp",
        "recon-smb",
        "tls-handshake",
        # ARG-017 §4.11 — egress restricted to the OAST plane only.
        "oast-egress",
        # ARG-017 §4.12 — high-rate auth bruteforce: target CIDR + auth ports.
        "auth-bruteforce",
        # ARG-017 §4.13 — fully isolated cracking pods (offline only).
        "offline-no-egress",
        # ARG-027 §15 — cloud parity: dedicated egress profiles per cloud
        # provider with private-range / IMDS denylisting.
        "cloud-aws",
        "cloud-gcp",
        "cloud-azure",
    }
)

_DEFAULT_DNS_RESOLVERS: Final[tuple[str, ...]] = ("1.1.1.1", "9.9.9.9")

# DNS over UDP/53 is the smallest and most common case; over TCP/53 is opened
# in the same egress block so resolvers that fall back to TCP (large records,
# DNSSEC) keep working.
_DNS_PORTS_UDP: Final[tuple[int, ...]] = (53,)
_DNS_PORTS_TCP: Final[tuple[int, ...]] = (53,)


# Private + link-local CIDR blocks that must NEVER appear in a per-tool
# override. Anything inside these ranges is either intra-cluster pod / node
# traffic (blocked unconditionally by the K8s deny-all baseline) or a cloud
# metadata service (the SSRF target Azure / OpenStack / EC2 expose at
# 169.254.169.254). A misconfigured YAML widening the allow-list onto these
# blocks would silently bypass the network isolation invariant; ARG-027
# rejects them at render time with a deterministic ``ValueError``.
_PRIVATE_DENY_NETWORKS: Final[tuple[ipaddress.IPv4Network, ...]] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    # Carve out 169.254.169.254/32 explicitly so the error message points to
    # the IMDS SSRF risk, even though it would also match the broader
    # 169.254.0.0/16 link-local block.
    ipaddress.IPv4Network("169.254.169.254/32"),
    ipaddress.IPv4Network("169.254.0.0/16"),
)

# Cloud-provider templates open ``0.0.0.0/0`` minus the private ranges above.
# Materialising the except-list once keeps the cloud templates DRY and
# auditable in one place.
_CLOUD_EGRESS_EXCEPT_CIDRS: Final[tuple[str, ...]] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
)

# CIDRs that mean "any address" and therefore trigger the mandatory
# private-range / IMDS deny exceptions in :func:`_build_ip_block_peer`.
# Both the IPv4 and IPv6 wildcards are listed so a future IPv6 rollout does
# not silently regress.
_ANY_CIDRS: Final[frozenset[str]] = frozenset({"0.0.0.0/0", "::/0"})


# ---------------------------------------------------------------------------
# Public model
# ---------------------------------------------------------------------------


class PortRange(BaseModel):
    """Closed-interval port range used by :class:`NetworkPolicyTemplate`.

    K8s ``NetworkPolicyPort`` supports ``endPort`` (1.25+, GA), letting a
    single rule cover a contiguous port range without enumerating each
    port. Used for active-recon templates that legitimately need 1..65535
    so the rendered manifest stays small.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol: StrictStr = Field(pattern=r"^(TCP|UDP)$")
    start: StrictInt = Field(ge=1, le=65_535)
    end: StrictInt = Field(ge=1, le=65_535)


class NetworkPolicyTemplate(BaseModel):
    """Declarative description of a NetworkPolicy template.

    Pure value object — all rendering happens in
    :func:`render_networkpolicy_manifest`. Templates are immutable (frozen)
    so no caller can accidentally widen the policy after registration.

    Cloud-parity templates (ARG-027) use ``egress_allowlist_static`` to
    expose ``0.0.0.0/0`` and rely on ``egress_except_cidrs`` to carve out
    the private + IMDS blocks; the FQDN intent is captured in
    ``egress_allowed_fqdns`` for documentation, audit logs, and downstream
    Cilium / Calico FQDN-aware policies (vanilla NetworkPolicy v1 cannot
    enforce DNS names directly).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=64)
    description: StrictStr = Field(min_length=1, max_length=500)
    egress_allowlist_static: list[StrictStr] = Field(
        default_factory=list, max_length=32
    )
    # CIDRs subtracted from each entry of ``egress_allowlist_static`` via the
    # ``ipBlock.except`` field (Backlog §15). Cloud-parity templates use this
    # to expose ``0.0.0.0/0`` minus the private + IMDS blocks.
    egress_except_cidrs: list[StrictStr] = Field(default_factory=list, max_length=16)
    # Documentation-only FQDN allow-list. Vanilla K8s NetworkPolicy v1 can
    # only filter on IP / CIDR, so these names are surfaced through the
    # rendered manifest's annotations (``argus.io/egress-fqdns``) for
    # downstream FQDN-aware enforcement (Cilium / Calico) and audit
    # tooling. They never widen the rendered ipBlock list.
    egress_allowed_fqdns: list[StrictStr] = Field(default_factory=list, max_length=32)
    egress_target_dynamic: StrictBool = False
    allowed_ports_tcp: list[StrictInt] = Field(default_factory=list, max_length=64)
    allowed_ports_udp: list[StrictInt] = Field(default_factory=list, max_length=64)
    # Port ranges (NetworkPolicyPort.endPort). Use this instead of
    # enumerating long port lists in allowed_ports_tcp / udp.
    port_ranges: list[PortRange] = Field(default_factory=list, max_length=8)
    dns_resolvers: list[StrictStr] = Field(
        default_factory=lambda: list(_DEFAULT_DNS_RESOLVERS), max_length=8
    )
    ingress_blocked: StrictBool = True


# ---------------------------------------------------------------------------
# Template seed
# ---------------------------------------------------------------------------


def _build_seed_templates() -> dict[str, NetworkPolicyTemplate]:
    """Construct the seeded NetworkPolicy templates (called once at import)."""

    templates: dict[str, NetworkPolicyTemplate] = {}

    # 1) Passive recon — broad egress for OSINT APIs (crt.sh, Shodan, OTX,
    # GitHub, RDAP, VirusTotal). DNS + HTTPS only; no high ports needed.
    templates["recon-passive"] = NetworkPolicyTemplate(
        name="recon-passive",
        description=(
            "Passive recon (OSINT APIs, certificate transparency, WHOIS/RDAP)."
            " Broad egress 0.0.0.0/0 limited to 80/443 + DNS."
        ),
        egress_allowlist_static=["0.0.0.0/0"],
        egress_target_dynamic=False,
        allowed_ports_tcp=[80, 443],
        allowed_ports_udp=[],
    )

    # 2) Active TCP recon — egress restricted to the resolved scan target;
    # full TCP port range so masscan / nmap can sweep arbitrary services.
    # Use endPort (port range) instead of enumerating 65535 ports.
    templates["recon-active-tcp"] = NetworkPolicyTemplate(
        name="recon-active-tcp",
        description=(
            "Active TCP recon (nmap top-ports, full SYN scan, naabu, rustscan)"
            " — egress restricted to the per-job target CIDR; full TCP range."
        ),
        egress_allowlist_static=[],
        egress_target_dynamic=True,
        allowed_ports_tcp=[],
        allowed_ports_udp=[],
        port_ranges=[PortRange(protocol="TCP", start=1, end=65_535)],
    )

    # 3) Active UDP recon — same target restriction, UDP-only payload ports
    # for nmap_udp / unicornscan top-100 UDP probes.
    templates["recon-active-udp"] = NetworkPolicyTemplate(
        name="recon-active-udp",
        description=(
            "Active UDP recon (nmap_udp top-100, unicornscan) — egress to"
            " the per-job target on common UDP probe ports."
        ),
        egress_allowlist_static=[],
        egress_target_dynamic=True,
        allowed_ports_tcp=[],
        # Common UDP services hit by nmap_udp / unicornscan default profiles.
        allowed_ports_udp=[53, 67, 68, 69, 123, 161, 500, 1900, 5353],
    )

    # 4) SMB enumeration — smbmap / enum4linux / rpcclient need both 137/138
    # (NetBIOS over UDP) and 135/139/445 (TCP).
    templates["recon-smb"] = NetworkPolicyTemplate(
        name="recon-smb",
        description=(
            "SMB enumeration (smbmap, enum4linux-ng, rpcclient) — TCP"
            " 135/139/445 + UDP 137/138 to the per-job target only."
        ),
        egress_allowlist_static=[],
        egress_target_dynamic=True,
        allowed_ports_tcp=[135, 139, 445],
        allowed_ports_udp=[137, 138],
    )

    # 5) TLS handshake — testssl / sslyze / sslscan / tlsx / nmap ssl-enum
    # only need TCP/443 (other ports come from {port} placeholder when set).
    templates["tls-handshake"] = NetworkPolicyTemplate(
        name="tls-handshake",
        description=(
            "TLS / SSL handshake audit (testssl, sslyze, sslscan, tlsx,"
            " ssl-enum-ciphers) — TCP/443 to the per-job target."
        ),
        egress_allowlist_static=[],
        egress_target_dynamic=True,
        allowed_ports_tcp=[443],
        allowed_ports_udp=[],
    )

    # 6) OAST egress (ARG-017 §4.11) — pods must reach the dedicated
    # ARGUS OAST plane (interactsh client poll endpoint, oast-callback
    # bridge) AND the per-job target so the SSRF / OOB payload chain can
    # actually fire. The OAST plane lives on a dedicated /24 inside the
    # cluster (10.244.250.0/24); the policy pins egress to that block +
    # the dynamic target_cidr. DNS is opened separately (default).
    # Allowed ports: 53 / 80 / 443 / 25 / 587 — plus the target CIDR's
    # full TCP/UDP range so the actual SSRF probe can hit any internal
    # service that triggers the OOB callback.
    templates["oast-egress"] = NetworkPolicyTemplate(
        name="oast-egress",
        description=(
            "OAST / OOB egress (ARG-017 §4.11) — interactsh / oastify"
            " clients + SSRF probes. Egress to the OAST plane (TCP/UDP"
            " 80/443/53/25/587) plus the per-job target on TCP 1..65535."
        ),
        egress_allowlist_static=["10.244.250.0/24"],
        egress_target_dynamic=True,
        allowed_ports_tcp=[25, 53, 80, 443, 587, 8080, 8443],
        allowed_ports_udp=[53],
        port_ranges=[PortRange(protocol="TCP", start=1, end=65_535)],
    )

    # 7) Auth bruteforce (ARG-017 §4.12 + ARG-019 §4.17) — egress restricted
    # to the in-scope target CIDR on the common authenticated-service ports.
    # Each tool (hydra / medusa / patator / ncrack / cme / kerbrute /
    # smbclient / snmp-check / evil-winrm / redis-cli / mongosh) hits
    # exactly one of these.
    templates["auth-bruteforce"] = NetworkPolicyTemplate(
        name="auth-bruteforce",
        description=(
            "Auth bruteforce (ARG-017 §4.12 + ARG-019 §4.17 unauth probes)"
            " — hydra/medusa/patator/ncrack family + crackmapexec, kerbrute,"
            " smbclient, snmp-check, evil-winrm, redis_cli_probe,"
            " mongodb_probe. Egress: per-job target only, common auth ports"
            " (TCP 21/22/23/25/53/110/139/143/389/445/465/587/993/995"
            "/1433/1521/2049/3306/3389/5432/5900/5985/5986/6379/27017;"
            " UDP 53/137/161/500)."
        ),
        egress_allowlist_static=[],
        egress_target_dynamic=True,
        allowed_ports_tcp=[
            21,
            22,
            23,
            25,
            53,
            88,
            110,
            135,
            139,
            143,
            389,
            443,
            445,
            465,
            587,
            636,
            993,
            995,
            1433,
            1521,
            2049,
            3306,
            3389,
            5432,
            5900,
            5985,
            5986,
            # Redis (6379), MongoDB (27017) for §4.17 unauth probe — added ARG-019 C2 fix
            6379,
            27017,
        ],
        allowed_ports_udp=[53, 88, 137, 161, 500],
    )

    # 8) Offline / no egress (ARG-017 §4.13) — hashcat / john / ophcrack
    # / hashid / hash_analyzer never need to phone home. The pod is
    # network-isolated (no egress, no DNS) so an embedded "phone home"
    # in a pre-built rule pack cannot exfiltrate hashes.
    templates["offline-no-egress"] = NetworkPolicyTemplate(
        name="offline-no-egress",
        description=(
            "Fully offline cracking pods (ARG-017 §4.13) — hashcat /"
            " john / ophcrack / hashid / hash_analyzer. NO egress, NO"
            " DNS; ingress denied per global default. Defence in depth"
            " against malicious wordlist / rule packs."
        ),
        egress_allowlist_static=[],
        egress_target_dynamic=False,
        allowed_ports_tcp=[],
        allowed_ports_udp=[],
        dns_resolvers=[],
    )

    # 9) cloud-aws (ARG-027 §15) — broad TCP/443 egress to the public
    # internet **minus** the intra-cluster + EC2 IMDS link-local ranges.
    # The FQDN allow-list (`*.amazonaws.com`, `*.aws.amazon.com`,
    # `*.s3.amazonaws.com`, `*.cloudfront.net`) is documentation-only:
    # NetworkPolicy v1 cannot match on DNS, so the IP-level fallback opens
    # 0.0.0.0/0 and Cilium / Calico FQDN policies (deferred to ARG-O2x)
    # will tighten this further.  prowler / scoutsuite / cloudsploit /
    # pacu use this template instead of `recon-passive` so EC2 IMDS
    # (169.254.169.254 SSRF target) is unreachable from the pod.
    templates["cloud-aws"] = NetworkPolicyTemplate(
        name="cloud-aws",
        description=(
            "AWS cloud posture audit (prowler, scoutsuite, cloudsploit, pacu)"
            " — TCP/443 egress to 0.0.0.0/0 minus private + EC2 IMDS"
            " (169.254.169.254). FQDN intent: *.amazonaws.com,"
            " *.aws.amazon.com, *.s3.amazonaws.com, *.cloudfront.net."
        ),
        egress_allowlist_static=["0.0.0.0/0"],
        egress_except_cidrs=list(_CLOUD_EGRESS_EXCEPT_CIDRS),
        egress_allowed_fqdns=[
            "*.amazonaws.com",
            "*.aws.amazon.com",
            "*.s3.amazonaws.com",
            "*.cloudfront.net",
        ],
        egress_target_dynamic=False,
        allowed_ports_tcp=[443],
        allowed_ports_udp=[],
    )

    # 10) cloud-gcp (ARG-027 §15) — same shape as cloud-aws but with the
    # GCP-specific FQDN intent (`*.googleapis.com`, `*.gcr.io`,
    # `*.pkg.dev`).  GCP's metadata server lives at
    # `metadata.google.internal` (a stable RFC-1918-style 169.254.169.254
    # too); we deliberately keep the IMDS deny in place so a leaked
    # service-account token cannot be exfiltrated through the same
    # SSRF surface that Azure / EC2 expose.  Tools requiring metadata
    # access run with the workload-identity sidecar instead.
    templates["cloud-gcp"] = NetworkPolicyTemplate(
        name="cloud-gcp",
        description=(
            "GCP cloud posture audit — TCP/443 egress to 0.0.0.0/0 minus"
            " private + metadata.google.internal (169.254.169.254)."
            " FQDN intent: *.googleapis.com, *.gcr.io, *.pkg.dev,"
            " *.cloudfunctions.net."
        ),
        egress_allowlist_static=["0.0.0.0/0"],
        egress_except_cidrs=list(_CLOUD_EGRESS_EXCEPT_CIDRS),
        egress_allowed_fqdns=[
            "*.googleapis.com",
            "*.gcr.io",
            "*.pkg.dev",
            "*.cloudfunctions.net",
            "metadata.google.internal",
        ],
        egress_target_dynamic=False,
        allowed_ports_tcp=[443],
        allowed_ports_udp=[],
    )

    # 11) cloud-azure (ARG-027 §15) — Azure parity.  Critically, Azure's
    # IMDS at 169.254.169.254 is the SSRF target several past CVEs have
    # leveraged; the except-list explicitly drops the entire 169.254/16
    # block so neither the IMDS nor the wireserver (168.63.129.16 lives
    # outside private ranges and is therefore untouched by default,
    # which is intentional — it is required for VM agent communication).
    templates["cloud-azure"] = NetworkPolicyTemplate(
        name="cloud-azure",
        description=(
            "Azure cloud posture audit — TCP/443 egress to 0.0.0.0/0 minus"
            " private + Azure IMDS (169.254.169.254). FQDN intent:"
            " *.azure.com, *.azurewebsites.net, *.azure.net, *.windows.net,"
            " management.azure.com."
        ),
        egress_allowlist_static=["0.0.0.0/0"],
        egress_except_cidrs=list(_CLOUD_EGRESS_EXCEPT_CIDRS),
        egress_allowed_fqdns=[
            "*.azure.com",
            "*.azurewebsites.net",
            "*.azure.net",
            "*.windows.net",
            "management.azure.com",
        ],
        egress_target_dynamic=False,
        allowed_ports_tcp=[443],
        allowed_ports_udp=[],
    )

    # Defence-in-depth: never let _TEMPLATES drift away from the public set.
    seeded = frozenset(templates)
    if seeded != NETWORK_POLICY_NAMES:
        missing = sorted(NETWORK_POLICY_NAMES - seeded)
        extra = sorted(seeded - NETWORK_POLICY_NAMES)
        raise RuntimeError(
            "NETWORK_POLICY_NAMES diverged from seeded templates "
            f"(missing={missing}, extra={extra})"
        )

    return templates


_TEMPLATES: Final[dict[str, NetworkPolicyTemplate]] = _build_seed_templates()


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


def get_template(name: str) -> NetworkPolicyTemplate:
    """Return the template registered under ``name``.

    Raises :class:`KeyError` (with a stable message) when ``name`` is not in
    :data:`NETWORK_POLICY_NAMES`. The caller is expected to translate this
    into a domain-specific error (see :class:`SandboxConfigError` in the
    k8s adapter).
    """
    if name not in _TEMPLATES:
        raise KeyError(
            f"NetworkPolicy template {name!r} is not registered. "
            f"Known templates: {sorted(NETWORK_POLICY_NAMES)}"
        )
    return _TEMPLATES[name]


def list_templates() -> list[NetworkPolicyTemplate]:
    """Return every registered template, sorted by name."""
    return [_TEMPLATES[name] for name in sorted(_TEMPLATES)]


# ---------------------------------------------------------------------------
# Validation helpers (ARG-027)
# ---------------------------------------------------------------------------


def _is_fqdn_entry(entry: str) -> bool:
    """Heuristic: treat any entry without a leading digit (or wildcard) as FQDN.

    NetworkPolicy v1 ipBlock takes CIDR / IP literals; ARGUS additionally
    accepts FQDN entries (``*.example.com``, ``api.example.com``,
    ``metadata.google.internal``) as documentation that downstream
    FQDN-aware policies (Cilium / Calico) will enforce.  IP / CIDR entries
    always start with a digit (or ``::`` for IPv6 short-form) — the
    distinction is therefore syntactic and unambiguous.
    """
    if not entry:
        return False
    head = entry[0]
    return head.isalpha() or head == "*"


def _network_overlaps_deny(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """True iff ``net`` overlaps with any private / IMDS deny block.

    Both directions are checked: an entry that is a subnet of a deny block
    AND an entry whose subnet *contains* the deny block both fail (the
    second case catches an attempted ``0.0.0.0/0`` injection through the
    override surface, which would silently widen the policy onto
    intra-cluster pod traffic).
    """
    if isinstance(net, ipaddress.IPv6Network):
        # IPv6 link-local + ULA are out-of-scope for ARG-027 — the cloud
        # metadata services are IPv4-only. Future tightening is a
        # follow-up task.
        return False
    for deny in _PRIVATE_DENY_NETWORKS:
        if net.subnet_of(deny) or deny.subnet_of(net):
            return True
    return False


def _validate_egress_override_entry(entry: str, *, field_name: str) -> None:
    """Raise :class:`ValueError` if ``entry`` is forbidden in an override.

    FQDN entries (``*.example.com``, ``api.example.com``) are accepted
    verbatim — DNS-name enforcement is delegated to downstream
    FQDN-aware policies. CIDR / IP entries are parsed strictly and
    rejected when they overlap any block in
    :data:`_PRIVATE_DENY_NETWORKS`, **except** for the wildcard ``0.0.0.0/0``
    (and IPv6 ``::/0``) which is the canonical "permit all internet" intent
    used by 40+ recon / OSINT tool YAMLs. The renderer
    (:func:`_build_ip_block_peer`) automatically attaches the private +
    IMDS deny list to every wildcard peer so the resulting policy is still
    safe — strictly safer, in fact, than the pre-ARG-027 behaviour which
    emitted a naked ``0.0.0.0/0`` peer with no exceptions at all.
    """
    if not isinstance(entry, str) or not entry:
        raise ValueError(
            f"{field_name} entry must be a non-empty string, got {entry!r}"
        )
    if _is_fqdn_entry(entry):
        return
    try:
        net = ipaddress.ip_network(entry, strict=False)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"{field_name} entry {entry!r} is not a valid CIDR / IP / FQDN"
        ) from exc
    if str(net) in _ANY_CIDRS:
        # Wildcard egress is permitted because the renderer enforces the
        # private-range / IMDS deny list on every wildcard peer it builds.
        return
    if _network_overlaps_deny(net):
        raise ValueError(
            f"{field_name} entry {entry!r} overlaps a private / IMDS deny "
            "range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "
            "169.254.169.254/32, 169.254.0.0/16) — private ranges and "
            "the cloud metadata service are NOT allowed in egress overrides."
        )


def _validate_dns_resolver_entry(entry: str) -> None:
    """Raise :class:`ValueError` for an invalid / disallowed DNS resolver.

    DNS resolvers are pinned to public addresses (NetworkPolicy v1 ipBlock
    accepts CIDR/IP only), so FQDN entries are rejected outright — pinning
    to a public IP is the whole point of resolver-pinning. Private /
    intra-cluster / IMDS addresses are rejected for the same reason as
    egress override entries.
    """
    if not isinstance(entry, str) or not entry:
        raise ValueError(
            f"dns_resolvers entry must be a non-empty string, got {entry!r}"
        )
    try:
        net = ipaddress.ip_network(entry, strict=False)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"dns_resolvers entry {entry!r} must be a valid IP / CIDR (FQDNs "
            "are not allowed for resolver pinning — NetworkPolicy v1 ipBlock "
            "only accepts IP literals)"
        ) from exc
    if _network_overlaps_deny(net):
        raise ValueError(
            f"dns_resolvers entry {entry!r} overlaps a private / IMDS deny "
            "range — DNS resolvers must be public addresses to keep the "
            "resolver pinning auditable."
        )


def _validated_egress_overrides(
    entries: Sequence[str] | None, *, field_name: str
) -> list[str]:
    """Validate and de-duplicate an override list, preserving caller order."""
    if not entries:
        return []
    seen: set[str] = set()
    result: list[str] = []
    for raw in entries:
        _validate_egress_override_entry(raw, field_name=field_name)
        if raw not in seen:
            seen.add(raw)
            result.append(raw)
    return result


def _validated_dns_overrides(entries: Sequence[str] | None) -> list[str]:
    """Validate and de-duplicate a DNS-resolver override, preserving order."""
    if not entries:
        return []
    seen: set[str] = set()
    result: list[str] = []
    for raw in entries:
        _validate_dns_resolver_entry(raw)
        if raw not in seen:
            seen.add(raw)
            result.append(raw)
    return result


# ---------------------------------------------------------------------------
# Manifest renderer
# ---------------------------------------------------------------------------


def _normalise_cidr(cidr: str) -> str:
    """Validate and normalise a CIDR (or bare IP) literal.

    Accepts both ``10.0.0.5`` (auto-promotes to ``/32`` for v4 / ``/128`` for
    v6) and ``10.0.0.0/24``. Rejects anything :func:`ipaddress.ip_network`
    would otherwise reject (typos, host bits set, malformed prefix).
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"target_cidr {cidr!r} is not a valid CIDR / IP literal"
        ) from exc
    return str(net)


def _split_cidrs_and_fqdns(entries: Iterable[str]) -> tuple[list[str], list[str]]:
    """Partition an entry list into (CIDR-like, FQDN-like) buckets.

    NetworkPolicy v1 ``ipBlock.cidr`` only accepts IP literals; FQDN
    entries from ``egress_allowlist_override`` (and the documentation
    intent on cloud templates) are surfaced as annotations instead.
    """
    cidrs: list[str] = []
    fqdns: list[str] = []
    for entry in entries:
        if _is_fqdn_entry(entry):
            fqdns.append(entry)
        else:
            cidrs.append(entry)
    return cidrs, fqdns


def _build_dns_egress_rule(resolvers: list[str]) -> dict[str, Any]:
    """Build the DNS egress block (UDP/53 + TCP/53 to pinned resolvers)."""
    if not resolvers:
        return {}
    peers = [{"ipBlock": {"cidr": _normalise_cidr(addr)}} for addr in resolvers]
    ports: list[dict[str, Any]] = [
        {"protocol": "UDP", "port": port} for port in _DNS_PORTS_UDP
    ]
    ports.extend({"protocol": "TCP", "port": port} for port in _DNS_PORTS_TCP)
    return {"to": peers, "ports": ports}


def _build_ip_block_peer(cidr: str, except_cidrs: Sequence[str]) -> dict[str, Any]:
    """Build a single ``to.ipBlock`` entry, attaching ``except`` when present.

    ``except`` entries are normalised through :func:`_normalise_cidr` so a
    typo in the template (e.g. ``10.0.0.0/33``) fails fast at render time
    rather than producing a silently-broken policy at apply time.

    Per the Kubernetes NetworkPolicy spec ``except`` entries MUST be
    subnets of ``cidr``; entries that fall outside the peer's range are
    silently filtered out. This lets the cloud templates declare a single
    deny-list (private + IMDS) and have it apply only where it is
    syntactically valid (the broad ``0.0.0.0/0`` peer), while narrower
    user override peers get a clean ``ipBlock`` with no spurious
    ``except`` entries that the K8s API server would reject at apply
    time.

    Defence in depth (ARG-027): when ``cidr`` resolves to ``0.0.0.0/0``
    (or IPv6 ``::/0``) the private + IMDS deny list is *always* attached
    — even if the caller passed an empty ``except_cidrs``. This makes it
    impossible to render a wildcard peer that silently allows reach into
    intra-cluster pod traffic or the cloud metadata service, no matter
    how the upstream template / override widens the policy.
    """
    normalised_cidr = _normalise_cidr(cidr)
    effective_excepts: list[str] = list(except_cidrs)
    if normalised_cidr in _ANY_CIDRS:
        for forced in _PRIVATE_DENY_NETWORKS:
            if str(forced) not in effective_excepts:
                effective_excepts.append(str(forced))
    block: dict[str, Any] = {"cidr": normalised_cidr}
    if effective_excepts:
        peer_net = ipaddress.ip_network(normalised_cidr, strict=False)
        valid_excepts: list[str] = []
        seen_excepts: set[str] = set()
        for raw in effective_excepts:
            try:
                ex_net = ipaddress.ip_network(raw, strict=False)
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"egress_except_cidrs entry {raw!r} is not a valid CIDR"
                ) from exc
            # ``subnet_of`` requires both networks to be the same IP version
            # (mypy cannot narrow on ``.version`` equality, so use isinstance).
            if isinstance(peer_net, ipaddress.IPv4Network):
                if not isinstance(ex_net, ipaddress.IPv4Network):
                    continue
                if not ex_net.subnet_of(peer_net):
                    continue
            else:
                if not isinstance(ex_net, ipaddress.IPv6Network):
                    continue
                if not ex_net.subnet_of(peer_net):
                    continue
            normalised_except = str(ex_net)
            if normalised_except in seen_excepts:
                continue
            seen_excepts.add(normalised_except)
            valid_excepts.append(normalised_except)
        if valid_excepts:
            block["except"] = valid_excepts
    return {"ipBlock": block}


def _build_payload_egress_rule(
    template: NetworkPolicyTemplate,
    *,
    target_cidr: str | None,
    egress_allowlist_override_cidrs: Sequence[str] = (),
) -> dict[str, Any]:
    """Build the per-template payload egress block (target + ports + overrides).

    The override list is unioned with ``template.egress_allowlist_static``
    (deduplicated, order-preserving). FQDN entries from the override are
    handled separately by the caller (rendered as annotations) — only
    IP / CIDR entries reach this rule's ``to.ipBlock`` array.
    """
    peers: list[dict[str, Any]] = []
    if template.egress_target_dynamic:
        if target_cidr is None:
            raise ValueError(
                f"template {template.name!r} requires a target_cidr "
                "(egress_target_dynamic=True)"
            )
        peers.append(_build_ip_block_peer(target_cidr, ()))
        for cidr in egress_allowlist_override_cidrs:
            peers.append(_build_ip_block_peer(cidr, ()))
    else:
        seen: set[str] = set()
        for cidr in (
            *template.egress_allowlist_static,
            *egress_allowlist_override_cidrs,
        ):
            normalised = _normalise_cidr(cidr)
            if normalised in seen:
                continue
            seen.add(normalised)
            peers.append(_build_ip_block_peer(cidr, template.egress_except_cidrs))

    ports: list[dict[str, Any]] = []
    ports.extend(
        {"protocol": "TCP", "port": port} for port in template.allowed_ports_tcp
    )
    ports.extend(
        {"protocol": "UDP", "port": port} for port in template.allowed_ports_udp
    )
    for port_range in template.port_ranges:
        ports.append(
            {
                "protocol": port_range.protocol,
                "port": port_range.start,
                "endPort": port_range.end,
            }
        )

    rule: dict[str, Any] = {}
    if peers:
        rule["to"] = peers
    if ports:
        rule["ports"] = ports
    return rule


def render_networkpolicy_manifest(
    template: NetworkPolicyTemplate,
    *,
    namespace: str,
    pod_label_selector: dict[str, str],
    target_cidr: str | None = None,
    name_suffix: str | None = None,
    dns_resolvers_override: Sequence[str] | None = None,
    egress_allowlist_override: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Render a NetworkPolicy v1 manifest tailored to a single sandbox job.

    Parameters
    ----------
    template
        The :class:`NetworkPolicyTemplate` to materialise. Pass one returned
        by :func:`get_template`.
    namespace
        Kubernetes namespace the policy lives in (matches the Job).
    pod_label_selector
        Labels uniquely identifying the target pod(s). Almost always a
        single ``argus.io/job-id`` label so the policy applies to one Job.
    target_cidr
        REQUIRED when ``template.egress_target_dynamic`` is True; ignored
        otherwise (a passing value is accepted to keep the call site simple).
    name_suffix
        Optional suffix appended to the policy name. The K8s name MUST be
        unique within the namespace; a per-job suffix (e.g. the Job's short
        UUID) keeps multiple concurrent runs of the same template isolated.
    dns_resolvers_override
        Per-tool override (ARG-027). When non-empty, **replaces** the
        template's default DNS resolver list. Validated against
        :data:`_PRIVATE_DENY_NETWORKS` so a misconfigured YAML cannot
        pin DNS to an intra-cluster / IMDS address.
    egress_allowlist_override
        Per-tool override (ARG-027). **Unioned** with the template's
        static allowlist (additive, never replaces). FQDN-style entries
        (e.g. ``api.example.com``) are surfaced via the
        ``argus.io/egress-fqdns`` annotation; IP / CIDR entries are
        appended to the ``to.ipBlock`` peer list. Validated against the
        same denylist as ``dns_resolvers_override``.

    Returns
    -------
    dict
        A ``dict`` ready to pass to ``yaml.safe_dump`` or
        ``kubernetes.client.NetworkingV1Api().create_namespaced_network_policy``.

    Raises
    ------
    ValueError
        If ``target_cidr`` is required but not supplied, if any CIDR fails
        :func:`ipaddress.ip_network`, or if either override contains an
        entry inside :data:`_PRIVATE_DENY_NETWORKS`.
    """
    if not pod_label_selector:
        raise ValueError("pod_label_selector must contain at least one label")

    validated_dns = _validated_dns_overrides(dns_resolvers_override)
    validated_egress = _validated_egress_overrides(
        egress_allowlist_override, field_name="egress_allowlist_override"
    )
    override_cidrs, override_fqdns = _split_cidrs_and_fqdns(validated_egress)

    metadata_name = template.name
    if name_suffix:
        # K8s names must be DNS-1123 — keep this simple and predictable.
        metadata_name = f"{template.name}-{name_suffix}"

    resolvers = validated_dns if validated_dns else list(template.dns_resolvers)

    egress_rules: list[dict[str, Any]] = []
    payload_rule = _build_payload_egress_rule(
        template,
        target_cidr=target_cidr,
        egress_allowlist_override_cidrs=override_cidrs,
    )
    if payload_rule:
        egress_rules.append(payload_rule)
    dns_rule = _build_dns_egress_rule(resolvers)
    if dns_rule:
        egress_rules.append(dns_rule)

    annotations: dict[str, str] = {}
    fqdn_intent = list(template.egress_allowed_fqdns) + override_fqdns
    if fqdn_intent:
        # Stable, deterministic ordering for diffability + audit-log readability.
        annotations["argus.io/egress-fqdns"] = ",".join(fqdn_intent)

    metadata: dict[str, Any] = {
        "name": metadata_name,
        "namespace": namespace,
        "labels": {
            "app.kubernetes.io/name": "argus-sandbox",
            "app.kubernetes.io/component": "network-policy",
            "argus.io/template": template.name,
        },
    }
    if annotations:
        metadata["annotations"] = annotations

    manifest: dict[str, Any] = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": metadata,
        "spec": {
            "podSelector": {"matchLabels": dict(pod_label_selector)},
            "policyTypes": ["Ingress", "Egress"],
            # Ingress block is always empty (deny-all). Egress is built above.
            "ingress": [],
            "egress": egress_rules,
        },
    }
    return manifest


__all__ = [
    "NETWORK_POLICY_NAMES",
    "NetworkPolicyTemplate",
    "PortRange",
    "get_template",
    "list_templates",
    "render_networkpolicy_manifest",
]
