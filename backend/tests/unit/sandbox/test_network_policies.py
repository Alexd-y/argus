"""Unit tests for :mod:`src.sandbox.network_policies`.

Covers the eleven seeded NetworkPolicy templates + the renderer (Backlog/dev1_md
§5/§15 + ARG-017 §4.11..4.13 + ARG-027 cloud parity). Every template is
checked for:

* Ingress is denied unconditionally.
* DNS is opened on UDP/53 + TCP/53 to the pinned resolvers (except the
  fully air-gapped ``offline-no-egress`` template, which intentionally
  empties the resolver list).
* Per-template allowed_ports_tcp / allowed_ports_udp materialise correctly.
* Templates with ``egress_target_dynamic=True`` REQUIRE ``target_cidr``.
* No ``hostPath`` / ``docker.sock`` traces ever appear in the rendered manifest.

ARG-027 adds:

* The ``cloud-aws`` / ``cloud-gcp`` / ``cloud-azure`` templates (broad TCP/443
  egress to ``0.0.0.0/0`` minus the private + IMDS deny ranges).
* ``dns_resolvers_override`` and ``egress_allowlist_override`` consumption in
  :func:`render_networkpolicy_manifest`, including negative validation for
  private / IMDS ranges.
"""

from __future__ import annotations

import pytest

from src.sandbox.network_policies import (
    NETWORK_POLICY_NAMES,
    NetworkPolicyTemplate,
    get_template,
    list_templates,
    render_networkpolicy_manifest,
)


_DEFAULT_POD_SELECTOR: dict[str, str] = {"argus.io/job-id": "abcd1234"}
_DEFAULT_NAMESPACE = "argus-sandbox"


# ---------------------------------------------------------------------------
# Template discovery
# ---------------------------------------------------------------------------


def test_network_policy_names_constant_lists_eleven_templates() -> None:
    """ARG-003 seeded 5 policies; ARG-017 added 3; ARG-027 added 3 (§15 cloud parity)."""
    assert NETWORK_POLICY_NAMES == frozenset(
        {
            "recon-passive",
            "recon-active-tcp",
            "recon-active-udp",
            "recon-smb",
            "tls-handshake",
            "oast-egress",
            "auth-bruteforce",
            "offline-no-egress",
            "cloud-aws",
            "cloud-gcp",
            "cloud-azure",
        }
    )


def test_list_templates_returns_one_per_registered_name() -> None:
    templates = list_templates()
    assert len(templates) == len(NETWORK_POLICY_NAMES)
    for tpl in templates:
        assert isinstance(tpl, NetworkPolicyTemplate)
        assert tpl.name in NETWORK_POLICY_NAMES


def test_list_templates_is_sorted_by_name() -> None:
    templates = list_templates()
    names = [tpl.name for tpl in templates]
    assert names == sorted(names)


@pytest.mark.parametrize("name", sorted(NETWORK_POLICY_NAMES))
def test_get_template_returns_frozen_template(name: str) -> None:
    tpl = get_template(name)
    assert tpl.name == name
    # ``frozen=True`` only freezes the model attributes — assigning to a
    # field MUST raise. (List contents are not deep-frozen by pydantic.)
    with pytest.raises(Exception):
        tpl.name = "tampered"


def test_get_template_unknown_name_raises_keyerror() -> None:
    with pytest.raises(KeyError, match="not registered"):
        get_template("not-a-real-policy")


@pytest.mark.parametrize(
    "name",
    sorted(NETWORK_POLICY_NAMES - {"offline-no-egress"}),
)
def test_template_has_dns_resolvers_pinned_by_default(name: str) -> None:
    """Every template except the air-gapped one pins Cloudflare + Quad9."""
    tpl = get_template(name)
    assert "1.1.1.1" in tpl.dns_resolvers
    assert "9.9.9.9" in tpl.dns_resolvers
    assert tpl.ingress_blocked is True


def test_offline_no_egress_template_has_no_resolvers_and_no_egress() -> None:
    """ARG-017 §4.13 cracking pods MUST NOT have DNS or any egress.

    Defence in depth: a malicious rule pack or wordlist cannot exfiltrate
    cracked plaintexts because the pod has no DNS, no egress IPs, and no
    open ports. Ingress remains denied like every other template.
    """
    tpl = get_template("offline-no-egress")
    assert tpl.dns_resolvers == []
    assert tpl.egress_allowlist_static == []
    assert tpl.egress_target_dynamic is False
    assert tpl.allowed_ports_tcp == []
    assert tpl.allowed_ports_udp == []
    assert tpl.port_ranges == []
    assert tpl.ingress_blocked is True


# ---------------------------------------------------------------------------
# Per-template payload contracts
# ---------------------------------------------------------------------------


def test_recon_passive_opens_only_http_https_to_world() -> None:
    tpl = get_template("recon-passive")
    assert tpl.egress_target_dynamic is False
    assert tpl.egress_allowlist_static == ["0.0.0.0/0"]
    assert tpl.allowed_ports_tcp == [80, 443]
    assert tpl.allowed_ports_udp == []


def test_recon_active_tcp_targets_dynamic_cidr_full_range() -> None:
    tpl = get_template("recon-active-tcp")
    assert tpl.egress_target_dynamic is True
    assert tpl.egress_allowlist_static == []
    assert tpl.allowed_ports_tcp == []
    assert tpl.allowed_ports_udp == []
    # Full TCP range expressed via NetworkPolicyPort.endPort.
    assert len(tpl.port_ranges) == 1
    range_ = tpl.port_ranges[0]
    assert range_.protocol == "TCP"
    assert range_.start == 1
    assert range_.end == 65_535


def test_recon_active_udp_targets_dynamic_cidr_udp_only() -> None:
    tpl = get_template("recon-active-udp")
    assert tpl.egress_target_dynamic is True
    assert tpl.allowed_ports_tcp == []
    assert tpl.allowed_ports_udp  # non-empty
    for port in tpl.allowed_ports_udp:
        assert 1 <= port <= 65_535


def test_recon_smb_opens_smb_ports_only() -> None:
    tpl = get_template("recon-smb")
    assert tpl.egress_target_dynamic is True
    assert tpl.allowed_ports_tcp == [135, 139, 445]
    assert tpl.allowed_ports_udp == [137, 138]


def test_tls_handshake_opens_only_443() -> None:
    tpl = get_template("tls-handshake")
    assert tpl.egress_target_dynamic is True
    assert tpl.allowed_ports_tcp == [443]
    assert tpl.allowed_ports_udp == []


# ---------------------------------------------------------------------------
# Manifest renderer — happy paths
# ---------------------------------------------------------------------------


def test_render_recon_passive_manifest_has_correct_shape() -> None:
    manifest = render_networkpolicy_manifest(
        get_template("recon-passive"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
    )
    assert manifest["apiVersion"] == "networking.k8s.io/v1"
    assert manifest["kind"] == "NetworkPolicy"
    assert manifest["metadata"]["name"] == "recon-passive"
    assert manifest["metadata"]["namespace"] == _DEFAULT_NAMESPACE
    assert manifest["spec"]["policyTypes"] == ["Ingress", "Egress"]
    assert manifest["spec"]["ingress"] == []  # ingress always denied
    assert manifest["spec"]["podSelector"] == {"matchLabels": _DEFAULT_POD_SELECTOR}


def test_render_dynamic_template_includes_target_cidr() -> None:
    manifest = render_networkpolicy_manifest(
        get_template("recon-active-tcp"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        target_cidr="10.0.0.0/24",
    )
    egress = manifest["spec"]["egress"]
    payload_rule = egress[0]
    assert payload_rule["to"] == [{"ipBlock": {"cidr": "10.0.0.0/24"}}]
    # Full TCP range encoded as a single endPort entry.
    assert payload_rule["ports"] == [{"protocol": "TCP", "port": 1, "endPort": 65_535}]


def test_render_dynamic_template_promotes_bare_ipv4_to_slash32() -> None:
    manifest = render_networkpolicy_manifest(
        get_template("tls-handshake"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        target_cidr="10.0.0.5",
    )
    payload_rule = manifest["spec"]["egress"][0]
    assert payload_rule["to"] == [{"ipBlock": {"cidr": "10.0.0.5/32"}}]


def test_render_dynamic_template_accepts_ipv6_target() -> None:
    manifest = render_networkpolicy_manifest(
        get_template("tls-handshake"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        target_cidr="2001:db8::1",
    )
    payload_rule = manifest["spec"]["egress"][0]
    assert payload_rule["to"] == [{"ipBlock": {"cidr": "2001:db8::1/128"}}]


def test_render_dns_egress_uses_pinned_resolvers() -> None:
    manifest = render_networkpolicy_manifest(
        get_template("recon-passive"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
    )
    # First rule = payload, second = DNS.
    dns_rule = manifest["spec"]["egress"][1]
    assert {"ipBlock": {"cidr": "1.1.1.1/32"}} in dns_rule["to"]
    assert {"ipBlock": {"cidr": "9.9.9.9/32"}} in dns_rule["to"]
    # DNS must allow both UDP/53 and TCP/53.
    protocols = {(p["protocol"], p["port"]) for p in dns_rule["ports"]}
    assert ("UDP", 53) in protocols
    assert ("TCP", 53) in protocols


def test_render_with_name_suffix_appends_to_metadata_name() -> None:
    manifest = render_networkpolicy_manifest(
        get_template("recon-passive"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        name_suffix="abcd1234",
    )
    assert manifest["metadata"]["name"] == "recon-passive-abcd1234"


def test_render_attaches_template_label_for_introspection() -> None:
    manifest = render_networkpolicy_manifest(
        get_template("recon-smb"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        target_cidr="10.0.0.0/8",
    )
    assert manifest["metadata"]["labels"]["argus.io/template"] == "recon-smb"


# ---------------------------------------------------------------------------
# Manifest renderer — failure modes
# ---------------------------------------------------------------------------


def test_render_dynamic_template_without_target_raises() -> None:
    with pytest.raises(ValueError, match="requires a target_cidr"):
        render_networkpolicy_manifest(
            get_template("recon-active-tcp"),
            namespace=_DEFAULT_NAMESPACE,
            pod_label_selector=_DEFAULT_POD_SELECTOR,
        )


def test_render_invalid_target_cidr_raises() -> None:
    with pytest.raises(ValueError, match="not a valid CIDR"):
        render_networkpolicy_manifest(
            get_template("recon-active-tcp"),
            namespace=_DEFAULT_NAMESPACE,
            pod_label_selector=_DEFAULT_POD_SELECTOR,
            target_cidr="not-an-ip",
        )


def test_render_empty_pod_label_selector_raises() -> None:
    with pytest.raises(ValueError, match="pod_label_selector"):
        render_networkpolicy_manifest(
            get_template("recon-passive"),
            namespace=_DEFAULT_NAMESPACE,
            pod_label_selector={},
        )


def test_render_static_template_ignores_target_cidr() -> None:
    """Passing a target_cidr to a static template is harmless (kept simple)."""
    manifest = render_networkpolicy_manifest(
        get_template("recon-passive"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        target_cidr="10.0.0.0/24",  # ignored
    )
    payload_rule = manifest["spec"]["egress"][0]
    # Static allow-list still wins; the wildcard peer carries the mandatory
    # private + IMDS deny exceptions injected by ARG-027 so an OSINT pod
    # cannot accidentally reach intra-cluster pods or 169.254.169.254.
    assert payload_rule["to"] == [
        {
            "ipBlock": {
                "cidr": "0.0.0.0/0",
                "except": [
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "169.254.169.254/32",
                    "169.254.0.0/16",
                ],
            }
        }
    ]


# ---------------------------------------------------------------------------
# Defence-in-depth — security invariants on EVERY rendered manifest
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(NETWORK_POLICY_NAMES))
def test_rendered_manifest_never_contains_dangerous_strings(name: str) -> None:
    """Sanity scan every rendered manifest for forbidden tokens."""
    target_cidr = "10.0.0.0/24" if get_template(name).egress_target_dynamic else None
    manifest = render_networkpolicy_manifest(
        get_template(name),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        target_cidr=target_cidr,
    )
    serialised = repr(manifest).lower()
    assert "hostpath" not in serialised
    assert "docker.sock" not in serialised
    assert "privileged" not in serialised


@pytest.mark.parametrize("name", sorted(NETWORK_POLICY_NAMES))
def test_rendered_manifest_blocks_ingress(name: str) -> None:
    """Ingress is denied for EVERY template — there is no opt-out."""
    target_cidr = "10.0.0.0/24" if get_template(name).egress_target_dynamic else None
    manifest = render_networkpolicy_manifest(
        get_template(name),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        target_cidr=target_cidr,
    )
    assert "Ingress" in manifest["spec"]["policyTypes"]
    assert manifest["spec"]["ingress"] == []


# ---------------------------------------------------------------------------
# ARG-027 — cloud-aws / cloud-gcp / cloud-azure parity templates
# ---------------------------------------------------------------------------


_CLOUD_TEMPLATES: list[str] = ["cloud-aws", "cloud-gcp", "cloud-azure"]


@pytest.mark.parametrize("name", _CLOUD_TEMPLATES)
def test_cloud_template_opens_443_to_world_minus_private(name: str) -> None:
    """Every cloud-* template exposes 0.0.0.0/0 with the private + IMDS except-list."""
    tpl = get_template(name)
    assert tpl.egress_target_dynamic is False
    assert tpl.egress_allowlist_static == ["0.0.0.0/0"]
    assert tpl.allowed_ports_tcp == [443]
    assert tpl.allowed_ports_udp == []
    assert tpl.ingress_blocked is True
    # Private + link-local + IMDS blocks are denied at template level.
    expected_excepts = {
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
    }
    assert expected_excepts.issubset(set(tpl.egress_except_cidrs))


def test_cloud_aws_fqdn_intent_lists_amazonaws_endpoints() -> None:
    tpl = get_template("cloud-aws")
    assert "*.amazonaws.com" in tpl.egress_allowed_fqdns
    assert "*.s3.amazonaws.com" in tpl.egress_allowed_fqdns


def test_cloud_gcp_fqdn_intent_lists_googleapis_endpoints() -> None:
    tpl = get_template("cloud-gcp")
    assert "*.googleapis.com" in tpl.egress_allowed_fqdns
    assert "*.gcr.io" in tpl.egress_allowed_fqdns
    assert "metadata.google.internal" in tpl.egress_allowed_fqdns


def test_cloud_azure_fqdn_intent_lists_azure_endpoints() -> None:
    tpl = get_template("cloud-azure")
    assert "*.azure.com" in tpl.egress_allowed_fqdns
    assert "*.azurewebsites.net" in tpl.egress_allowed_fqdns
    assert "*.windows.net" in tpl.egress_allowed_fqdns


@pytest.mark.parametrize("name", _CLOUD_TEMPLATES)
def test_render_cloud_template_emits_ipblock_with_excepts(name: str) -> None:
    """cloud-* render attaches the except-list to the world peer block."""
    manifest = render_networkpolicy_manifest(
        get_template(name),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
    )
    payload_rule = manifest["spec"]["egress"][0]
    peer = payload_rule["to"][0]
    assert peer["ipBlock"]["cidr"] == "0.0.0.0/0"
    assert "169.254.0.0/16" in peer["ipBlock"]["except"]
    assert "10.0.0.0/8" in peer["ipBlock"]["except"]


@pytest.mark.parametrize("name", _CLOUD_TEMPLATES)
def test_render_cloud_template_pins_dns_to_public_resolvers(name: str) -> None:
    """cloud-* templates inherit the Cloudflare/Quad9 default resolver pinning."""
    manifest = render_networkpolicy_manifest(
        get_template(name),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
    )
    dns_rule = manifest["spec"]["egress"][1]
    cidrs = {peer["ipBlock"]["cidr"] for peer in dns_rule["to"]}
    assert "1.1.1.1/32" in cidrs
    assert "9.9.9.9/32" in cidrs


@pytest.mark.parametrize("name", _CLOUD_TEMPLATES)
def test_render_cloud_template_surfaces_fqdn_intent_in_annotations(name: str) -> None:
    manifest = render_networkpolicy_manifest(
        get_template(name),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
    )
    annotations = manifest["metadata"]["annotations"]
    fqdns = annotations["argus.io/egress-fqdns"]
    expected_substring = {
        "cloud-aws": "*.amazonaws.com",
        "cloud-gcp": "*.googleapis.com",
        "cloud-azure": "*.azure.com",
    }[name]
    assert expected_substring in fqdns


def test_render_cloud_azure_blocks_imds_via_except_list() -> None:
    """Azure IMDS at 169.254.169.254 must NOT be reachable from the cloud-azure pod."""
    manifest = render_networkpolicy_manifest(
        get_template("cloud-azure"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
    )
    peer = manifest["spec"]["egress"][0]["to"][0]
    excepts = peer["ipBlock"]["except"]
    # 169.254.0.0/16 is broader than 169.254.169.254/32 → IMDS denied.
    assert "169.254.0.0/16" in excepts


# ---------------------------------------------------------------------------
# ARG-027 — dns_resolvers_override consumption + validation
# ---------------------------------------------------------------------------


def test_dns_resolvers_override_replaces_template_defaults() -> None:
    """A non-empty override replaces (not augments) template DNS pinning."""
    manifest = render_networkpolicy_manifest(
        get_template("recon-passive"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        dns_resolvers_override=["8.8.8.8", "8.8.4.4"],
    )
    dns_rule = manifest["spec"]["egress"][1]
    cidrs = {peer["ipBlock"]["cidr"] for peer in dns_rule["to"]}
    assert cidrs == {"8.8.8.8/32", "8.8.4.4/32"}
    # Template defaults must be ABSENT (replace, not augment).
    assert "1.1.1.1/32" not in cidrs
    assert "9.9.9.9/32" not in cidrs


def test_empty_dns_resolvers_override_keeps_template_defaults() -> None:
    """An empty override list preserves the template's pinned resolvers."""
    manifest = render_networkpolicy_manifest(
        get_template("recon-passive"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        dns_resolvers_override=[],
    )
    dns_rule = manifest["spec"]["egress"][1]
    cidrs = {peer["ipBlock"]["cidr"] for peer in dns_rule["to"]}
    assert "1.1.1.1/32" in cidrs
    assert "9.9.9.9/32" in cidrs


def test_dns_resolvers_override_dedup_preserves_first_seen_order() -> None:
    manifest = render_networkpolicy_manifest(
        get_template("recon-passive"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        dns_resolvers_override=["8.8.8.8", "8.8.4.4", "8.8.8.8"],
    )
    dns_rule = manifest["spec"]["egress"][1]
    ordered = [peer["ipBlock"]["cidr"] for peer in dns_rule["to"]]
    assert ordered == ["8.8.8.8/32", "8.8.4.4/32"]


@pytest.mark.parametrize(
    "bad_resolver",
    [
        "10.0.0.5",
        "10.0.0.0/24",
        "172.16.5.5",
        "192.168.1.1",
        "169.254.169.254",
        "169.254.1.5",
    ],
)
def test_dns_resolvers_override_rejects_private_or_imds(bad_resolver: str) -> None:
    with pytest.raises(ValueError, match="private / IMDS deny range"):
        render_networkpolicy_manifest(
            get_template("recon-passive"),
            namespace=_DEFAULT_NAMESPACE,
            pod_label_selector=_DEFAULT_POD_SELECTOR,
            dns_resolvers_override=[bad_resolver],
        )


def test_dns_resolvers_override_rejects_fqdn() -> None:
    """DNS resolver pinning must be IP-only (NetworkPolicy v1 ipBlock limit)."""
    with pytest.raises(ValueError, match="must be a valid IP / CIDR"):
        render_networkpolicy_manifest(
            get_template("recon-passive"),
            namespace=_DEFAULT_NAMESPACE,
            pod_label_selector=_DEFAULT_POD_SELECTOR,
            dns_resolvers_override=["dns.google"],
        )


def test_dns_resolvers_override_rejects_garbage_input() -> None:
    with pytest.raises(ValueError, match="must be a valid IP / CIDR"):
        render_networkpolicy_manifest(
            get_template("recon-passive"),
            namespace=_DEFAULT_NAMESPACE,
            pod_label_selector=_DEFAULT_POD_SELECTOR,
            dns_resolvers_override=["8.8.8.8", "not-a-real-ip"],
        )


# ---------------------------------------------------------------------------
# ARG-027 — egress_allowlist_override consumption + validation
# ---------------------------------------------------------------------------


def test_egress_allowlist_override_unions_with_template_static() -> None:
    """Override entries are added to the template's static allowlist (not replace)."""
    manifest = render_networkpolicy_manifest(
        get_template("cloud-aws"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        egress_allowlist_override=["198.51.100.0/24"],
    )
    payload_rule = manifest["spec"]["egress"][0]
    cidrs = [peer["ipBlock"]["cidr"] for peer in payload_rule["to"]]
    # Template static (0.0.0.0/0) MUST still be present (additive, not replace).
    assert "0.0.0.0/0" in cidrs
    # Override entry appended.
    assert "198.51.100.0/24" in cidrs


def test_egress_allowlist_override_with_dynamic_target_appends_extra_peer() -> None:
    """Dynamic-target templates also accept extra IP overrides."""
    manifest = render_networkpolicy_manifest(
        get_template("recon-active-tcp"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        target_cidr="203.0.113.0/24",
        egress_allowlist_override=["198.51.100.10/32"],
    )
    payload_rule = manifest["spec"]["egress"][0]
    cidrs = {peer["ipBlock"]["cidr"] for peer in payload_rule["to"]}
    assert "203.0.113.0/24" in cidrs
    assert "198.51.100.10/32" in cidrs


def test_egress_allowlist_override_fqdn_lands_in_annotation_only() -> None:
    """FQDN entries surface as annotations; ipBlock list stays IP-only."""
    manifest = render_networkpolicy_manifest(
        get_template("cloud-aws"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        egress_allowlist_override=["api.example.com", "*.tenant.example.com"],
    )
    payload_rule = manifest["spec"]["egress"][0]
    for peer in payload_rule["to"]:
        cidr = peer["ipBlock"]["cidr"]
        # The CIDR field must remain a syntactically valid IP literal.
        assert "example.com" not in cidr
    annotations = manifest["metadata"]["annotations"]["argus.io/egress-fqdns"]
    assert "api.example.com" in annotations
    assert "*.tenant.example.com" in annotations


@pytest.mark.parametrize(
    "bad_entry",
    [
        "10.0.0.5",
        "10.0.0.0/24",
        "172.16.0.0/12",
        "172.20.5.5",
        "192.168.1.1",
        "169.254.169.254",
        "169.254.169.254/32",
        "169.254.1.5",
    ],
)
def test_egress_allowlist_override_rejects_private_or_imds(bad_entry: str) -> None:
    with pytest.raises(ValueError, match="private / IMDS deny range"):
        render_networkpolicy_manifest(
            get_template("cloud-aws"),
            namespace=_DEFAULT_NAMESPACE,
            pod_label_selector=_DEFAULT_POD_SELECTOR,
            egress_allowlist_override=[bad_entry],
        )


def test_egress_allowlist_override_rejects_garbage_input() -> None:
    """Anything that's neither a valid CIDR nor a FQDN-like string is rejected."""
    with pytest.raises(ValueError, match="not a valid CIDR / IP / FQDN"):
        render_networkpolicy_manifest(
            get_template("cloud-aws"),
            namespace=_DEFAULT_NAMESPACE,
            pod_label_selector=_DEFAULT_POD_SELECTOR,
            egress_allowlist_override=["198.51.100.5/99"],
        )


def test_egress_allowlist_override_zero_zero_carries_mandatory_deny_excepts() -> None:
    """The wildcard 0.0.0.0/0 is permitted but must auto-attach the deny list.

    40+ recon / OSINT tool YAMLs use ``egress_allowlist: ['0.0.0.0/0']`` as
    the canonical "permit all internet" intent. ARG-027 keeps that working
    AND tightens the security guarantee: every wildcard peer is rendered
    with the private + IMDS deny exceptions, so a misconfigured override
    cannot widen the policy onto intra-cluster pods or 169.254.169.254.
    """
    manifest = render_networkpolicy_manifest(
        get_template("recon-active-tcp"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        target_cidr="203.0.113.0/24",
        egress_allowlist_override=["0.0.0.0/0"],
    )
    payload_rule = manifest["spec"]["egress"][0]
    wildcard_peers = [
        peer for peer in payload_rule["to"] if peer["ipBlock"]["cidr"] == "0.0.0.0/0"
    ]
    assert len(wildcard_peers) == 1
    excepts = wildcard_peers[0]["ipBlock"].get("except", [])
    for must_block in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.169.254/32",
        "169.254.0.0/16",
    ):
        assert must_block in excepts, (
            f"wildcard peer must auto-attach {must_block} so override cannot "
            "leak onto intra-cluster pods or the cloud metadata service"
        )


def test_egress_allowlist_override_dedup_preserves_order() -> None:
    """Duplicate entries collapse to one peer, first-seen order preserved."""
    manifest = render_networkpolicy_manifest(
        get_template("recon-active-tcp"),
        namespace=_DEFAULT_NAMESPACE,
        pod_label_selector=_DEFAULT_POD_SELECTOR,
        target_cidr="203.0.113.0/24",
        egress_allowlist_override=[
            "198.51.100.10/32",
            "198.51.100.10/32",
            "198.51.100.20/32",
        ],
    )
    payload_rule = manifest["spec"]["egress"][0]
    cidrs = [peer["ipBlock"]["cidr"] for peer in payload_rule["to"]]
    # Target + 2 unique overrides == 3 peers (de-duplicated).
    assert cidrs == ["203.0.113.0/24", "198.51.100.10/32", "198.51.100.20/32"]


def test_egress_allowlist_override_rejects_empty_string_entry() -> None:
    with pytest.raises(ValueError, match="non-empty string"):
        render_networkpolicy_manifest(
            get_template("cloud-aws"),
            namespace=_DEFAULT_NAMESPACE,
            pod_label_selector=_DEFAULT_POD_SELECTOR,
            egress_allowlist_override=[""],
        )
