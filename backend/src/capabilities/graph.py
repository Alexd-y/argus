"""Capability knowledge graph — seeded taxonomy and query helpers (Stage E)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Final

from src.capabilities.schemas import (
    CapabilityApplicability,
    CapabilityEdge,
    CapabilityEdgeType,
    CapabilityFamily,
    CapabilityNode,
    ProductionRisk,
)
from src.eval.rates import record_plan_step

_QUICK_MODES: Final[tuple[str, ...]] = ("production", "lab_unrestricted", "quick")
_FULL_MODES: Final[tuple[str, ...]] = ("production", "lab_unrestricted")
_ALWAYS_COLLECTIONS: Final[tuple[str, ...]] = (
    "argus_product",
    "episodic_validated",
    "capability_graph",
)


@dataclass(frozen=True)
class CapabilityPlanStep:
    node_id: str
    tools: tuple[str, ...]
    collections: tuple[str, ...]
    prerequisite_ids: tuple[str, ...]
    completed: bool = False


def _node(
    node_id: str,
    family: CapabilityFamily,
    *,
    labels: tuple[str, ...] = (),
    asset_types: tuple[str, ...] = (),
    production_risk: ProductionRisk = ProductionRisk.ACTIVE,
    allowed_phases: tuple[str, ...] = (),
    evidence_types: tuple[str, ...] = (),
    tools: tuple[str, ...] = (),
    attack_techniques: tuple[str, ...] = (),
    training_only: bool = False,
    quick_eligible: bool = False,
    estimated_cost_seconds: int = 30,
    applicability: CapabilityApplicability | None = None,
) -> CapabilityNode:
    return CapabilityNode(
        id=node_id,
        family=family,
        labels=labels,
        asset_types=asset_types,
        execution_modes=_QUICK_MODES if quick_eligible else _FULL_MODES,
        production_risk=production_risk,
        allowed_phases=allowed_phases,
        evidence_types=evidence_types,
        tools=tools,
        attack_techniques=attack_techniques,
        training_only=training_only,
        quick_eligible=quick_eligible,
        estimated_cost_seconds=estimated_cost_seconds,
        applicability=applicability or CapabilityApplicability(),
    )


_SEED_NODES: Final[tuple[CapabilityNode, ...]] = (
    _node(
        "web.application.forms.input_validation",
        CapabilityFamily.WEB_APPLICATION,
        labels=("Form fuzzing", "Input validation"),
        asset_types=("web_app", "api"),
        allowed_phases=("quick_fuzz", "vuln_analysis"),
        evidence_types=("http_response", "request_response"),
        tools=("ffuf", "dalfox"),
        attack_techniques=("T1190",),
        quick_eligible=False,
        estimated_cost_seconds=120,
        applicability=CapabilityApplicability(protocols=("http", "https")),
    ),
    _node(
        "web.application.api.rest",
        CapabilityFamily.WEB_APPLICATION,
        labels=("REST API", "OpenAPI surface"),
        asset_types=("api", "web_app"),
        allowed_phases=("source_analysis", "recon", "vuln_analysis"),
        evidence_types=("openapi_spec", "http_response"),
        tools=("nuclei", "ffuf"),
        quick_eligible=True,
        estimated_cost_seconds=25,
        applicability=CapabilityApplicability(
            protocols=("http", "https"),
            require_api_hints=True,
        ),
    ),
    _node(
        "web.application.auth.session",
        CapabilityFamily.WEB_APPLICATION,
        labels=("Session management", "Auth bypass"),
        asset_types=("web_app", "api"),
        production_risk=ProductionRisk.INTRUSIVE,
        allowed_phases=("vuln_analysis", "exploitation"),
        evidence_types=("http_response", "cookie_metadata"),
        tools=("nuclei", "dalfox"),
        attack_techniques=("T1550",),
        quick_eligible=True,
        estimated_cost_seconds=35,
        applicability=CapabilityApplicability(protocols=("http", "https")),
    ),
    _node(
        "windows.server.ad.enumeration",
        CapabilityFamily.WINDOWS_SERVER,
        labels=("AD enumeration", "Domain services"),
        asset_types=("ad_domain", "windows_host"),
        production_risk=ProductionRisk.INTRUSIVE,
        allowed_phases=("recon", "threat_modeling", "vuln_analysis"),
        evidence_types=("command_output", "ldap_result"),
        tools=("enum4linux-ng", "crackmapexec"),
        attack_techniques=("T1087", "T1069"),
        quick_eligible=True,
        estimated_cost_seconds=45,
        applicability=CapabilityApplicability(
            services=("ldap", "kerberos", "smb"),
            asset_types=("ad_domain", "windows_host"),
        ),
    ),
    _node(
        "windows.server.gpo.misconfig",
        CapabilityFamily.WINDOWS_SERVER,
        labels=("GPO misconfiguration",),
        asset_types=("ad_domain", "windows_host"),
        production_risk=ProductionRisk.INTRUSIVE,
        allowed_phases=("vuln_analysis", "post_exploitation"),
        evidence_types=("command_output", "registry_snapshot"),
        tools=("crackmapexec",),
        attack_techniques=("T1484",),
        quick_eligible=False,
        estimated_cost_seconds=60,
    ),
    _node(
        "linux.system.services.hardening",
        CapabilityFamily.LINUX_SYSTEM,
        labels=("Service enumeration", "Hardening gaps"),
        asset_types=("linux_host",),
        allowed_phases=("recon", "vuln_analysis"),
        evidence_types=("command_output", "package_manifest"),
        tools=("nmap", "nuclei"),
        quick_eligible=True,
        estimated_cost_seconds=40,
        applicability=CapabilityApplicability(
            asset_types=("linux_host",),
            services=("ssh", "linux"),
        ),
    ),
    _node(
        "linux.system.users.permissions",
        CapabilityFamily.LINUX_SYSTEM,
        labels=("Users/groups", "File permissions"),
        asset_types=("linux_host",),
        allowed_phases=("vuln_analysis", "post_exploitation"),
        evidence_types=("command_output",),
        tools=("nmap",),
        attack_techniques=("T1222",),
        quick_eligible=False,
        estimated_cost_seconds=50,
    ),
    _node(
        "network.attack_paths.kerberos.ticket_operations",
        CapabilityFamily.NETWORK_ATTACK_PATHS,
        labels=("Kerberoasting", "Pass-the-Ticket"),
        asset_types=("ad_domain", "windows_host"),
        production_risk=ProductionRisk.INTRUSIVE,
        allowed_phases=(
            "threat_modeling",
            "vuln_analysis",
            "exploitation",
            "post_exploitation",
        ),
        evidence_types=("command_output", "ticket_metadata", "authentication_event"),
        tools=("impacket", "crackmapexec"),
        attack_techniques=("T1558.003", "T1550.003"),
        quick_eligible=False,
        estimated_cost_seconds=90,
    ),
    _node(
        "network.attack_paths.lateral.smb_relay",
        CapabilityFamily.NETWORK_ATTACK_PATHS,
        labels=("SMB relay", "Lateral movement"),
        asset_types=("windows_host", "ad_domain"),
        production_risk=ProductionRisk.INTRUSIVE,
        allowed_phases=("exploitation", "post_exploitation"),
        evidence_types=("command_output", "authentication_event"),
        tools=("impacket",),
        attack_techniques=("T1557",),
        quick_eligible=False,
        estimated_cost_seconds=80,
    ),
    _node(
        "reverse_engineering.static.binary_analysis",
        CapabilityFamily.REVERSE_ENGINEERING,
        labels=("Static analysis", "IDA workflow"),
        asset_types=("binary", "malware_sample"),
        production_risk=ProductionRisk.PASSIVE,
        allowed_phases=("source_analysis", "vuln_analysis"),
        evidence_types=("disassembly", "artifact_hash"),
        tools=("ghidra", "ida"),
        attack_techniques=("T1027",),
        quick_eligible=False,
        estimated_cost_seconds=300,
    ),
    _node(
        "reverse_engineering.dynamic.debugging",
        CapabilityFamily.REVERSE_ENGINEERING,
        labels=("Dynamic debugging", "x64dbg"),
        asset_types=("binary", "malware_sample"),
        allowed_phases=("vuln_analysis", "post_exploitation"),
        evidence_types=("debugger_trace", "artifact_hash"),
        tools=("x64dbg", "gdb"),
        quick_eligible=False,
        estimated_cost_seconds=240,
    ),
    _node(
        "privilege_escalation.linux.sudo_misconfig",
        CapabilityFamily.PRIVILEGE_ESCALATION_LINUX,
        labels=("Sudo misconfiguration",),
        asset_types=("linux_host",),
        production_risk=ProductionRisk.INTRUSIVE,
        allowed_phases=("exploitation", "post_exploitation"),
        evidence_types=("command_output",),
        tools=("linpeas",),
        attack_techniques=("T1548.003",),
        quick_eligible=False,
        estimated_cost_seconds=90,
    ),
    _node(
        "privilege_escalation.linux.scheduled_tasks",
        CapabilityFamily.PRIVILEGE_ESCALATION_LINUX,
        labels=("Cron abuse", "Scheduled tasks"),
        asset_types=("linux_host",),
        production_risk=ProductionRisk.INTRUSIVE,
        allowed_phases=("post_exploitation",),
        evidence_types=("command_output", "file_metadata"),
        attack_techniques=("T1053.003",),
        quick_eligible=False,
        estimated_cost_seconds=70,
    ),
    _node(
        "privilege_escalation.windows.unquoted_service",
        CapabilityFamily.PRIVILEGE_ESCALATION_WINDOWS,
        labels=("Unquoted service path",),
        asset_types=("windows_host",),
        production_risk=ProductionRisk.INTRUSIVE,
        allowed_phases=("post_exploitation",),
        evidence_types=("registry_snapshot", "command_output"),
        attack_techniques=("T1574.009",),
        quick_eligible=False,
        estimated_cost_seconds=70,
    ),
    _node(
        "privilege_escalation.windows.dll_hijack",
        CapabilityFamily.PRIVILEGE_ESCALATION_WINDOWS,
        labels=("DLL hijack",),
        asset_types=("windows_host",),
        production_risk=ProductionRisk.INTRUSIVE,
        allowed_phases=("post_exploitation",),
        evidence_types=("file_metadata", "command_output"),
        attack_techniques=("T1574.001",),
        quick_eligible=False,
        estimated_cost_seconds=70,
    ),
    _node(
        "training.certification.oscp.web_exploitation",
        CapabilityFamily.TRAINING_CERTIFICATION,
        labels=("OSCP web lab", "Training module"),
        asset_types=("training_target",),
        allowed_phases=("vuln_analysis", "exploitation"),
        evidence_types=("lab_writeup",),
        training_only=True,
        quick_eligible=False,
        estimated_cost_seconds=120,
    ),
    _node(
        "training.certification.crto.kerberos_chain",
        CapabilityFamily.TRAINING_CERTIFICATION,
        labels=("CRTO Kerberos chain", "Training module"),
        asset_types=("training_target", "ad_domain"),
        allowed_phases=("threat_modeling", "exploitation", "post_exploitation"),
        evidence_types=("lab_writeup", "ticket_metadata"),
        training_only=True,
        quick_eligible=False,
        estimated_cost_seconds=180,
    ),
    _node(
        "foundations.networking.dns_exposure",
        CapabilityFamily.FOUNDATIONS_NETWORKING,
        labels=("DNS", "Routing", "Name exposure"),
        asset_types=("web_app", "host", "dns"),
        production_risk=ProductionRisk.PASSIVE,
        allowed_phases=("recon", "vuln_analysis"),
        evidence_types=("dns_record", "http_response"),
        tools=("nuclei",),
        quick_eligible=True,
        estimated_cost_seconds=20,
        applicability=CapabilityApplicability(asset_types=("web_app", "host", "dns")),
    ),
    _node(
        "foundations.networking.exposed_services",
        CapabilityFamily.FOUNDATIONS_NETWORKING,
        labels=("Exposed services", "Priority ports"),
        asset_types=("host", "web_app", "linux_host", "windows_host"),
        production_risk=ProductionRisk.PASSIVE,
        allowed_phases=("recon",),
        evidence_types=("port_scan", "banner"),
        tools=("nmap", "nuclei"),
        quick_eligible=True,
        estimated_cost_seconds=25,
        applicability=CapabilityApplicability(
            asset_types=("host", "web_app", "linux_host", "windows_host"),
        ),
    ),
    _node(
        "web.application.tls.posture",
        CapabilityFamily.WEB_APPLICATION,
        labels=("TLS", "Security headers"),
        asset_types=("web_app", "api"),
        production_risk=ProductionRisk.PASSIVE,
        allowed_phases=("recon", "vuln_analysis"),
        evidence_types=("tls_handshake", "http_response"),
        tools=("testssl", "nuclei"),
        quick_eligible=True,
        estimated_cost_seconds=20,
        applicability=CapabilityApplicability(
            protocols=("https", "ssl", "tls"),
            require_tls=True,
        ),
    ),
    _node(
        "web.application.exposure.sensitive_files",
        CapabilityFamily.WEB_APPLICATION,
        labels=("Sensitive file exposure", "Debug endpoints"),
        asset_types=("web_app", "api"),
        production_risk=ProductionRisk.PASSIVE,
        allowed_phases=("recon", "vuln_analysis"),
        evidence_types=("http_response",),
        tools=("nuclei",),
        quick_eligible=True,
        estimated_cost_seconds=25,
        applicability=CapabilityApplicability(protocols=("http", "https")),
    ),
    _node(
        "web.application.cve.known_product",
        CapabilityFamily.WEB_APPLICATION,
        labels=("Known product CVE", "Technology CVE"),
        asset_types=("web_app", "api"),
        allowed_phases=("vuln_analysis",),
        evidence_types=("http_response", "nuclei_match"),
        tools=("nuclei",),
        quick_eligible=True,
        estimated_cost_seconds=30,
        applicability=CapabilityApplicability(protocols=("http", "https")),
    ),
    _node(
        "web.application.cms.fingerprint",
        CapabilityFamily.WEB_APPLICATION,
        labels=("CMS", "Framework fingerprint"),
        asset_types=("web_app",),
        production_risk=ProductionRisk.PASSIVE,
        allowed_phases=("recon",),
        evidence_types=("http_response", "tech_fingerprint"),
        tools=("whatweb", "nuclei"),
        quick_eligible=True,
        estimated_cost_seconds=20,
        applicability=CapabilityApplicability(protocols=("http", "https")),
    ),
    _node(
        "linux.system.misconfig.common",
        CapabilityFamily.LINUX_SYSTEM,
        labels=("Linux misconfiguration", "Exposed daemons"),
        asset_types=("linux_host",),
        allowed_phases=("recon", "vuln_analysis"),
        evidence_types=("command_output", "http_response"),
        tools=("nuclei", "nmap"),
        quick_eligible=True,
        estimated_cost_seconds=35,
        applicability=CapabilityApplicability(
            asset_types=("linux_host",),
            services=("ssh", "linux"),
        ),
    ),
    _node(
        "cloud.exposure.storage_admin_debug",
        CapabilityFamily.CLOUD_EXPOSURE,
        labels=("Cloud storage", "Admin", "Debug exposure"),
        asset_types=("web_app", "cloud_asset"),
        production_risk=ProductionRisk.PASSIVE,
        allowed_phases=("recon", "vuln_analysis"),
        evidence_types=("http_response", "cloud_metadata"),
        tools=("nuclei",),
        quick_eligible=True,
        estimated_cost_seconds=25,
        applicability=CapabilityApplicability(
            protocols=("http", "https"),
            require_cloud_exposure=True,
        ),
    ),
    _node(
        "malware_analysis.classification.artifact_only",
        CapabilityFamily.MALWARE_ANALYSIS,
        labels=("Malware classification", "Artifact triage"),
        asset_types=("binary", "malware_sample"),
        production_risk=ProductionRisk.PASSIVE,
        allowed_phases=("source_analysis",),
        evidence_types=("artifact_hash", "classifier_label"),
        tools=(),
        quick_eligible=True,
        estimated_cost_seconds=15,
        applicability=CapabilityApplicability(
            asset_types=("binary", "malware_sample"),
        ),
    ),
    _node(
        "nuclei.protocol.http",
        CapabilityFamily.NUCLEI_PROTOCOL,
        labels=("Nuclei HTTP family",),
        asset_types=("web_app", "api"),
        production_risk=ProductionRisk.PASSIVE,
        allowed_phases=("vuln_analysis",),
        evidence_types=("nuclei_match", "http_response"),
        tools=("nuclei",),
        quick_eligible=True,
        estimated_cost_seconds=30,
        applicability=CapabilityApplicability(protocols=("http", "https")),
    ),
    _node(
        "nuclei.protocol.ssl",
        CapabilityFamily.NUCLEI_PROTOCOL,
        labels=("Nuclei SSL/TLS family",),
        asset_types=("web_app", "api"),
        production_risk=ProductionRisk.PASSIVE,
        allowed_phases=("vuln_analysis",),
        evidence_types=("nuclei_match", "tls_handshake"),
        tools=("nuclei",),
        quick_eligible=True,
        estimated_cost_seconds=20,
        applicability=CapabilityApplicability(
            protocols=("https", "ssl", "tls"),
            require_tls=True,
        ),
    ),
    _node(
        "nuclei.protocol.dns",
        CapabilityFamily.NUCLEI_PROTOCOL,
        labels=("Nuclei DNS family",),
        asset_types=("web_app", "host", "dns"),
        production_risk=ProductionRisk.PASSIVE,
        allowed_phases=("recon", "vuln_analysis"),
        evidence_types=("nuclei_match", "dns_record"),
        tools=("nuclei",),
        quick_eligible=True,
        estimated_cost_seconds=15,
        applicability=CapabilityApplicability(asset_types=("web_app", "host", "dns")),
    ),
)

_SEED_EDGES: Final[tuple[CapabilityEdge, ...]] = (
    CapabilityEdge(
        source_id="web.application.api.rest",
        target_id="web.application.forms.input_validation",
        edge_type=CapabilityEdgeType.PREREQUISITE,
    ),
    CapabilityEdge(
        source_id="windows.server.ad.enumeration",
        target_id="network.attack_paths.kerberos.ticket_operations",
        edge_type=CapabilityEdgeType.PREREQUISITE,
    ),
    CapabilityEdge(
        source_id="network.attack_paths.kerberos.ticket_operations",
        target_id="network.attack_paths.lateral.smb_relay",
        edge_type=CapabilityEdgeType.PART_OF,
    ),
    CapabilityEdge(
        source_id="linux.system.services.hardening",
        target_id="privilege_escalation.linux.sudo_misconfig",
        edge_type=CapabilityEdgeType.ENABLES_DETECTION,
    ),
    CapabilityEdge(
        source_id="privilege_escalation.linux.sudo_misconfig",
        target_id="privilege_escalation.linux.scheduled_tasks",
        edge_type=CapabilityEdgeType.PART_OF,
    ),
    CapabilityEdge(
        source_id="windows.server.ad.enumeration",
        target_id="privilege_escalation.windows.unquoted_service",
        edge_type=CapabilityEdgeType.APPLIES_TO_ASSET,
    ),
    CapabilityEdge(
        source_id="reverse_engineering.static.binary_analysis",
        target_id="reverse_engineering.dynamic.debugging",
        edge_type=CapabilityEdgeType.PREREQUISITE,
    ),
    CapabilityEdge(
        source_id="training.certification.oscp.web_exploitation",
        target_id="web.application.forms.input_validation",
        edge_type=CapabilityEdgeType.MAPPED_TO_ATTACK,
    ),
    CapabilityEdge(
        source_id="training.certification.crto.kerberos_chain",
        target_id="network.attack_paths.kerberos.ticket_operations",
        edge_type=CapabilityEdgeType.MAPPED_TO_ATTACK,
    ),
    CapabilityEdge(
        source_id="web.application.cms.fingerprint",
        target_id="web.application.cve.known_product",
        edge_type=CapabilityEdgeType.ENABLES_DETECTION,
    ),
    CapabilityEdge(
        source_id="nuclei.protocol.http",
        target_id="web.application.exposure.sensitive_files",
        edge_type=CapabilityEdgeType.ENABLES_DETECTION,
    ),
    CapabilityEdge(
        source_id="web.application.tls.posture",
        target_id="nuclei.protocol.ssl",
        edge_type=CapabilityEdgeType.PART_OF,
    ),
)


class CapabilityGraph:
    """In-memory capability graph backed by the seeded taxonomy."""

    def __init__(
        self,
        nodes: Iterable[CapabilityNode] | None = None,
        edges: Iterable[CapabilityEdge] | None = None,
    ) -> None:
        node_list = tuple(nodes) if nodes is not None else _SEED_NODES
        edge_list = tuple(edges) if edges is not None else _SEED_EDGES
        self._nodes: dict[str, CapabilityNode] = {n.id: n for n in node_list}
        if len(self._nodes) != len(node_list):
            raise ValueError("duplicate capability node ids in graph seed")
        self._edges: list[CapabilityEdge] = []
        self._outgoing: dict[str, list[CapabilityEdge]] = defaultdict(list)
        self._incoming: dict[str, list[CapabilityEdge]] = defaultdict(list)
        for edge in edge_list:
            if edge.source_id not in self._nodes or edge.target_id not in self._nodes:
                raise ValueError(
                    f"edge references unknown node: {edge.source_id} -> {edge.target_id}"
                )
            self._edges.append(edge)
            self._outgoing[edge.source_id].append(edge)
            self._incoming[edge.target_id].append(edge)

    @property
    def nodes(self) -> tuple[CapabilityNode, ...]:
        return tuple(self._nodes.values())

    @property
    def edges(self) -> tuple[CapabilityEdge, ...]:
        return tuple(self._edges)

    def get_node(self, node_id: str) -> CapabilityNode | None:
        return self._nodes.get(node_id)

    def nodes_for_family(self, family: CapabilityFamily | str) -> tuple[CapabilityNode, ...]:
        key = family.value if isinstance(family, CapabilityFamily) else str(family)
        return tuple(n for n in self._nodes.values() if str(n.family) == key)

    def training_nodes(self) -> tuple[CapabilityNode, ...]:
        return tuple(n for n in self._nodes.values() if n.training_only)

    def quick_eligible_nodes(self) -> tuple[CapabilityNode, ...]:
        """Deterministic: eligible nodes sorted by id."""
        return tuple(
            node
            for node in sorted(self._nodes.values(), key=lambda item: item.id)
            if node.quick_eligible
        )

    def prerequisites(self, node_id: str) -> tuple[CapabilityNode, ...]:
        prereq_ids = [
            e.source_id
            for e in self._incoming.get(node_id, ())
            if e.edge_type is CapabilityEdgeType.PREREQUISITE
        ]
        return tuple(self._nodes[i] for i in prereq_ids if i in self._nodes)

    def outgoing(
        self,
        node_id: str,
        *,
        edge_type: CapabilityEdgeType | None = None,
    ) -> Iterator[CapabilityEdge]:
        for edge in self._outgoing.get(node_id, ()):
            if edge_type is None or edge.edge_type is edge_type:
                yield edge

    def nodes_for_phase(
        self,
        phase: str,
        mode: str,
        asset_types: Sequence[str] = (),
    ) -> tuple[CapabilityNode, ...]:
        phase_key = (phase or "").strip().lower()
        mode_key = (mode or "").strip().lower()
        wanted_assets = {item.strip().lower() for item in asset_types if item.strip()}
        selected: list[CapabilityNode] = []
        for node in self._nodes.values():
            if node.training_only and mode_key != "lab_unrestricted":
                continue
            if node.allowed_phases and phase_key not in {
                item.lower() for item in node.allowed_phases
            }:
                continue
            if node.execution_modes and mode_key not in {
                item.lower() for item in node.execution_modes
            }:
                continue
            if wanted_assets and node.asset_types:
                node_assets = {item.lower() for item in node.asset_types}
                if not wanted_assets.intersection(node_assets):
                    continue
            selected.append(node)
        return tuple(sorted(selected, key=lambda item: item.id))

    def collections_for_phase(
        self,
        phase: str,
        mode: str,
        asset_types: Sequence[str] = (),
    ) -> tuple[str, ...]:
        names: set[str] = set(_ALWAYS_COLLECTIONS)
        for node in self.nodes_for_phase(phase, mode, asset_types):
            names.update(self.collections_for_node(node))
        return tuple(sorted(names))

    def collections_for_node(self, node: CapabilityNode) -> tuple[str, ...]:
        names: set[str] = set(_ALWAYS_COLLECTIONS)
        tools = {item.lower() for item in node.tools}
        if tools:
            names.add("tool_catalog")
        if "nuclei" in tools:
            names.add("detection_templates")
        if tools.intersection({"dalfox", "ffuf", "sqlmap", "commix", "xsstrike"}):
            names.add("payload_catalog")
        if node.evidence_types:
            names.add("scan_evidence")
        node_id = node.id.lower()
        if "cve" in node_id or "known_product" in node_id:
            names.add("public_intel")
            names.add("finding_history")
        if "api" in node_id or "openapi" in " ".join(node.labels).lower():
            names.add("api_surface")
            names.add("codebase")
        if "code" in node_id or "binary" in node_id:
            names.add("codebase")
        return tuple(sorted(names))

    def plan_steps(
        self,
        phase: str,
        mode: str,
        asset_types: Sequence[str] = (),
        *,
        completed_node_ids: Sequence[str] = (),
        record_eval: bool = True,
    ) -> tuple[CapabilityPlanStep, ...]:
        ordered = self._order_nodes(self.nodes_for_phase(phase, mode, asset_types))
        completed = {item.strip() for item in completed_node_ids if item.strip()}
        steps: list[CapabilityPlanStep] = []
        selected_ids = {node.id for node in ordered}
        for node in ordered:
            prereq_ids = tuple(
                item.id
                for item in self.prerequisites(node.id)
                if item.id in selected_ids
            )
            step_completed = node.id in completed
            if record_eval:
                record_plan_step(completed=step_completed)
            steps.append(
                CapabilityPlanStep(
                    node_id=node.id,
                    tools=tuple(node.tools),
                    collections=self.collections_for_node(node),
                    prerequisite_ids=prereq_ids,
                    completed=step_completed,
                )
            )
        return tuple(steps)

    def _order_nodes(
        self,
        nodes: Sequence[CapabilityNode],
    ) -> tuple[CapabilityNode, ...]:
        remaining = {node.id: node for node in nodes}
        selected_ids = set(remaining)
        ordered: list[CapabilityNode] = []
        while remaining:
            ready = [
                node
                for node in remaining.values()
                if all(
                    prereq.id not in remaining
                    for prereq in self.prerequisites(node.id)
                    if prereq.id in selected_ids
                )
            ]
            if not ready:
                ordered.extend(sorted(remaining.values(), key=lambda item: item.id))
                break
            pick = min(ready, key=lambda item: item.id)
            ordered.append(pick)
            del remaining[pick.id]
        return tuple(ordered)


def default_capability_graph() -> CapabilityGraph:
    """Return the canonical seeded capability graph."""
    return CapabilityGraph()


__all__ = [
    "_SEED_EDGES",
    "_SEED_NODES",
    "CapabilityGraph",
    "CapabilityPlanStep",
    "default_capability_graph",
]
