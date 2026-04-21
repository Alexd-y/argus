"""Generate ``docs/tool-catalog.md`` from the signed ARGUS tool registry.

Reads every YAML descriptor under ``backend/config/tools/`` through
:class:`src.sandbox.tool_registry.ToolRegistry` (Ed25519-verified), then
renders a deterministic markdown reference: header, per-phase tables sorted
by ``tool_id``, security-invariants block, coverage matrix, and a path-list
of related modules.

The committed ``docs/tool-catalog.md`` is the byte-for-byte output of this
script.  Re-running it after editing a YAML is the *only* supported way to
update the doc; CI guards drift via the parametrised coverage test in
``backend/tests/test_tool_catalog_coverage.py`` and the ``--check`` mode here.

CLI (run from ``backend/``):

    python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md
    python -m scripts.docs_tool_catalog --check          # CI drift guard

Exit codes:
    0 — markdown rendered (or ``--check`` confirmed in-sync)
    1 — registry load failed (signature, schema, allow-list, …) or drift in
        ``--check`` mode; one-line JSON record on stderr.
    2 — output path could not be written / read (filesystem error).
"""

from __future__ import annotations

import argparse
import html
import json
import logging
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Final

from src.pipeline.contracts.phase_io import ScanPhase
from src.sandbox.adapter_base import ParseStrategy, ToolCategory, ToolDescriptor
from src.sandbox.parsers import get_registered_tool_parsers
from src.sandbox.tool_registry import RegistryLoadError, ToolRegistry

_logger = logging.getLogger("docs_tool_catalog")


# ---------------------------------------------------------------------------
# Rendering constants — kept module-level so the helpers stay pure functions.
# ---------------------------------------------------------------------------


_DESCRIPTION_MAX_CHARS: Final[int] = 80
_TRUNCATION_SUFFIX: Final[str] = "..."

# ARG-040 — sandbox image directory layout. Each subdirectory under
# ``sandbox/images/`` (except the ``_shared`` helpers folder) hosts a single
# Dockerfile that materialises one image profile. The bare image name on
# disk corresponds to the ``image`` field in tool YAMLs once the ``:tag``
# suffix is stripped (e.g. ``argus-kali-web:latest`` → ``argus-kali-web``).
# A descriptor may legitimately reference an image profile that has not yet
# been materialised on disk — those rows show ``Dockerfile = no`` and serve
# as the operator-visible to-do list for the next image batch.
_SANDBOX_IMAGES_DIR: Final[Path] = (
    Path(__file__).resolve().parents[2] / "sandbox" / "images"
)
_SHARED_IMAGE_DIR_NAME: Final[str] = "_shared"

# Stable phase rendering order.  Phases not listed here render at the end in
# alphabetical order, so a future YAML batch surfacing a new phase does not
# silently break the layout.
_PHASE_RENDER_ORDER: Final[tuple[str, ...]] = (
    ScanPhase.RECON.value,
    ScanPhase.THREAT_MODELING.value,
    ScanPhase.VULN_ANALYSIS.value,
    ScanPhase.EXPLOITATION.value,
    ScanPhase.POST_EXPLOITATION.value,
    ScanPhase.REPORTING.value,
)

_PHASE_TITLES: Final[dict[str, str]] = {
    ScanPhase.RECON.value: "Recon",
    ScanPhase.THREAT_MODELING.value: "Threat modeling",
    ScanPhase.VULN_ANALYSIS.value: "Vulnerability analysis",
    ScanPhase.EXPLOITATION.value: "Exploitation",
    ScanPhase.POST_EXPLOITATION.value: "Post-exploitation",
    ScanPhase.REPORTING.value: "Reporting",
}

# Per-phase tool counts that the current shipped scope commits to:
# Backlog/dev1_md §4.1 (passive recon, 17) + §4.2 (active recon, 11) +
# §4.3 (TLS / mkcert in vuln_analysis, 7) + §4.4 (HTTP fingerprinting, 9,
# added by ARG-011) + §4.5 (content / path / parameter discovery & fuzzing,
# 10, added by ARG-012 — 2 in recon: ffuf_vhost + paramspider; 8 in
# vuln_analysis: ffuf_dir + ffuf_param + feroxbuster + gobuster_dir +
# dirsearch + kiterunner + arjun + wfuzz) + §4.6 (crawler / JS / endpoint
# extraction, 8, added by ARG-013 — 7 in recon: katana + gospider +
# hakrawler + waybackurls + gau + linkfinder + subjs; 1 in vuln_analysis:
# secretfinder) + §4.7 (CMS / platform-specific scanners, 8, added by
# ARG-014 — 0 in recon; 8 in vuln_analysis: wpscan + joomscan + droopescan
# + cmsmap + magescan + nextjs_check + spring_boot_actuator + jenkins_enum)
# + §4.8 (web vulnerability scanners, 7, added by ARG-015 — 0 in recon;
# 7 in vuln_analysis: nuclei + nikto + wapiti + arachni + skipfish +
# w3af_console + zap_baseline) + §4.9 (SQL-injection scanners, 6, added
# by ARG-016 — 0 in recon; 5 in vuln_analysis: sqlmap_safe + ghauri +
# jsql + tplmap + nosqlmap; 1 in exploitation: sqlmap_confirm) + §4.10
# (XSS scanners, 5, added by ARG-016 — 0 in recon; 4 in vuln_analysis:
# dalfox + xsstrike + kxss + xsser; 1 in exploitation:
# playwright_xss_verify, mapped from "validation" to exploitation per
# ARG-016 phase mapping) + §4.11 (SSRF/OAST/OOB, 6, added by ARG-017 +
# cycle-2 reviewer C1 — 0 in recon; 5 in vuln_analysis:
# interactsh_client + oastify_client + ssrfmap + gopherus +
# oast_dns_probe; 1 in exploitation: cloud_metadata_check) + §4.12
# (Auth/bruteforce, 11, added by ARG-017 + cycle-2 reviewer C2 — 1 in
# recon: snmp_check; 1 in vuln_analysis: gobuster_auth; 8 in
# exploitation: hydra + medusa + patator + ncrack + crackmapexec +
# kerbrute + smbclient + impacket_examples; 1 in post_exploitation:
# evil_winrm) + §4.13 (Hash/ crypto, 5, added by ARG-017 — 0 in recon;
# 5 in post_exploitation: hashcat + john + ophcrack + hashid +
# hash_analyzer) + §4.14 (API / GraphQL / gRPC scanners, 7, added by
# ARG-018 — 2 in recon: graphw00f + grpcurl_probe; 5 in vuln_analysis:
# openapi_scanner + clairvoyance + inql + graphql_cop + postman_newman)
# + §4.15 (Cloud / IaC / container, 12, added by ARG-018 — 0 in recon;
# 11 in vuln_analysis: prowler + scoutsuite + cloudsploit + trivy_image
# + trivy_fs + grype + syft + dockle + kube_bench + kube_hunter +
# checkov; 1 in exploitation: pacu) + §4.16 (IaC/code/secrets, 8, added
# by ARG-018 — 0 in recon; 8 in vuln_analysis: terrascan + tfsec + kics
# + semgrep + bandit + gitleaks + trufflehog + detect_secrets) +
# §4.17 (Network exploitation / protocol fuzzing, 10, added by ARG-019 —
# 6 in recon: ike_scan + snmpwalk + onesixtyone + ldapsearch +
# redis_cli_probe + mongodb_probe; 2 in exploitation: ntlmrelayx +
# responder; 2 in post_exploitation: impacket_secretsdump +
# bloodhound_python) + §4.18 (Binary / forensic / mobile analysis, 5,
# added by ARG-019 — 0 in recon; 5 in vuln_analysis: apktool + jadx +
# binwalk + radare2_info + mobsf_api) + §4.19 (Browser automation /
# headless / DAST helpers, 5, added by ARG-019 — 1 in recon:
# puppeteer_screens; 4 in vuln_analysis: playwright_runner +
# chrome_csp_probe + cors_probe + cookie_probe).  Future cycles bump
# these when new §4.x batches ship.
_EXPECTED_TOOLS_PER_PHASE: Final[dict[str, int]] = {
    ScanPhase.RECON.value: 56,
    ScanPhase.VULN_ANALYSIS.value: 79,
    ScanPhase.EXPLOITATION.value: 14,
    ScanPhase.POST_EXPLOITATION.value: 8,
}

# Long-term Backlog §4 catalog target (sum of §4.1–§4.19).  Surfaced in the
# coverage matrix so the gap to §4.4–§4.19 stays explicit between cycles.
# ARG-019 closes the catalog at the §4.17 / §4.18 / §4.19 boundary; the
# Backlog §4 long-term target is now identical to the shipped scope.
_BACKLOG_TOTAL_LONG_TERM: Final[int] = 157

# Modules participating in catalog dispatch — surfaced as a doc footer so an
# operator reviewing the catalog has a single jump-list.
_RELATED_MODULES: Final[tuple[str, ...]] = (
    "backend/src/sandbox/adapter_base.py",
    "backend/src/sandbox/tool_registry.py",
    "backend/src/sandbox/templating.py",
    "backend/src/sandbox/signing.py",
    "backend/src/sandbox/network_policies.py",
    "backend/src/sandbox/manifest.py",
    "backend/src/sandbox/k8s_adapter.py",
    "backend/src/sandbox/runner.py",
    "backend/scripts/tools_list.py",
    "backend/scripts/tools_sign.py",
    "backend/scripts/docs_tool_catalog.py",
    "backend/config/tools/SIGNATURES",
)


# ---------------------------------------------------------------------------
# Pure helpers — every function below is referentially transparent and safe
# to call from tests.  No I/O, no globals besides the constants above.
# ---------------------------------------------------------------------------


def _short_description(text: str) -> str:
    """Return ``text`` collapsed to a single line and capped at 80 chars."""
    flat = " ".join(text.split())
    if len(flat) <= _DESCRIPTION_MAX_CHARS:
        return flat
    cutoff = _DESCRIPTION_MAX_CHARS - len(_TRUNCATION_SUFFIX)
    return flat[:cutoff].rstrip() + _TRUNCATION_SUFFIX


def _render_command_html(tokens: Iterable[str]) -> str:
    """Render an argv list as an inline HTML ``<code>`` block.

    HTML escaping is mandatory because ``|`` would split the markdown table
    cell and ``<`` / ``>`` / ``&`` would be parsed as markup.  The numeric
    entity ``&#124;`` replaces the unicode pipe (``html.escape`` leaves it
    untouched) so the cell never collapses mid-row.
    """
    rendered = " ".join(tokens)
    escaped = html.escape(rendered, quote=True).replace("|", "&#124;")
    return f"<code>{escaped}</code>"


def _phase_sort_key(phase: str) -> tuple[int, str]:
    """Order phases by :data:`_PHASE_RENDER_ORDER`, unknown phases last."""
    try:
        return _PHASE_RENDER_ORDER.index(phase), phase
    except ValueError:
        return len(_PHASE_RENDER_ORDER), phase


# ---------------------------------------------------------------------------
# Parser status — ARG-020 (cycle 2 capstone).
#
# The catalog now surfaces, per descriptor, whether ``dispatch_parse`` will:
#
# * route to a first-class registered tool parser (``mapped``),
# * intentionally short-circuit before dispatch because the strategy is
#   :data:`ParseStrategy.BINARY_BLOB` — output is consumed by the evidence
#   pipeline, not the FindingDTO normaliser (``binary_blob``),
# * fall through to the heartbeat fail-soft path because no tool parser
#   is wired in for this ``tool_id`` yet (``heartbeat``).
#
# The label is computed once from a snapshot of
# :func:`src.sandbox.parsers.get_registered_tool_parsers` so a single
# ``ToolRegistry.load()`` cycle yields a stable, deterministic doc.
# ---------------------------------------------------------------------------


_PARSER_STATUS_MAPPED: Final[str] = "mapped"
_PARSER_STATUS_HEARTBEAT: Final[str] = "heartbeat"
_PARSER_STATUS_BINARY_BLOB: Final[str] = "binary_blob"


def _parser_status(
    descriptor: ToolDescriptor,
    registered_parsers: frozenset[str],
) -> str:
    """Return the doc label for the descriptor's parser dispatch outcome."""
    if descriptor.parse_strategy is ParseStrategy.BINARY_BLOB:
        return _PARSER_STATUS_BINARY_BLOB
    if descriptor.tool_id in registered_parsers:
        return _PARSER_STATUS_MAPPED
    return _PARSER_STATUS_HEARTBEAT


def _group_by_phase(
    descriptors: Iterable[ToolDescriptor],
) -> dict[str, list[ToolDescriptor]]:
    grouped: dict[str, list[ToolDescriptor]] = {}
    for descriptor in descriptors:
        grouped.setdefault(descriptor.phase.value, []).append(descriptor)
    return grouped


def _render_table_header() -> list[str]:
    return [
        (
            "| tool_id | category | risk_level | network_policy | requires_approval"
            " | parse_strategy | parser_status | command_template | description |"
        ),
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]


def _render_descriptor_row(
    descriptor: ToolDescriptor,
    registered_parsers: frozenset[str],
) -> str:
    cells = [
        f"`{descriptor.tool_id}`",
        descriptor.category.value,
        descriptor.risk_level.value,
        descriptor.network_policy.name,
        "yes" if descriptor.requires_approval else "no",
        descriptor.parse_strategy.value,
        _parser_status(descriptor, registered_parsers),
        _render_command_html(descriptor.command_template),
        _short_description(descriptor.description),
    ]
    return "| " + " | ".join(cells) + " |"


def _render_phase_section(
    phase: str,
    descriptors: list[ToolDescriptor],
    registered_parsers: frozenset[str],
) -> str:
    title = _PHASE_TITLES.get(phase, phase.replace("_", " ").title())
    lines: list[str] = [
        f"### {title} (`{phase}`)",
        "",
        f"_{len(descriptors)} tool(s) in this phase._",
        "",
    ]
    lines.extend(_render_table_header())
    for descriptor in sorted(descriptors, key=lambda d: d.tool_id):
        lines.append(_render_descriptor_row(descriptor, registered_parsers))
    return "\n".join(lines)


def _render_catalog_section(
    descriptors: list[ToolDescriptor],
    registered_parsers: frozenset[str],
) -> str:
    grouped = _group_by_phase(descriptors)
    lines: list[str] = ["## Tool reference", ""]
    for phase in sorted(grouped, key=_phase_sort_key):
        lines.append(_render_phase_section(phase, grouped[phase], registered_parsers))
        lines.append("")
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)


def _render_security_invariants() -> str:
    """Return the static security-invariants block.

    Each bullet is sourced from a concrete module so the contract is
    auditable: pod / container security context come from
    :mod:`src.sandbox.manifest`; network rules from
    :mod:`src.sandbox.network_policies`; placeholder allow-list from
    :mod:`src.sandbox.templating`; signing from :mod:`src.sandbox.signing`.
    """
    lines = [
        "## Security invariants",
        "",
        "Every tool in this catalog is dispatched through the ARGUS sandbox "
        "(`backend/src/sandbox/`) which enforces the following invariants — "
        "no per-tool override is possible:",
        "",
        "- **Non-root pod** — `runAsNonRoot=True`, `runAsUser=runAsGroup=fsGroup=65532` "
        "(`src.sandbox.manifest.build_pod_security_context`).",
        "- **Read-only root filesystem** — `readOnlyRootFilesystem=True`; only "
        "`/out` and `/tmp` `emptyDir` volumes are writable. No `hostPath`, no "
        "PVCs, no docker.sock mounts.",
        '- **All Linux capabilities dropped** — `capabilities.drop=["ALL"]`, '
        "`allowPrivilegeEscalation=False`, `privileged=False` "
        "(`src.sandbox.manifest.build_container_security_context`).",
        "- **Seccomp `RuntimeDefault`** — every descriptor declares "
        "`seccomp_profile=runtime/default`; `ToolRegistry.load()` is fail-closed "
        "on any other value.",
        "- **No service-account token** — `automountServiceAccountToken=False`; "
        "tool pods cannot reach the Kubernetes API.",
        "- **Argv-only execution** — `subprocess.run(argv, shell=False)`; "
        "templates render through `src.sandbox.templating.render_argv` against "
        "an allow-listed placeholder set (`ALLOWED_PLACEHOLDERS`).",
        "- **Ed25519-signed YAML descriptors** — every entry is verified against "
        "`backend/config/tools/SIGNATURES` (`src.sandbox.signing`); signature "
        "mismatch, schema mismatch, duplicate `tool_id`, or a forbidden "
        "placeholder all abort startup.",
        "- **Ingress always denied; egress allow-listed per `network_policy.name`** "
        "(`src.sandbox.network_policies`). DNS pinned to Cloudflare (`1.1.1.1`) "
        "and Quad9 (`9.9.9.9`).",
        "- **Active-recon templates require an explicit `target_cidr`** at render "
        "time — wildcard egress to the Internet is impossible from active categories.",
        "- **Job lifecycle** — `restartPolicy=Never`, `backoffLimit=0`, "
        "deterministic `default_timeout_s` per descriptor.",
        "- **Guaranteed QoS** — every container declares `requests==limits` for "
        "both CPU and memory (defence against `LimitRange` admission and noisy "
        "neighbours).",
        "",
        "Any descriptor that violates one of these invariants fails "
        "`ToolRegistry.load()` and the application refuses to start serving traffic.",
    ]
    return "\n".join(lines)


def _render_coverage_matrix(descriptors: list[ToolDescriptor]) -> str:
    counts: Counter[str] = Counter(d.phase.value for d in descriptors)
    lines: list[str] = [
        "## Coverage matrix",
        "",
        "Snapshot of the catalog scope shipped through ARG-019 "
        "(Backlog/dev1_md §4.1–§4.19) and ratcheted across cycles 2–5 "
        "(parser coverage 39 % → 58 % → **75.2 %** after Cycle 6 T05; was 62.4 % "
        "at Cycle 5 "
        "close).  The full Backlog §4 matrix lists "
        f"**{_BACKLOG_TOTAL_LONG_TERM}** tools — ARG-019 closes the "
        "long-term catalog at §4.19.  ARG-049 (Cycle 5 capstone) sustains "
        "the parser ratchet (mapped 118 / heartbeat 39) and ratchets the "
        "per-tool contract matrix to **16** gates (C1–C16).",
        "",
        "| Phase | Shipped | Expected (current scope) | Gap |",
        "| --- | ---: | ---: | ---: |",
    ]
    total_shipped = 0
    total_expected = 0
    phases = sorted(set(_EXPECTED_TOOLS_PER_PHASE) | set(counts), key=_phase_sort_key)
    for phase in phases:
        shipped = counts.get(phase, 0)
        expected = _EXPECTED_TOOLS_PER_PHASE.get(phase, shipped)
        gap = expected - shipped
        total_shipped += shipped
        total_expected += expected
        lines.append(f"| `{phase}` | {shipped} | {expected} | {gap} |")
    lines.append(
        f"| **Total** | **{total_shipped}** | **{total_expected}** "
        f"| **{total_expected - total_shipped}** |"
    )
    return "\n".join(lines)


def _render_parser_coverage(
    descriptors: list[ToolDescriptor],
    registered_parsers: frozenset[str],
) -> str:
    """Aggregate parser-status counts across the whole catalog.

    Surfaces three numbers operators care about per ARG-020 (cycle 2
    capstone) and ARG-030 (cycle 3 close-out):

    * **mapped** — descriptors whose ``tool_id`` resolves to a registered
      tool parser; ``dispatch_parse`` produces real findings.
    * **heartbeat** — descriptors whose strategy is implemented but whose
      ``tool_id`` is not yet wired in; ``dispatch_parse`` returns a single
      :class:`FindingDTO` heartbeat (``FindingCategory.INFO``,
      ``ARGUS-HEARTBEAT`` tag) AND a structured warning so the gap is
      observable.
    * **binary_blob** — descriptors whose evidence is a binary blob;
      :meth:`ShellToolAdapter.parse_output` short-circuits before dispatch
      and the evidence pipeline owns the artifact.

    The sum is the catalog total (Backlog/dev1_md §4 long-term target).
    Per ARG-030 the section also breaks the same numbers down by
    :class:`ToolCategory` so reviewers can spot uneven cycle-over-cycle
    coverage (e.g. ``recon`` ahead, ``cloud`` behind) without manually
    cross-referencing the per-phase table with each tool's category.
    """
    statuses: Counter[str] = Counter(
        _parser_status(d, registered_parsers) for d in descriptors
    )
    per_phase_status: dict[str, Counter[str]] = {}
    per_category_status: dict[str, Counter[str]] = {}
    for descriptor in descriptors:
        status = _parser_status(descriptor, registered_parsers)
        per_phase_status.setdefault(descriptor.phase.value, Counter())[status] += 1
        per_category_status.setdefault(descriptor.category.value, Counter())[
            status
        ] += 1

    total = len(descriptors)
    mapped = statuses.get(_PARSER_STATUS_MAPPED, 0)
    heartbeat = statuses.get(_PARSER_STATUS_HEARTBEAT, 0)
    binary_blob = statuses.get(_PARSER_STATUS_BINARY_BLOB, 0)
    mapped_pct = (mapped / total) * 100 if total else 0.0
    heartbeat_pct = (heartbeat / total) * 100 if total else 0.0

    lines: list[str] = [
        "## Parser coverage",
        "",
        f"**Mapped: {mapped} ({mapped_pct:.1f}%), "
        f"Heartbeat: {heartbeat} ({heartbeat_pct:.1f}%)** — "
        f"snapshot at ARG-040 close (cycle 4 capstone).",
        "",
        "Per descriptor, ``dispatch_parse`` follows exactly one of three "
        "deterministic paths (ARG-020, cycle 2 capstone).  No tool is allowed "
        "to silently produce zero findings: an unmapped tool always yields a "
        "single ``FindingCategory.INFO`` heartbeat tagged "
        "``ARGUS-HEARTBEAT`` plus a structured ``parsers.dispatch.*`` "
        "warning.",
        "",
        "- **`mapped`** — `tool_id` is registered in "
        "`src.sandbox.parsers._TOOL_TO_PARSER`; the strategy handler routes "
        "to a first-class parser that returns real findings.",
        "- **`heartbeat`** — strategy is registered, but no per-tool parser "
        "exists yet; the dispatcher emits one heartbeat finding "
        "(`FindingCategory.INFO`, CVSS 0.0, `cwe=[1059]`) plus the "
        "`parsers.dispatch.unmapped_tool` / `parsers.dispatch.no_handler` "
        "WARNING.  Wiring the parser flips the row from `heartbeat` to "
        "`mapped` with no contract change for callers.",
        "- **`binary_blob`** — strategy is `binary_blob`; "
        "`ShellToolAdapter.parse_output` short-circuits before dispatch and "
        "the evidence pipeline owns the artifact.  No FindingDTO is emitted "
        "from the parser layer (by design).",
        "",
        "### Catalog totals",
        "",
        "| Status | Count | Share |",
        "| --- | ---: | ---: |",
        f"| **`mapped`** | {mapped} | {_share(mapped, total)} |",
        f"| **`heartbeat`** | {heartbeat} | {_share(heartbeat, total)} |",
        f"| **`binary_blob`** | {binary_blob} | {_share(binary_blob, total)} |",
        f"| **Total** | **{total}** | **100.00%** |",
        "",
        "### Parser coverage by category",
        "",
        "Per :class:`ToolCategory` breakdown (ARG-030).  The `coverage` "
        "column is `mapped / total` as a percentage — a low value flags a "
        "category that lags the overall mapped ratio and is a strong "
        "candidate for the next parser batch.",
        "",
        "| Category | mapped | heartbeat | binary_blob | total | coverage |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for category in sorted(per_category_status, key=_category_sort_key):
        bucket = per_category_status[category]
        cat_mapped = bucket.get(_PARSER_STATUS_MAPPED, 0)
        cat_heartbeat = bucket.get(_PARSER_STATUS_HEARTBEAT, 0)
        cat_binary = bucket.get(_PARSER_STATUS_BINARY_BLOB, 0)
        cat_total = sum(bucket.values())
        lines.append(
            f"| `{category}` "
            f"| {cat_mapped} "
            f"| {cat_heartbeat} "
            f"| {cat_binary} "
            f"| {cat_total} "
            f"| {_share(cat_mapped, cat_total)} |"
        )
    lines.append(
        f"| **Total** "
        f"| **{mapped}** | **{heartbeat}** | **{binary_blob}** | **{total}** "
        f"| **{_share(mapped, total)}** |"
    )
    lines.extend(
        [
            "",
            "### Per-phase breakdown",
            "",
            "| Phase | mapped | heartbeat | binary_blob | total |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for phase in sorted(per_phase_status, key=_phase_sort_key):
        bucket = per_phase_status[phase]
        phase_total = sum(bucket.values())
        lines.append(
            f"| `{phase}` "
            f"| {bucket.get(_PARSER_STATUS_MAPPED, 0)} "
            f"| {bucket.get(_PARSER_STATUS_HEARTBEAT, 0)} "
            f"| {bucket.get(_PARSER_STATUS_BINARY_BLOB, 0)} "
            f"| {phase_total} |"
        )
    lines.append(
        f"| **Total** "
        f"| **{mapped}** | **{heartbeat}** | **{binary_blob}** | **{total}** |"
    )
    return "\n".join(lines)


# Stable :class:`ToolCategory` rendering order — matches the enum
# declaration order so reviewers see the "default" walk (recon → web_va
# → cloud → iac → network → auth → binary → browser → oast → misc).
# Categories not declared in the enum render at the end alphabetically
# so a future enum addition shipped without a doc update stays visible.
_CATEGORY_RENDER_ORDER: Final[tuple[str, ...]] = tuple(c.value for c in ToolCategory)


def _category_sort_key(category: str) -> tuple[int, str]:
    """Return a tuple that puts known categories first in enum order.

    Mirrors :func:`_phase_sort_key` so unknown categories surface at the
    end (alphabetised) instead of silently breaking the layout.
    """
    if category in _CATEGORY_RENDER_ORDER:
        return (_CATEGORY_RENDER_ORDER.index(category), category)
    return (len(_CATEGORY_RENDER_ORDER), category)


def _share(count: int, total: int) -> str:
    """Format ``count / total`` as a 2-decimal percentage; 0/0 → ``0.00%``."""
    if total <= 0:
        return "0.00%"
    return f"{(count / total) * 100:.2f}%"


# ---------------------------------------------------------------------------
# ARG-040 — Per-image coverage rendering.
#
# The catalog now surfaces the sandbox-image footprint as a first-class
# section so an operator (or a CI sweep) can answer two questions at a
# glance:
#
#   1. Which sandbox image hosts each tool, and how many tools per image?
#      (Driven by the descriptor's :attr:`ToolDescriptor.image` field.)
#   2. Which images actually have a Dockerfile on disk under
#      ``sandbox/images/``?  A ``no`` in the ``Dockerfile`` column flags
#      a future image-build task — those tools will not run until the
#      profile is materialised.
#
# The two helpers below are pure: image discovery and image-name
# normalisation are referentially transparent and safe to call from
# tests.
# ---------------------------------------------------------------------------


def _strip_image_tag(image: str) -> str:
    """Return the bare image name with any ``:tag`` suffix stripped.

    ``argus-kali-web:latest`` → ``argus-kali-web``.  Plain references
    (``argus-kali-web``) round-trip unchanged.  Used to match the
    descriptor's ``image`` field against the ``sandbox/images/<name>/``
    directory layout on disk.
    """
    return image.split(":", 1)[0]


def _discover_built_images(images_dir: Path) -> frozenset[str]:
    """Return the set of image names that have a Dockerfile on disk.

    Iterates ``sandbox/images/<name>/Dockerfile`` and skips the shared
    helpers folder (``_shared``).  Returns an empty set if the images
    directory is missing — keeps the renderer pure and tolerant of
    stripped checkouts (e.g. backend-only test environments).
    """
    if not images_dir.is_dir():
        return frozenset()
    discovered: set[str] = set()
    for child in images_dir.iterdir():
        if not child.is_dir() or child.name == _SHARED_IMAGE_DIR_NAME:
            continue
        if (child / "Dockerfile").is_file():
            discovered.add(child.name)
    return frozenset(discovered)


def _render_image_coverage(
    descriptors: list[ToolDescriptor],
    *,
    images_dir: Path = _SANDBOX_IMAGES_DIR,
) -> str:
    """Render the per-image coverage section.

    Cross-tabulates :attr:`ToolDescriptor.image` against the on-disk
    Dockerfiles under ``sandbox/images/``.  Surfaces three columns per
    row: built-yes/no, descriptor count, and share-of-catalog
    percentage.  Output is sorted by descending tool count so the
    most-trafficked image rises to the top.
    """
    counts: Counter[str] = Counter(descriptor.image for descriptor in descriptors)
    built = _discover_built_images(images_dir)
    total = len(descriptors)
    built_total = sum(
        count for image, count in counts.items() if _strip_image_tag(image) in built
    )
    pending_total = total - built_total
    built_pct = (built_total / total) * 100 if total else 0.0
    pending_pct = (pending_total / total) * 100 if total else 0.0

    lines: list[str] = [
        "## Image coverage",
        "",
        f"**Built: {built_total} ({built_pct:.1f}%), "
        f"Pending: {pending_total} ({pending_pct:.1f}%)** — snapshot at "
        "ARG-058 close (cycle 6: dual-listed YAML migration).",
        "",
        "Per :attr:`ToolDescriptor.image`, the sandbox materialises one image "
        "profile per ``sandbox/images/<name>/Dockerfile``. A descriptor may "
        "reference a profile that has not yet been materialised — those rows "
        "show ``Dockerfile = no`` and form the operator-visible to-do list for "
        "the next image batch. ARG-048 delivered the missing ``argus-kali-recon`` "
        "(Backlog §4.1 passive + §4.2 active recon) and ``argus-kali-network`` "
        "(Backlog §4.17 protocol exploitation: SNMP/LDAP/SMB/IKE/impacket) "
        "profiles, lifting the built-image count from 4 to 6. ARG-058 then "
        "moved the 16 dual-listed network-protocol tools "
        "(``bloodhound_python``, ``crackmapexec``, ``evil_winrm``, ``ike_scan``, "
        "``impacket_examples``, ``impacket_secretsdump``, ``kerbrute``, "
        "``ldapsearch``, ``mongodb_probe``, ``ntlmrelayx``, ``onesixtyone``, "
        "``redis_cli_probe``, ``responder``, ``smbclient``, ``snmp_check``, "
        "``snmpwalk``) off ``argus-kali-web`` (91 → 75) into ``argus-kali-network`` "
        "(0 → 16), eliminating the dual-listing without touching descriptor count.",
        "",
        "| image | Dockerfile | tool_count | share |",
        "| --- | :---: | ---: | ---: |",
    ]
    for image, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        bare = _strip_image_tag(image)
        present = "yes" if bare in built else "no"
        lines.append(f"| `{image}` | {present} | {count} | {_share(count, total)} |")
    lines.append(
        f"| **Total** | — | **{total}** | **100.00%** |"
    )
    return "\n".join(lines)


def _render_related_modules() -> str:
    lines: list[str] = ["## Related modules", ""]
    for path in _RELATED_MODULES:
        lines.append(f"- `{path}`")
    return "\n".join(lines)


def _render_header(total: int) -> str:
    lines = [
        "# ARGUS sandbox tool catalog",
        "",
        "<!-- AUTO-GENERATED by `python -m scripts.docs_tool_catalog "
        "--out ../docs/tool-catalog.md` -->",
        "<!-- DO NOT EDIT BY HAND. Re-run the script after changing any YAML in -->",
        "<!-- `backend/config/tools/`. The script verifies every signature and -->",
        "<!-- renders this file deterministically (stable order: phase → tool_id). -->",
        "",
        f"This document indexes the **{total}** tool descriptors that the ARGUS Active "
        "Pentest Engine ships through cycles **ARG-001..ARG-049** "
        "(Backlog/dev1_md §4.1–§4.19). "
        "Each entry is loaded via `src.sandbox.tool_registry.ToolRegistry`, validated "
        "against `src.sandbox.adapter_base.ToolDescriptor`, and Ed25519-verified against "
        "`backend/config/tools/SIGNATURES` before the application starts serving traffic. "
        "ARG-040 (Cycle 4 capstone) added the mandatory `version: <semver>` field on "
        "every descriptor and pins parser coverage at **mapped: 118 (75.2%) / heartbeat: "
        "39 (24.9%)** — see *Parser coverage* below. "
        "ARG-049 (Cycle 5 capstone) ratcheted the per-tool contract matrix from 14 to "
        "**16** parametrised gates by adding C15 (`tool-yaml-version-monotonic`, frozen "
        "baseline at `backend/tests/snapshots/tool_versions_baseline.json`) and C16 "
        "(`image-coverage-completeness`, every tool_id installed by ≥1 of the 6 sandbox "
        "image profiles in `infra/sandbox/images/tool_to_package.json`).",
        "",
        "Build & run pipeline at a glance:",
        "",
        "1. **YAML descriptor** under `backend/config/tools/*.yaml` "
        "(matching record in `SIGNATURES`).",
        "2. **`ToolRegistry.load()`** parses through `ToolDescriptor`, verifies the "
        "Ed25519 signature, and validates `command_template` against the "
        "placeholder allow-list (`src.sandbox.templating.ALLOWED_PLACEHOLDERS`).",
        "3. **`KubernetesSandboxAdapter`** materialises a hardened `Job` manifest "
        "(non-root, read-only rootfs, dropped caps, NetworkPolicy from "
        "`src.sandbox.network_policies`) and dispatches it.",
        "4. **Findings + evidence** flow into the standard pipeline (`FindingDTO`, "
        "`EvidenceDTO`) and are persisted with redaction + chain-of-custody hashing "
        "(`src.evidence.pipeline`, `src.evidence.redaction`).",
        "",
        "See `Backlog/dev1_md` §4 for the long-term tool roadmap and the intent "
        "behind each category, plus §3 / §5 / §18 for the adapter contract, "
        "sandbox guardrails, and signing model that this catalog instantiates.",
    ]
    return "\n".join(lines)


def build_markdown(
    descriptors: list[ToolDescriptor],
    *,
    registered_parsers: frozenset[str] | None = None,
) -> str:
    """Compose the full markdown document from a list of descriptors.

    Public for tests: deterministic input → deterministic output (no clock,
    no env, no I/O).  Trailing newline is appended for POSIX-friendliness.

    Parameters
    ----------
    descriptors:
        The :class:`ToolDescriptor` set produced by
        :class:`~src.sandbox.tool_registry.ToolRegistry`.
    registered_parsers:
        Snapshot of the per-tool parser registry returned by
        :func:`src.sandbox.parsers.get_registered_tool_parsers`.  Passed in
        explicitly so tests can pin a deterministic doc against an
        arbitrary parser set; defaults to the live registry.
    """
    parsers_snapshot = (
        get_registered_tool_parsers()
        if registered_parsers is None
        else registered_parsers
    )
    sections = [
        _render_header(total=len(descriptors)),
        _render_catalog_section(descriptors, parsers_snapshot),
        _render_security_invariants(),
        _render_coverage_matrix(descriptors),
        _render_image_coverage(descriptors),
        _render_parser_coverage(descriptors, parsers_snapshot),
        _render_related_modules(),
    ]
    return "\n\n".join(sections).rstrip() + "\n"


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------


def _resolve_default_tools_dir() -> Path:
    """Return the canonical ``backend/config/tools`` directory."""
    return Path(__file__).resolve().parent.parent / "config" / "tools"


def _resolve_default_output() -> Path:
    """Return the canonical ``docs/tool-catalog.md`` path under repo root."""
    return Path(__file__).resolve().parents[2] / "docs" / "tool-catalog.md"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="docs_tool_catalog",
        description="Render docs/tool-catalog.md from the signed ARGUS tool registry.",
    )
    parser.add_argument(
        "--tools-dir",
        type=Path,
        default=_resolve_default_tools_dir(),
        help="Tools YAML directory (default: backend/config/tools/).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=_resolve_default_output(),
        help="Output markdown path (default: docs/tool-catalog.md).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Render in-memory and compare against the existing file; exit 1"
            " on drift.  Used by CI to ensure the committed doc tracks the catalog."
        ),
    )
    return parser


def _emit_error(event: str, **fields: object) -> None:
    """Emit a one-line JSON error record on stderr (no stack traces)."""
    payload: dict[str, object] = {"event": event}
    payload.update(fields)
    sys.stderr.write(json.dumps(payload, sort_keys=True, ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    registry = ToolRegistry(tools_dir=args.tools_dir)
    try:
        registry.load()
    except RegistryLoadError as exc:
        _emit_error("docs_tool_catalog.load_failed", reason=str(exc))
        return 1

    descriptors = registry.all_descriptors()
    rendered = build_markdown(descriptors)

    if args.check:
        try:
            existing = args.out.read_text(encoding="utf-8")
        except OSError as exc:
            _emit_error(
                "docs_tool_catalog.read_failed",
                path=str(args.out),
                reason=str(exc),
            )
            return 2
        if existing != rendered:
            _emit_error(
                "docs_tool_catalog.drift",
                path=str(args.out),
                hint="re-run: python -m scripts.docs_tool_catalog --out <path>",
            )
            return 1
        _logger.info(
            "docs_tool_catalog.check_ok tools=%d path=%s",
            len(descriptors),
            args.out,
        )
        return 0

    try:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        _emit_error(
            "docs_tool_catalog.write_failed",
            path=str(args.out),
            reason=str(exc),
        )
        return 2

    _logger.info(
        "docs_tool_catalog.rendered tools=%d path=%s",
        len(descriptors),
        args.out,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
