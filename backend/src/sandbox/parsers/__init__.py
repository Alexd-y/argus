"""Sandbox tool-output parsers — public dispatch registry.

This package is the single dispatch point between :class:`ShellToolAdapter`
(or any other consumer) and a tool-specific parser.  Each concrete parser
lives in its own module (``<family>_parser.py``) and exposes a pure function
``parse_<family>(stdout, stderr, artifacts_dir, tool_id?) -> list[FindingDTO]``.
The package wires those callables to the corresponding
:class:`~src.sandbox.adapter_base.ParseStrategy` enum value AND, since
ARG-012, to a per-``tool_id`` table so several distinct tools that share a
strategy (e.g. all JSON_OBJECT content-discovery scanners) can route to
their own parser without bespoke ``if/elif`` chains in the strategy
handler.

Public surface
--------------
* :func:`register_parser` — register / override the handler for a strategy.
* :func:`register_tool_parser` — register / override the per-tool parser.
* :func:`get_registered_strategies` — introspection (used by tests).
* :func:`get_registered_tool_parsers` — introspection (used by tests).
* :func:`dispatch_parse` — the single entry point used by adapters.
* :func:`reset_registry` — test-only helper to restore default registrations.

Failure model (fail-soft, with operator-visible heartbeats since ARG-020)
------------------------------------------------------------------------
Every fail-soft branch emits the original structured ``WARNING`` for
observability AND a single :class:`FindingDTO` heartbeat
(:data:`FindingCategory.INFO`, CVSS 0.0, ``HEARTBEAT-{tool_id}`` tag in
``owasp_wstg``).  The heartbeat tells the orchestrator / UI "the tool ran
to completion but findings could not be extracted — inspect the raw
artifacts" instead of silently producing zero findings.

* **Unknown strategy** (no handler registered) — log
  ``WARNING parsers.dispatch.no_handler`` + return one heartbeat finding.
* **Unknown tool inside a known strategy** — log
  ``WARNING parsers.dispatch.unmapped_tool`` + return one heartbeat finding.
* **Handler raised** — log structured ``WARNING
  parsers.dispatch.handler_failed`` (no stack trace, no PII) for
  :class:`ParseError`, ``parsers.dispatch.handler_unexpected_error`` for
  any other exception, return ``[]``.  A misbehaving parser is a
  programming bug, not a coverage gap; we do NOT emit a heartbeat in that
  case so the metric remains a clean signal of "tool ran but no parser
  is wired".  ``BINARY_BLOB`` is short-circuited by
  :class:`ShellToolAdapter` before ever reaching dispatch, so it never
  triggers a heartbeat.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Final

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    SSVCDecision,
)
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers._base import (
    MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES,
    SENTINEL_CVSS_SCORE,
    SENTINEL_CVSS_VECTOR,
    SENTINEL_UUID,
    ParseError,
    ParserContext,
    make_finding_dto,
    safe_decode,
    safe_load_json,
    safe_load_jsonl,
)
from src.sandbox.parsers.amass_passive_parser import parse_amass_passive
from src.sandbox.parsers.apktool_parser import parse_apktool
from src.sandbox.parsers.assetfinder_parser import parse_assetfinder
from src.sandbox.parsers.bandit_parser import parse_bandit_json
from src.sandbox.parsers.binwalk_parser import parse_binwalk
from src.sandbox.parsers.bloodhound_python_parser import parse_bloodhound_python
from src.sandbox.parsers.censys_parser import parse_censys
from src.sandbox.parsers.chaos_parser import parse_chaos
from src.sandbox.parsers.checkov_parser import parse_checkov_json
from src.sandbox.parsers.chrome_csp_probe_parser import parse_chrome_csp_probe
from src.sandbox.parsers.cloudsploit_parser import parse_cloudsploit_json
from src.sandbox.parsers.crackmapexec_parser import parse_crackmapexec
from src.sandbox.parsers.dalfox_parser import parse_dalfox_json
from src.sandbox.parsers.detect_secrets_parser import parse_detect_secrets_json
from src.sandbox.parsers.dnsrecon_parser import parse_dnsrecon
from src.sandbox.parsers.discovery_text_parser import parse_discovery_text_lines
from src.sandbox.parsers.dnsx_parser import parse_dnsx
from src.sandbox.parsers.dockle_parser import parse_dockle_json
from src.sandbox.parsers.enum4linux_ng_parser import parse_enum4linux_ng
from src.sandbox.parsers.evil_winrm_parser import parse_evil_winrm
from src.sandbox.parsers.ffuf_parser import parse_ffuf_json
from src.sandbox.parsers.fierce_parser import parse_fierce
from src.sandbox.parsers.findomain_parser import parse_findomain
from src.sandbox.parsers.gitleaks_parser import parse_gitleaks_json
from src.sandbox.parsers.gowitness_parser import parse_gowitness
from src.sandbox.parsers.graphql_cop_parser import parse_graphql_cop_json
from src.sandbox.parsers.grype_parser import parse_grype_json
from src.sandbox.parsers.hash_analyzer_parser import parse_hash_analyzer_json
from src.sandbox.parsers.hashcat_parser import parse_hashcat
from src.sandbox.parsers.hashid_parser import parse_hashid_json
from src.sandbox.parsers.httpx_parser import parse_httpx_jsonl
from src.sandbox.parsers.hydra_parser import parse_hydra
from src.sandbox.parsers.impacket_secretsdump_parser import (
    parse_impacket_secretsdump,
)
from src.sandbox.parsers.interactsh_parser import parse_interactsh_jsonl
from src.sandbox.parsers.jadx_parser import parse_jadx
from src.sandbox.parsers.jarm_parser import parse_jarm_json
from src.sandbox.parsers.jsql_probe_parser import parse_jsql_json
from src.sandbox.parsers.katana_parser import (
    parse_gau_jsonl,
    parse_gospider_jsonl,
    parse_katana_jsonl,
)
from src.sandbox.parsers.kerbrute_parser import parse_kerbrute
from src.sandbox.parsers.kics_parser import parse_kics_json
from src.sandbox.parsers.kube_bench_parser import parse_kube_bench_json
from src.sandbox.parsers.ldapsearch_parser import parse_ldapsearch
from src.sandbox.parsers.masscan_parser import parse_masscan_json
from src.sandbox.parsers.medusa_parser import parse_medusa
from src.sandbox.parsers.mobsf_parser import parse_mobsf_json
from src.sandbox.parsers.mongodb_probe_parser import parse_mongodb_probe
from src.sandbox.parsers.naabu_parser import parse_naabu_jsonl
from src.sandbox.parsers.ncrack_parser import parse_ncrack
from src.sandbox.parsers.nmap_parser import parse_nmap_xml
from src.sandbox.parsers.ntlmrelayx_parser import parse_ntlmrelayx
from src.sandbox.parsers.nuclei_parser import (
    parse_nikto_json,
    parse_nuclei_jsonl,
    parse_wapiti_json,
)
from src.sandbox.parsers.openapi_scanner_parser import parse_openapi_scanner_json
from src.sandbox.parsers.patator_parser import parse_patator
from src.sandbox.parsers.playwright_runner_parser import parse_playwright_runner
from src.sandbox.parsers.postman_newman_parser import parse_postman_newman_json
from src.sandbox.parsers.prowler_parser import parse_prowler_json
from src.sandbox.parsers.puppeteer_screens_parser import parse_puppeteer_screens
from src.sandbox.parsers.radare2_info_parser import parse_radare2_info
from src.sandbox.parsers.redis_cli_probe_parser import parse_redis_cli_probe
from src.sandbox.parsers.responder_parser import parse_responder
from src.sandbox.parsers.rpcclient_enum_parser import parse_rpcclient_enum
from src.sandbox.parsers.semgrep_parser import parse_semgrep_json
from src.sandbox.parsers.smbclient_check_parser import parse_smbclient_check
from src.sandbox.parsers.smbmap_parser import parse_smbmap
from src.sandbox.parsers.snmpwalk_parser import parse_snmpwalk
from src.sandbox.parsers.sqlmap_parser import parse_sqlmap_output
from src.sandbox.parsers.sqli_probe_text_parser import parse_sqli_probe_text
from src.sandbox.parsers.subfinder_parser import parse_subfinder
from src.sandbox.parsers.syft_parser import parse_syft_json
from src.sandbox.parsers.terrascan_parser import parse_terrascan_json
from src.sandbox.parsers.tfsec_parser import parse_tfsec_json
from src.sandbox.parsers.trivy_parser import parse_trivy_json
from src.sandbox.parsers.trufflehog_parser import parse_trufflehog_jsonl
from src.sandbox.parsers.unicornscan_parser import parse_unicornscan
from src.sandbox.parsers.wappalyzer_cli_parser import parse_wappalyzer_cli_json
from src.sandbox.parsers.webanalyze_parser import parse_webanalyze
from src.sandbox.parsers.whatweb_parser import parse_whatweb
from src.sandbox.parsers.wpscan_parser import (
    parse_droopescan_json,
    parse_wpscan_json,
)
from src.sandbox.parsers.xss_auxiliary_json_parser import parse_xss_auxiliary_json
from src.sandbox.parsers.zap_baseline_parser import parse_zap_baseline_json

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Handler signatures
# ---------------------------------------------------------------------------


# Every dispatch-registered strategy handler accepts the raw IO triple plus
# the ``tool_id`` (for log correlation / multi-tool routing inside one
# strategy).  Concrete tool-specific parsers stay 4-arg pure functions
# ``parse_<tool>(stdout, stderr, artifacts_dir, tool_id)``; the dispatch
# strategy handler looks them up in :data:`_TOOL_TO_PARSER`.
ParserHandler = Callable[[bytes, bytes, Path, str], list[FindingDTO]]
ToolParser = Callable[[bytes, bytes, Path, str], list[FindingDTO]]


# ---------------------------------------------------------------------------
# Heartbeat finding (ARG-020)
# ---------------------------------------------------------------------------


# Tag stamped onto :data:`FindingDTO.owasp_wstg` for every heartbeat.
# Lets the orchestrator / UI / `findings/` query layer recognise a
# "tool ran but parser deferred" entry without having to inspect free-form
# fields.  Format keeps tool_id intact for grep-friendliness.
HEARTBEAT_TAG_PREFIX: Final[str] = "ARGUS-HEARTBEAT"


def _heartbeat_finding(
    *,
    tool_id: str,
    parse_strategy: ParseStrategy,
    reason: str,
) -> FindingDTO:
    """Build the canonical heartbeat :class:`FindingDTO` for a fail-soft branch.

    The DTO carries:

    * ``category=INFO`` and ``cvss_v3_score=0.0`` so the normaliser maps it
      onto severity ``info`` — the heartbeat MUST never raise the scan's
      worst-severity bar.
    * ``cwe=[CWE-1059]`` (Insufficient Technical Documentation) — the
      catalog ships the tool but ARGUS lacks the technical wiring to
      interpret its output, which is exactly what CWE-1059 codifies.
    * Three identifying tags in ``owasp_wstg``:
      ``ARGUS-HEARTBEAT``, ``HEARTBEAT-{tool_id}``, and
      ``HEARTBEAT-STRATEGY-{parse_strategy}``.  The orchestrator filters on
      the first; humans pivot on the latter two.

    ``reason`` is a short machine-readable code (``unmapped_tool`` or
    ``no_handler``) that is logged but NOT embedded in the DTO — the DTO
    contract has no free-form ``description`` slot, so the breakdown lives
    in the structured warning that always accompanies the heartbeat.
    """
    del reason  # Surfaced via the structured warning, not the DTO itself.
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[1059],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=SENTINEL_CVSS_SCORE,
        confidence=ConfidenceLevel.SUSPECTED,
        status=FindingStatus.NEW,
        ssvc_decision=SSVCDecision.TRACK,
        owasp_wstg=[
            HEARTBEAT_TAG_PREFIX,
            f"HEARTBEAT-{tool_id}",
            f"HEARTBEAT-STRATEGY-{parse_strategy.value}",
        ],
    )


# ---------------------------------------------------------------------------
# Per-tool parser registry
# ---------------------------------------------------------------------------


_TOOL_TO_PARSER: dict[str, ToolParser] = {}


def register_tool_parser(
    tool_id: str,
    parser: ToolParser,
    *,
    override: bool = False,
) -> None:
    """Register ``parser`` for ``tool_id``.

    Raises :class:`ValueError` if a parser is already registered for
    ``tool_id`` and ``override`` is False — the catch-all bug class is "two
    parsers silently fight for the same tool", not "user forgot
    ``override``".
    """
    if tool_id in _TOOL_TO_PARSER and not override:
        raise ValueError(
            f"parser for tool_id={tool_id!r} already registered; "
            "pass override=True to replace it"
        )
    _TOOL_TO_PARSER[tool_id] = parser
    _logger.debug(
        "parsers.register_tool",
        extra={
            "event": "parsers_register_tool",
            "tool_id": tool_id,
            "override": override,
        },
    )


def get_registered_tool_parsers() -> frozenset[str]:
    """Return a snapshot of ``tool_id`` s that currently have a parser."""
    return frozenset(_TOOL_TO_PARSER.keys())


# ---------------------------------------------------------------------------
# Strategy handler — resolves ``tool_id`` against ``_TOOL_TO_PARSER``
# ---------------------------------------------------------------------------


def _strategy_handler(
    strategy: ParseStrategy,
) -> ParserHandler:
    """Build a ParserHandler that delegates to ``_TOOL_TO_PARSER[tool_id]``.

    When the strategy is registered but no per-tool parser exists for
    ``tool_id`` (the YAML legitimately shipped ahead of its parser), the
    closure:

    1. Logs ``WARNING parsers.dispatch.unmapped_tool`` with
       ``event=parsers_dispatch_unmapped_tool``, ``tool_id``,
       ``parse_strategy``, and ``artifacts_dir`` so the gap is observable.
    2. Returns a single :class:`FindingDTO` heartbeat (ARG-020) so the
       orchestrator / UI can surface "tool ran, parser deferred" without
       confusing it with "tool ran, found nothing".
    """

    def _handler(
        stdout: bytes,
        stderr: bytes,
        artifacts_dir: Path,
        tool_id: str,
    ) -> list[FindingDTO]:
        parser = _TOOL_TO_PARSER.get(tool_id)
        if parser is None:
            _logger.warning(
                "parsers.dispatch.unmapped_tool",
                extra={
                    "event": "parsers_dispatch_unmapped_tool",
                    "tool_id": tool_id,
                    "parse_strategy": strategy.value,
                    "artifacts_dir": str(artifacts_dir),
                    "stdout_len": len(stdout),
                    "stderr_len": len(stderr),
                },
            )
            return [
                _heartbeat_finding(
                    tool_id=tool_id,
                    parse_strategy=strategy,
                    reason="unmapped_tool",
                )
            ]
        return parser(stdout, stderr, artifacts_dir, tool_id)

    return _handler


# ---------------------------------------------------------------------------
# Per-tool adapter wrappers — keep the (stdout, stderr, artifacts_dir, tool_id)
# call shape uniform even when a concrete parser does not need ``tool_id``.
# ---------------------------------------------------------------------------


def _httpx_tool_parser(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """4-arg adapter for :func:`parse_httpx_jsonl` (drops unused ``tool_id``)."""
    del tool_id
    return parse_httpx_jsonl(stdout, stderr, artifacts_dir)


# ---------------------------------------------------------------------------
# Default registrations — populated at import time and restored by
# :func:`reset_registry`.  Keep this list sorted by strategy so a future
# diff of "what shipped in cycle N" stays grep-friendly.
# ---------------------------------------------------------------------------


_DEFAULT_TOOL_PARSERS: dict[str, ToolParser] = {
    # §4.2 Active recon — Nmap XML back-port (ARG-019).  All five Nmap
    # invocations share the canonical ``-oX /out/nmap.xml`` envelope
    # (Backlog/dev1_md §4.2) so they multiplex on ``tool_id`` while
    # routing through the single :func:`parse_nmap_xml` parser under
    # ``ParseStrategy.XML_NMAP``:
    #
    # * ``nmap_tcp_full``  — full TCP port-discovery sweep (``-sS -p-``).
    # * ``nmap_tcp_top``   — top-1000 TCP discovery (``-sS --top-ports 1000``).
    # * ``nmap_udp``       — top-100 UDP probe (``-sU --top-ports 100``).
    # * ``nmap_version``   — service / version detection (``-sV``).
    # * ``nmap_vuln``      — NSE vulnerability scan (``-sV --script vuln,vulners,vulscan``).
    #
    # The parser uses :mod:`defusedxml` so XXE / billion-laughs payloads
    # are refused at the tree-build step, and surfaces both INFO (open
    # port + service banner) and SUPPLY_CHAIN (CVE-bearing vulners
    # script output) findings into a shared ``nmap_findings.jsonl``
    # sidecar that stays demultiplexable via the ``tool_id`` field.
    "nmap_tcp_full": parse_nmap_xml,
    "nmap_tcp_top": parse_nmap_xml,
    "nmap_udp": parse_nmap_xml,
    "nmap_version": parse_nmap_xml,
    "nmap_vuln": parse_nmap_xml,
    # §4.4 HTTP fingerprinting (ARG-011).
    "httpx": _httpx_tool_parser,
    # §4.5 Content / path / parameter discovery (ARG-012).  Every JSON-
    # emitting §4.5 tool routes through the universal ffuf-shape parser:
    #
    # * ``ffuf_dir`` / ``ffuf_vhost`` / ``ffuf_param`` — native ffuf
    #   ``-of json`` envelope.
    # * ``feroxbuster`` — JSONL stream OR ``{"results": [...]}`` envelope.
    # * ``dirsearch`` — ``{"results": [...]}`` envelope with hyphenated
    #   ``content-length`` field.
    # * ``arjun`` — top-level dict keyed by URL (handled via the
    #   tool_id-aware branch in ``_extract_findings_list``).
    # * ``kiterunner`` — best-effort: kr's JSON output broadly matches
    #   the ffuf shape (``status`` / ``length`` / ``url``); records that
    #   do not normalise are fail-soft logged + skipped.
    # * ``wfuzz`` — best-effort: wfuzz's printer emits a top-level JSON
    #   array of ``{url, status/code, ...}`` records that flow through
    #   ``_iter_normalised``.
    #
    # §4.5 TEXT_LINES discovery (Cycle 6 T05) — gobuster + paramspider
    # now share :func:`parse_discovery_text_lines` with the §4.6 crawler
    # URL extractors wired in the same batch.
    "gobuster_dir": parse_discovery_text_lines,
    "gobuster_auth": parse_discovery_text_lines,
    "paramspider": parse_discovery_text_lines,
    "ffuf_dir": parse_ffuf_json,
    "ffuf_vhost": parse_ffuf_json,
    "ffuf_param": parse_ffuf_json,
    "feroxbuster": parse_ffuf_json,
    "dirsearch": parse_ffuf_json,
    "arjun": parse_ffuf_json,
    "kiterunner": parse_ffuf_json,
    "wfuzz": parse_ffuf_json,
    # §4.6 Crawler / JS / endpoint extraction (ARG-013).  Three tools
    # emit JSONL; the TEXT_LINES five-pack plus ``kxss`` route through
    # :func:`parse_discovery_text_lines` (Cycle 6 T05).
    #
    # * ``katana``    — native ``-jsonl`` output (one request per line).
    # * ``gospider``  — ``--json`` output (one URL per line); shape adapter
    #   inside the parser collapses gospider's ``output`` / ``stat`` fields
    #   onto katana's canonical ``request.endpoint`` / ``response.status_code``.
    # * ``gau``       — ``--json`` output: minimal ``{"url": "..."}`` per
    #   archived URL.
    "katana": parse_katana_jsonl,
    "gospider": parse_gospider_jsonl,
    "gau": parse_gau_jsonl,
    "hakrawler": parse_discovery_text_lines,
    "waybackurls": parse_discovery_text_lines,
    "linkfinder": parse_discovery_text_lines,
    "subjs": parse_discovery_text_lines,
    "secretfinder": parse_discovery_text_lines,
    "kxss": parse_discovery_text_lines,
    # §4.7 CMS / platform-specific scanners (ARG-014).  Two of the eight
    # §4.7 tools emit a stable, parseable JSON shape on disk; the rest
    # ship without parsers in Cycle 2:
    #
    # * ``wpscan``     — flagship WordPress scanner; canonical
    #   ``--format json --output /out/wpscan.json`` envelope with
    #   ``interesting_findings`` / ``version`` / ``main_theme`` /
    #   ``themes`` / ``plugins`` / ``users`` blocks.
    # * ``droopescan`` — Drupal / Joomla / SilverStripe / WordPress
    #   scanner; ``-o json`` envelope with ``version`` / ``themes`` /
    #   ``plugins`` / ``modules`` / ``users``.  Lightweight
    #   info-only adapter (no inline vulnerability metadata).
    #
    # Three §4.7 tools (``joomscan``, ``cmsmap``, ``magescan``) share
    # :func:`parse_discovery_text_lines` (Cycle 6 T05) for text / JSON
    # stdout extraction.
    # Three more (``nextjs_check``, ``spring_boot_actuator``,
    # ``jenkins_enum``) wrap nuclei templates and route through
    # ``ParseStrategy.NUCLEI_JSONL`` — handled by ARG-015 (below).
    "wpscan": parse_wpscan_json,
    "droopescan": parse_droopescan_json,
    "joomscan": parse_discovery_text_lines,
    "cmsmap": parse_discovery_text_lines,
    "magescan": parse_discovery_text_lines,
    # §4.7 + §4.8 nuclei JSONL family (ARG-015). Four callers share the
    # single ``parse_nuclei_jsonl`` parser because the JSONL shape nuclei
    # emits is invariant of the template / tag selection — only the
    # template set differs:
    #
    # * ``nuclei`` (§4.8)              — flagship generic invocation.
    # * ``nextjs_check`` (§4.7)        — ``-tags nextjs`` wrapper.
    # * ``spring_boot_actuator`` (§4.7) — ``-tags springboot,actuator``.
    # * ``jenkins_enum`` (§4.7)        — ``-tags jenkins`` wrapper.
    #
    # The remaining §4.8 web-vuln scanners (``skipfish``, ``w3af_console``)
    # still defer TEXT_LINES parsers; ``arachni`` + ``zap_baseline`` are
    # wired (T05 + ARG-029 respectively).
    "nuclei": parse_nuclei_jsonl,
    "nextjs_check": parse_nuclei_jsonl,
    "spring_boot_actuator": parse_nuclei_jsonl,
    "jenkins_enum": parse_nuclei_jsonl,
    # §4.8 — additional active web vuln scanners with stable JSON shapes.
    #
    # * ``nikto``  — ``-Format json`` envelope with ``vulnerabilities[]``;
    #   minimal MISCONFIG-class adapter (CWE-16 default).
    # * ``wapiti`` — ``-f json`` envelope with ``vulnerabilities`` keyed by
    #   category name; the parser maps each Wapiti category onto a
    #   :class:`FindingCategory`.
    "nikto": parse_nikto_json,
    "wapiti": parse_wapiti_json,
    # §4.9 SQL injection (ARG-016).  Both sqlmap wrappers share the
    # canonical text-log shape under ``--output-dir``, so they route
    # through the single :func:`parse_sqlmap_output` parser via the
    # newly registered ``ParseStrategy.TEXT_LINES`` handler.
    #
    # * ``sqlmap_safe``    — passive boolean / time-based detection
    #   (``--technique=BT --level 2 --risk 1 --safe-url=...``).
    # * ``sqlmap_confirm`` — error-based exploitation pass
    #   (``--technique=E --dbs --count``); approval-gated.
    #
    # §4.9 — ``jsql`` JSON plus ``ghauri`` / ``tplmap`` / ``nosqlmap``
    # heuristic TEXT_LINES probes (Cycle 6 T05).
    "sqlmap_safe": parse_sqlmap_output,
    "sqlmap_confirm": parse_sqlmap_output,
    # §4.9 — jsql JSON export + heuristic TEXT_LINES probes (Cycle 6 T05).
    "jsql": parse_jsql_json,
    "ghauri": parse_sqli_probe_text,
    "tplmap": parse_sqli_probe_text,
    "nosqlmap": parse_sqli_probe_text,
    "arachni": parse_sqli_probe_text,
    # §4.10 XSS (ARG-016 + Cycle 6 T05).  ``dalfox`` keeps its bespoke
    # adapter; ``xsstrike`` / ``xsser`` / ``playwright_xss_verify`` share
    # :func:`parse_xss_auxiliary_json`; ``kxss`` uses
    # :func:`parse_discovery_text_lines`.
    "dalfox": parse_dalfox_json,
    # §4.10 — XSS JSON auxiliaries (Cycle 6 T05): XSStrike / XSSer /
    # Playwright verifier share a defensive JSON walker separate from
    # dalfox's bespoke envelope.
    "xsstrike": parse_xss_auxiliary_json,
    "xsser": parse_xss_auxiliary_json,
    "playwright_xss_verify": parse_xss_auxiliary_json,
    # §4.11 SSRF / OAST / OOB (ARG-017).  ``interactsh_client`` is the
    # canonical OOB receiver; it emits one JSON envelope per OAST
    # callback to ``-o /out/interactsh.jsonl``.  ``oastify_client`` is
    # the upstream-compatible mirror — its wire shape is identical, so
    # both route through :func:`parse_interactsh_jsonl` under
    # ``ParseStrategy.JSON_LINES``. The remaining three §4.11 tools
    # (``ssrfmap`` / ``gopherus`` / ``oast_dns_probe`` / ``cloud_metadata_check``)
    # ship without a parser in Cycle 2 — Cycle 3 work.
    "interactsh_client": parse_interactsh_jsonl,
    "oastify_client": parse_interactsh_jsonl,
    # §4.15 Cloud / IaC / container (ARG-018 + ARG-021).
    #
    # ARG-018 wired ``trivy_image`` / ``trivy_fs`` (canonical
    # ``Results[].Vulnerabilities`` / ``.Misconfigurations`` /
    # ``.Secrets`` envelope).
    #
    # ARG-021 (Cycle 3 batch 1) adds five more cloud / container /
    # K8s / IaC parsers that all route through
    # ``ParseStrategy.JSON_OBJECT``:
    #
    # * ``checkov``     — Bridgecrew multi-IaC (TF/CFN/K8s/Helm/Docker)
    #   ``-o json`` envelope.  ``results.failed_checks[]`` →
    #   FindingCategory.MISCONFIG (CKV_SECRET_* → SECRET_LEAK).
    # * ``dockle``      — Goodwith CIS Docker Benchmark scanner;
    #   ``-f json`` envelope with ``details[].alerts[]``.
    # * ``grype``       — Anchore SCA/CVE matcher; canonical ``matches[]``.
    #   FindingCategory.SUPPLY_CHAIN with CVSSv3 anchored on the
    #   highest-scoring vendor block.
    # * ``kube_bench``  — Aqua CIS Kubernetes Benchmark; ``Controls[].tests[]``
    #   tree.  Drops PASS/INFO; emits FAIL/WARN as MISCONFIG with
    #   per-node-type dedup so master + node fail-on-the-same-rule both
    #   surface.
    # * ``kics``        — Checkmarx multi-IaC; canonical
    #   ``queries[].files[]`` shape.  Defaults to MISCONFIG; routes
    #   "secret"/"password"/"credential"-keyword queries to SECRET_LEAK.
    "checkov": parse_checkov_json,
    "dockle": parse_dockle_json,
    "grype": parse_grype_json,
    "kube_bench": parse_kube_bench_json,
    "kics": parse_kics_json,
    "trivy_image": parse_trivy_json,
    "trivy_fs": parse_trivy_json,
    # §4.16 Code / secrets (ARG-018 + ARG-021).
    #
    # ARG-018 wired ``semgrep`` (multi-language SAST flagship).
    #
    # ARG-021 (Cycle 3 batch 1) adds four more SAST / IaC / secret-leak
    # parsers under ``ParseStrategy.JSON_OBJECT``:
    #
    # * ``bandit``    — PyCQA Python SAST; canonical ``results[]``
    #   envelope.  CWE pulled from ``issue_cwe.id``; severity / confidence
    #   one-to-one mapped onto ARGUS' ConfidenceLevel ladder.
    # * ``gitleaks`` — Zricethezav secret scanner; top-level JSON array.
    #   **CRITICAL**: ``Match`` / ``Secret`` fields are redacted via
    #   :func:`src.sandbox.parsers._base.redact_secret` before any
    #   sidecar / log persistence; CWE-798 pinned for every finding.
    #   Severity is rule-id derived (private/aws → CRITICAL).
    # * ``terrascan`` — Tenable IaC; ``results.violations[]``.
    # * ``tfsec``    — Aqua Terraform; ``results[]`` with
    #   ``location.{filename,start_line}``.
    "bandit": parse_bandit_json,
    "gitleaks": parse_gitleaks_json,
    "semgrep": parse_semgrep_json,
    "terrascan": parse_terrascan_json,
    "tfsec": parse_tfsec_json,
    # §4.18 Mobile binary / static (ARG-021).
    #
    # * ``mobsf_api`` — Mobile Security Framework REST/CLI report.
    #   Defensive walk over MoBSF's deeply nested + version-variable
    #   envelope: code_analysis / android_api / binary_analysis /
    #   manifest_analysis / secrets / certificate_analysis /
    #   network_security / permissions sections each flow into the
    #   canonical FindingDTO.  Secrets sections route through
    #   :func:`redact_secret` so raw cleartext never lands in the
    #   sidecar.
    "mobsf_api": parse_mobsf_json,
    # §4.2 + §4.12 + §4.17 Network / AD / SMB / LDAP TEXT_LINES batch
    # (ARG-022, Cycle 3 batch 2).  Ten parsers route through
    # ``ParseStrategy.TEXT_LINES`` (and ``JSON_OBJECT`` for
    # ``enum4linux_ng`` whose YAML declares the JSON wrapper but whose
    # canonical text path is parsed here).
    #
    # CRITICAL security gate — ``impacket_secretsdump`` is the only
    # parser in the catalog that legitimately receives domain
    # credential material (NTDS.dit dumps).  Every record passes
    # through :func:`redact_hash_string` BEFORE FindingDTO construction
    # AND :func:`redact_hashes_in_evidence` BEFORE sidecar persistence.
    # No raw NT/LM/Kerberos hash byte ever touches an evidence file.
    #
    # * ``impacket_secretsdump`` (§4.17) — NTDS / SAM / LSA secret
    #   extraction, severity HIGH (CVSS 9.8) → AUTH category, CWE-522.
    # * ``evil_winrm`` (§4.12) — interactive PS post-ex marker, INFO
    #   category, severity 0.0.  One finding per session capturing the
    #   exit code + last operator command.
    # * ``kerbrute`` (§4.12) — userenum hits; ``[+] VALID USERNAME``
    #   lines.  ``NO PREAUTH`` variant escalates to CVSS 8.8 (CWE-287).
    # * ``bloodhound_python`` (§4.17) — collector log marker; one INFO
    #   finding per ``Compressing output into <name>.zip`` line.
    # * ``snmpwalk`` (§4.17) — OID walk; default community
    #   (``public``/``private``/``manager``) escalates to MISCONFIG
    #   HIGH (CWE-521).
    # * ``ldapsearch`` (§4.17) — LDIF blocks; ``Domain Admins`` /
    #   ``Enterprise Admins`` membership escalates to AUTH MEDIUM
    #   (CWE-269).
    # * ``smbclient`` (§4.12) — share listing rows; admin shares
    #   (``ADMIN$`` / ``C$`` / ``IPC$``) escalate to MISCONFIG MEDIUM.
    # * ``smbmap`` (§4.2) — access-rights matrix; writable shares
    #   (``READ, WRITE``) escalate to MISCONFIG HIGH (CVSS 8.5).
    # * ``enum4linux_ng`` (§4.2) — legacy text path (JSON
    #   ``-oJ`` output deferred); section + KV scraper.  ``Null
    #   sessions allowed`` markers escalate to MISCONFIG MEDIUM.
    # * ``rpcclient_enum`` (§4.2) — ``user:[NAME] rid:[0xRID]`` /
    #   ``account[NAME]`` blocks; null-session acceptance escalates
    #   to MISCONFIG MEDIUM (CVSS 5.3).
    "impacket_secretsdump": parse_impacket_secretsdump,
    "evil_winrm": parse_evil_winrm,
    "kerbrute": parse_kerbrute,
    "bloodhound_python": parse_bloodhound_python,
    "snmpwalk": parse_snmpwalk,
    "ldapsearch": parse_ldapsearch,
    "smbclient": parse_smbclient_check,
    "smbmap": parse_smbmap,
    "enum4linux_ng": parse_enum4linux_ng,
    "rpcclient_enum": parse_rpcclient_enum,
    # ARG-029 (Cycle 3 batch 3) — JSON_LINES family.
    #
    # CRITICAL security gates (security-auditor verifies):
    #
    # * ``trufflehog`` — JSONL output. Every record's ``Raw``, ``RawV2``
    #   and ``Redacted`` fields are passed through
    #   :func:`src.sandbox.parsers._base.redact_secret` BEFORE FindingDTO
    #   construction AND BEFORE sidecar persistence. No raw secret byte
    #   ever lands on disk; CWE-798 pinned for every finding.
    # * ``naabu``      — ProjectDiscovery port scanner; canonical
    #   ``-json`` output (one ``{ip, port, host, ...}`` per line).
    #   FindingCategory.INFO with CWE-200 / CWE-668. Dedup keyed on
    #   ``(ip, port, protocol)`` to keep big sweeps bounded.
    # * ``masscan``    — fast async port scanner; despite the
    #   "JSON_LINES" categorisation in the plan, masscan emits a
    #   top-level JSON ARRAY (legacy versions add a trailing comma we
    #   defensively repair). FindingCategory.INFO; CWE-200.
    # * ``prowler``    — multi-cloud posture scanner; JSON array of
    #   findings with status FAIL/PASS/MANUAL. We emit FAIL records as
    #   FindingCategory.MISCONFIG / CRYPTO / AUTH (keyword-driven) with
    #   CVSS mapped from severity. AWS account IDs in
    #   ``Resource.Identifier`` are PRESERVED — they are not secrets.
    "trufflehog": parse_trufflehog_jsonl,
    "naabu": parse_naabu_jsonl,
    "masscan": parse_masscan_json,
    "prowler": parse_prowler_json,
    # ARG-029 — custom parsers.
    #
    # * ``detect_secrets`` — Yelp baseline scanner. ``hashed_secret`` is
    #   a SHA-1 fingerprint so it stays in cleartext (it IS the dedup key
    #   the operator marks as known). Any cleartext ``secret`` field that
    #   sneaks through is passed through ``redact_secret`` before sidecar
    #   persistence.
    # * ``openapi_scanner`` — internal Swagger/OpenAPI walker; parser
    #   tolerates either a ``findings[]`` envelope (vulnerability mode)
    #   or a fallback ``endpoints[]`` envelope (pure discovery mode).
    # * ``graphql_cop``   — runs ~15 GraphQL safety probes, only
    #   ``result==true`` entries become findings; severity-keyword table
    #   maps to DOS / CSRF / INFO categories.
    # * ``postman_newman`` — Postman runner export; parses
    #   ``run.failures[]`` (assertion failures) and ``run.executions[]``
    #   (HTTP 5xx responses). Auth tokens scrubbed from response previews.
    # * ``zap_baseline``   — OWASP ZAP baseline JSON; one finding per
    #   ``(alert × instance)``; HTML descriptions stripped to text.
    "detect_secrets": parse_detect_secrets_json,
    "openapi_scanner": parse_openapi_scanner_json,
    "graphql_cop": parse_graphql_cop_json,
    "postman_newman": parse_postman_newman_json,
    "zap_baseline": parse_zap_baseline_json,
    # ARG-029 — mixed JSON_OBJECT family.
    #
    # * ``syft``           — Anchore CycloneDX SBOM. Emits one
    #   ``inventory`` finding plus one INFO finding per
    #   library/framework/application/operating-system component.
    #   FindingCategory.SUPPLY_CHAIN with CWE-1395.
    # * ``cloudsploit``    — Aqua multi-cloud posture; both the modern
    #   ``{results: [...]}`` shape and the legacy
    #   ``{regions: {region: {plugin: [...]}}}`` shape are supported.
    #   Severity escalates to ``high`` for IAM / encryption / public
    #   exposure keywords. AWS account IDs in resource ARNs are
    #   PRESERVED (they are not secrets).
    # * ``hashid`` / ``hash_analyzer`` — local hash classifiers. Raw
    #   hash strings are NEVER persisted; only ``stable_hash_12``,
    #   length, entropy and matched algorithms make it into the
    #   FindingDTO + sidecar. FindingCategory.CRYPTO with CWE-326/-327.
    # * ``jarm``           — TLS server fingerprint; JSON / single-
    #   record / JSONL all tolerated; all-zero fingerprints (target
    #   did not respond) dropped. FindingCategory.INFO + CWE-200,
    #   confidence CONFIRMED (JARM is deterministic).
    # * ``wappalyzer_cli`` — tech-stack fingerprint; one INFO finding
    #   per detected technology, dedup keyed on
    #   ``(url, name, version)``.
    "syft": parse_syft_json,
    "cloudsploit": parse_cloudsploit_json,
    "hashid": parse_hashid_json,
    "hash_analyzer": parse_hash_analyzer_json,
    "jarm": parse_jarm_json,
    "wappalyzer_cli": parse_wappalyzer_cli_json,
    # ARG-032 (Cycle 4 batch 4) — browser / binary / recon / auth.
    #
    # CRITICAL security gates (security-auditor verifies):
    #
    # Browser family (4a) — every HAR walker passes through
    # :mod:`src.sandbox.parsers._browser_base`, which redacts
    # ``Cookie`` / ``Set-Cookie`` / ``Authorization`` /
    # ``Proxy-Authorization`` headers and inline URL credentials
    # **before** any record reaches the per-tool parser.  The C12
    # bait blob (``Cookie: session=ABC``) therefore never lands in
    # the FindingDTO or the sidecar.
    #
    # Binary family (4b) — every parser routes evidence values
    # through :func:`src.sandbox.parsers._text_base.redact_memory_address`
    # via :func:`scrub_evidence_strings`.  ASLR offsets like
    # ``0xdeadbeef12345678`` are masked with the canonical
    # ``[REDACTED-ADDR]`` token.
    #
    # Recon family (4b) — every subdomain extractor validates the
    # candidate string against the strict RFC-1035 regex in
    # :func:`src.sandbox.parsers._subdomain_base.is_valid_hostname`
    # so a noisy log line cannot turn into a finding.
    #
    # Auth family (4c) — every credential bruteforcer routes the
    # cleartext password through
    # :func:`src.sandbox.parsers._text_base.redact_password_in_text`
    # AND replaces the value with the canonical
    # ``[REDACTED-PASSWORD]`` marker before any FindingDTO is
    # built.  ``responder``, ``hashcat``, ``ntlmrelayx``, and
    # ``crackmapexec`` additionally route hash bytes through
    # :func:`redact_hash_string` so the C12 NT-hash bait blob is
    # masked before reaching the sidecar.
    #
    # 4a — browser (6 parsers, browser coverage 0% → 100%).
    "playwright_runner": parse_playwright_runner,
    "puppeteer_screens": parse_puppeteer_screens,
    "chrome_csp_probe": parse_chrome_csp_probe,
    "webanalyze": parse_webanalyze,
    "gowitness": parse_gowitness,
    "whatweb": parse_whatweb,
    # 4b — binary analysis (4 parsers, binary coverage 20% → ~80%).
    "radare2_info": parse_radare2_info,
    "apktool": parse_apktool,
    "binwalk": parse_binwalk,
    "jadx": parse_jadx,
    # 4b — subdomain reconnaissance (6 parsers, recon coverage 20% → ~70%).
    "amass_passive": parse_amass_passive,
    "subfinder": parse_subfinder,
    "assetfinder": parse_assetfinder,
    "dnsrecon": parse_dnsrecon,
    "fierce": parse_fierce,
    "findomain": parse_findomain,
    # 4c — credential bruteforce / NTLM relay (8 parsers,
    # auth coverage 27% → ~80%).
    "hydra": parse_hydra,
    "medusa": parse_medusa,
    "patator": parse_patator,
    "ncrack": parse_ncrack,
    "crackmapexec": parse_crackmapexec,
    "responder": parse_responder,
    "hashcat": parse_hashcat,
    "ntlmrelayx": parse_ntlmrelayx,
    # 4c — network / OSINT / probes (6 parsers).
    "dnsx": parse_dnsx,
    "chaos": parse_chaos,
    "censys": parse_censys,
    "mongodb_probe": parse_mongodb_probe,
    "redis_cli_probe": parse_redis_cli_probe,
    "unicornscan": parse_unicornscan,
}


def _register_default_tool_parsers() -> None:
    """Populate :data:`_TOOL_TO_PARSER` from :data:`_DEFAULT_TOOL_PARSERS`."""
    for tool_id, parser in _DEFAULT_TOOL_PARSERS.items():
        _TOOL_TO_PARSER[tool_id] = parser


# ---------------------------------------------------------------------------
# Strategy registry
# ---------------------------------------------------------------------------


def _build_default_strategy_handlers() -> dict[ParseStrategy, ParserHandler]:
    """Build the default strategy → handler table.

    * ``JSON_LINES``   — routes ``httpx`` (§4.4), the §4.11 OOB tools
      (``interactsh_client`` / ``oastify_client``), and the ARG-029
      JSONL family (``trufflehog`` / ``naabu``).
    * ``JSON_OBJECT``  — routes the §4.5 ffuf-family content discovery
      scanners, the §4.7 wpscan / droopescan parsers, the §4.8
      ``nikto`` / ``wapiti`` web-vuln adapters, the §4.10 ``dalfox``
      XSS scanner (ARG-016), the §4.15 cloud / IaC / container batch
      (ARG-018 / ARG-021), and the ARG-029 mixed JSON_OBJECT family
      (``masscan`` / ``prowler`` / ``detect_secrets`` /
      ``openapi_scanner`` / ``graphql_cop`` / ``postman_newman`` /
      ``syft`` / ``cloudsploit`` / ``hashid`` / ``hash_analyzer`` /
      ``jarm`` / ``wappalyzer_cli``).
    * ``NUCLEI_JSONL`` — routes the §4.7 + §4.8 nuclei callers (``nuclei``,
      ``nextjs_check``, ``spring_boot_actuator``, ``jenkins_enum``) through
      :func:`src.sandbox.parsers.nuclei_parser.parse_nuclei_jsonl`.
    * ``TEXT_LINES``   — routes line-based tool outputs.  Introduced
      in ARG-016 with the §4.9 sqlmap wrappers (``sqlmap_safe`` /
      ``sqlmap_confirm``); ARG-022 added the §4.2 / §4.12 / §4.17
      AD/SMB/LDAP/SNMP batch; ARG-029 adds ``zap_baseline`` whose YAML
      declares ``text_lines`` but whose canonical parse path is a JSON
      sidecar (``zap_baseline.json``).  Cycle 6 T05 wired the deferred
      §4.9 / §4.10 SQLi + XSS heartbeat tools into first-class parsers.
    * ``XML_NMAP``     — routes the five §4.2 Nmap callers through
      :func:`src.sandbox.parsers.nmap_parser.parse_nmap_xml`. The
      parser uses ``defusedxml`` so XXE / billion-laughs / external
      DTD payloads are refused before the tree is materialised
      (ARG-019).

    All five go through the same per-tool lookup so a new YAML batch
    only needs a one-liner :func:`register_tool_parser` instead of a new
    ``elif`` in a strategy handler.
    """
    return {
        ParseStrategy.JSON_LINES: _strategy_handler(ParseStrategy.JSON_LINES),
        ParseStrategy.JSON_OBJECT: _strategy_handler(ParseStrategy.JSON_OBJECT),
        ParseStrategy.NUCLEI_JSONL: _strategy_handler(ParseStrategy.NUCLEI_JSONL),
        ParseStrategy.TEXT_LINES: _strategy_handler(ParseStrategy.TEXT_LINES),
        ParseStrategy.XML_NMAP: _strategy_handler(ParseStrategy.XML_NMAP),
    }


_REGISTRY: dict[ParseStrategy, ParserHandler] = _build_default_strategy_handlers()
_register_default_tool_parsers()


def register_parser(
    strategy: ParseStrategy,
    handler: ParserHandler,
    *,
    override: bool = False,
) -> None:
    """Register ``handler`` for ``strategy``.

    Raises :class:`ValueError` if a handler is already registered and
    ``override`` is False — the catch-all bug class is "two parsers
    silently fight for the same strategy", not "user forgot ``override``".
    """
    if strategy in _REGISTRY and not override:
        raise ValueError(
            f"parser for {strategy.value!r} already registered; "
            "pass override=True to replace it"
        )
    _REGISTRY[strategy] = handler
    _logger.debug(
        "parsers.register",
        extra={
            "event": "parsers_register",
            "parse_strategy": strategy.value,
            "override": override,
        },
    )


def get_registered_strategies() -> frozenset[ParseStrategy]:
    """Return a snapshot of strategies that currently have a handler."""
    return frozenset(_REGISTRY.keys())


def reset_registry() -> None:
    """Restore the registry to its default state (test-only helper)."""
    _REGISTRY.clear()
    _REGISTRY.update(_build_default_strategy_handlers())
    _TOOL_TO_PARSER.clear()
    _register_default_tool_parsers()


def dispatch_parse(
    strategy: ParseStrategy,
    raw_stdout: bytes,
    raw_stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Route raw output to the registered handler for ``strategy``.

    Fail-soft model:

    * **Strategy not registered** — log
      ``WARNING parsers.dispatch.no_handler`` and emit one
      :class:`FindingDTO` heartbeat (ARG-020).  This is the path triggered
      by catalog YAMLs declaring ``parse_strategy=custom`` / ``csv`` /
      ``xml_generic`` until Cycle 3 wires the strategy handler.
    * **Handler raised** — log structured warning and return ``[]``.
      A misbehaving parser is a programming bug, not a coverage gap; we do
      NOT emit a heartbeat so the heartbeat metric stays a clean signal of
      "tool ran but no parser is wired".

    The unmapped-tool case (strategy known, ``tool_id`` not in the
    per-tool registry) is handled inside :func:`_strategy_handler` because
    the strategy handler is the only place that can know about it.
    """
    handler = _REGISTRY.get(strategy)
    if handler is None:
        _logger.warning(
            "parsers.dispatch.no_handler",
            extra={
                "event": "parsers_dispatch_no_handler",
                "parse_strategy": strategy.value,
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "stdout_len": len(raw_stdout),
                "stderr_len": len(raw_stderr),
            },
        )
        return [
            _heartbeat_finding(
                tool_id=tool_id,
                parse_strategy=strategy,
                reason="no_handler",
            )
        ]
    try:
        return handler(raw_stdout, raw_stderr, artifacts_dir, tool_id)
    except ParseError as exc:
        _logger.warning(
            "parsers.dispatch.handler_failed",
            extra={
                "event": "parsers_dispatch_handler_failed",
                "parse_strategy": strategy.value,
                "tool_id": tool_id,
                "error_type": type(exc).__name__,
                "error_message": str(exc)[:200],
            },
        )
        return []
    except Exception as exc:
        _logger.warning(
            "parsers.dispatch.handler_unexpected_error",
            extra={
                "event": "parsers_dispatch_handler_unexpected_error",
                "parse_strategy": strategy.value,
                "tool_id": tool_id,
                "error_type": type(exc).__name__,
            },
        )
        return []


__all__ = [
    "HEARTBEAT_TAG_PREFIX",
    "MAX_STDERR_BYTES",
    "MAX_STDOUT_BYTES",
    "SENTINEL_CVSS_SCORE",
    "SENTINEL_CVSS_VECTOR",
    "SENTINEL_UUID",
    "ParseError",
    "ParserContext",
    "ParserHandler",
    "ToolParser",
    "dispatch_parse",
    "get_registered_strategies",
    "get_registered_tool_parsers",
    "make_finding_dto",
    "register_parser",
    "register_tool_parser",
    "reset_registry",
    "safe_decode",
    "safe_load_json",
    "safe_load_jsonl",
]
