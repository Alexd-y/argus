"""Single source of truth for the allowlist of command-template placeholders.

Per Backlog/dev1_md §18 critical guardrails. Both the YAML command-template
renderer (:mod:`src.sandbox.templating`) and the
:class:`~src.pipeline.contracts.tool_job.ToolJob` ``parameters`` contract MUST
agree on this set; otherwise YAMLs may declare placeholders that no
``ToolJob`` can ever satisfy (silent dead tools).

Layered as a pure constant module under :mod:`src.pipeline.contracts` (no
imports from sandbox / orchestrator / app layers), so both the contracts
layer and the sandbox layer can depend on it without inverting the layered
architecture.
"""

from __future__ import annotations

ALLOWED_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        # --- Backlog/dev1_md §18 core set ---
        "url",
        "host",
        "port",
        "domain",
        "ip",
        "cidr",
        "params",
        "wordlist",
        "canary",
        "out_dir",
        "in_dir",
        # --- §4.x extended (passive recon, active recon, web va, exploitation) ---
        "ports",
        "ports_range",
        "proto",
        "community",
        "community_string",
        # Auth (per §4.12 evil-winrm: -u/-p; legacy long forms kept for OpenVAS/etc.).
        "u",
        "p",
        "user",
        "pass",
        # Tool config (per §4.13 hashcat -m {mode}, §4.7 nuclei modules, §4.15 metasploit).
        "fmt",
        "mode",
        "module",
        "mod",
        "org",
        "profile",
        "image",
        "session",
        "dc",
        "size",
        "safe",
        "rand",
        "s",
        # ARG-017 §4.11 SSRF/OAST: signed, sandbox-rooted hash bundle anchor for
        # §4.13 password-cracker payloads (hashcat / john / ophcrack); kept
        # separate from {wordlist} so the validator can pin the strict /in/
        # prefix. Also surfaces an optional fully-qualified OAST callback
        # (``{rand}.oast.argus.local``) for tools that take a single URL flag
        # rather than a host + token pair.
        "hashes_file",
        "canary_callback",
        # ARG-017 §4.12 Auth/brute target protocol (e.g. ssh, ftp, smb).
        # Kept distinct from the existing free-form ``{proto}`` (which the
        # tool catalog uses for layer-7 protocol *labels*) so the auth
        # validator can refuse upper-case / unknown protos used as Hydra's
        # service:// scheme.
        "target_proto",
        # ARG-018 §4.14/§4.15/§4.16 (API / Cloud / Code) — sandbox-rooted
        # filesystem path to a code repo / IaC tree / artefact mount. Used
        # by SAST (semgrep, bandit), SCA (trivy fs, checkov), secret
        # scanners (gitleaks, trufflehog), and IaC linters (terrascan,
        # tfsec, kics). Constrained to the ``/in/`` sandbox prefix so a
        # malicious template cannot reach into the worker's read-only
        # rootfs or the orchestrator's secret bind-mounts.
        "path",
        # ARG-019 §4.17/§4.18/§4.19 (Network protocol / binary / browser).
        # Network-layer poisoning needs an interface label (eth0, tap0…),
        # binary analysis needs sandbox-rooted file paths to APK/ELF/PE
        # samples, browser automation tools take sandbox-rooted JavaScript
        # scenario files, and LDAP/Kerberos enumerators need a Distinguished
        # Name base. All values stay strictly inside ``/in/`` (file/script
        # /binary) or use a token-style validator (interface/basedn) — no
        # raw shell injection vector is ever introduced. See worker plan
        # ``ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md``
        # task ARG-019.
        "interface",
        "binary",
        "file",
        "script",
        "basedn",
        # Correlation tokens (always supplied by the dispatcher, never user input).
        "scan_id",
        "tenant_id",
    }
)

__all__ = ["ALLOWED_PLACEHOLDERS"]
