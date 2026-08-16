"""Single canonical tool-name namespace (Backlog T7).

Before this module ARGUS carried four independent tool-name namespaces that
drifted apart:

* the **signed catalog** — 162 ``tool_id`` values (e.g. ``sqlmap_safe``,
  ``ffuf_dir``, ``nmap_tcp_top``, ``crt_sh``, ``enum4linux_ng``);
* the **LLM/phase allowlists** — short binary names the planner proposes
  (``sqlmap``, ``ffuf``, ``nmap``, ``crtsh``, ``enum4linux``);
* the **MCP / Celery operation names** — ``run_sqlmap``,
  ``argus.va.run_sqlmap``;
* the **vuln→tool map** in the exploitation executor — again short names
  (``sqlmap``, ``ffuf``) that do **not** exist as catalog ``tool_id``s.

The result was a latent contract break: ``_VULN_TOOL_MAP`` asked for
``sqlmap``/``ffuf``, neither of which is a real ``tool_id``. This module is
the one place that reconciles every alias to a canonical catalog ``tool_id``
so callers (``ToolRegistry.resolve``, the MCP ``tool.run.trigger`` handler,
future P1 execution rewiring) share a single source of truth.

Resolution is intentionally pure and catalog-free at the unit level:
:func:`resolve_tool_alias` answers "what canonical id does this alias mean?"
without touching the signed catalog, while :func:`canonical_tool_id` folds in
a caller-supplied set of real ``tool_id``s to also cover identity matches and
separator variants. No subprocess, no I/O, no network.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Final

# ---------------------------------------------------------------------------
# Canonical alias table: alias → catalog ``tool_id``.
#
# Only *semantic* mappings live here (a generic name that has to pick a
# specific catalog variant, or a binary spelling that is not a pure
# separator fold of its ``tool_id``). Pure separator variants such as
# ``enum4linux-ng`` → ``enum4linux_ng`` or ``kube-bench`` → ``kube_bench``
# are handled generically by :func:`_fold_separators` and are deliberately
# NOT duplicated here (DRY). Every value below is asserted to be a real
# ``tool_id`` by ``tests/unit/sandbox/test_tool_aliases.py`` (drift guard).
# ---------------------------------------------------------------------------
TOOL_ALIASES: Final[dict[str, str]] = {
    # Generic binary name → the safe/default catalog variant.
    "sqlmap": "sqlmap_safe",
    "sqlmap_detect": "sqlmap_safe",
    "nmap": "nmap_tcp_top",
    "ffuf": "ffuf_dir",
    "gobuster": "gobuster_dir",
    "amass": "amass_passive",
    "trivy": "trivy_fs",
    "shodan": "shodan_cli",
    "wappalyzer": "wappalyzer_cli",
    "scout": "scoutsuite",
    "impacket": "impacket_examples",
    "nosqli": "nosqlmap",
    "enum4linux": "enum4linux_ng",
    # Binary spelling that is not a pure separator fold of the ``tool_id``.
    "testssl.sh": "testssl",
    "testssl_sh": "testssl",
    "crtsh": "crt_sh",
}

# Names that intentionally are NOT sandbox-catalog tools. Reconciliation
# tests treat these as known exceptions rather than drift: browser
# primitives exposed over MCP, source-analysis operations, and a handful of
# tools referenced by legacy allowlists that have no descriptor yet. Keeping
# them explicit means a genuinely mistyped allowlist entry still fails.
VIRTUAL_TOOLS: Final[frozenset[str]] = frozenset(
    {
        # Source-analysis MCP operations (not shell tools).
        "git_clone",
        "tree_sitter_parse",
        "file_read",
        # Browser primitives exposed via the MCP browser bridge.
        "browser_navigate",
        "browser_click",
        "browser_type",
        "browser_screenshot",
        "browser_intercept",
        "browser_execute_js",
        # Referenced by legacy allowlists; no signed descriptor yet.
        "linpeas",
        "winpeas",
        "burp_suite",
        "authmatrix",
        "gf_ssrf",
    }
)

# Operation-name prefixes stripped before alias lookup so that MCP/Celery
# operation names collapse onto their underlying tool (e.g.
# ``argus.va.run_sqlmap`` → ``run_sqlmap`` → ``sqlmap`` → ``sqlmap_safe``).
_OP_PREFIXES: Final[tuple[str, ...]] = (
    "argus.va.run_",
    "argus.recon.run_",
    "argus.va.",
    "argus.recon.",
    "argus.",
    "run_",
)


def normalize_tool_name(name: str) -> str:
    """Lower-case and strip surrounding whitespace; the canonical lookup key."""
    return name.strip().lower()


def _fold_separators(key: str) -> str:
    """Fold ``-``, ``.`` and spaces to ``_`` (already-normalized input)."""
    return key.replace("-", "_").replace(".", "_").replace(" ", "_")


def resolve_tool_alias(name: str) -> str | None:
    """Return the canonical ``tool_id`` for an alias, or ``None``.

    ``None`` means *name is not a known alias* — it may still be a canonical
    ``tool_id`` on its own, which is what :func:`canonical_tool_id` decides
    with knowledge of the real catalog. Operation prefixes are stripped
    recursively so both ``run_sqlmap`` and ``argus.va.run_sqlmap`` resolve.
    """
    key = normalize_tool_name(name)
    if not key:
        return None
    if key in TOOL_ALIASES:
        return TOOL_ALIASES[key]
    for prefix in _OP_PREFIXES:
        if key.startswith(prefix) and len(key) > len(prefix):
            inner = key[len(prefix) :]
            deeper = resolve_tool_alias(inner)
            return deeper if deeper is not None else inner
    return None


def canonical_tool_id(name: str, known_ids: Iterable[str]) -> str | None:
    """Resolve any namespace name to a real catalog ``tool_id``.

    Precedence: exact identity → explicit/operation alias → separator fold.
    Returns ``None`` when the name cannot be reconciled to any id in
    ``known_ids`` (the caller decides whether that is a hard error).
    """
    ids = known_ids if isinstance(known_ids, (set, frozenset)) else set(known_ids)
    key = normalize_tool_name(name)
    if not key:
        return None
    if key in ids:
        return key
    resolved = resolve_tool_alias(key)
    if resolved is not None and resolved in ids:
        return resolved
    folded = _fold_separators(key)
    if folded in ids:
        return folded
    return None


def all_aliases() -> Mapping[str, str]:
    """Return a read-only view of the canonical alias table (for tests/tools)."""
    return dict(TOOL_ALIASES)


__all__ = [
    "TOOL_ALIASES",
    "VIRTUAL_TOOLS",
    "all_aliases",
    "canonical_tool_id",
    "normalize_tool_name",
    "resolve_tool_alias",
]
