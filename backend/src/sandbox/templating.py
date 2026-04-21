"""Safe command-template renderer for the ARGUS sandbox (Backlog/dev1_md §18).

Every command that hits a sandbox runner is materialised here. The renderer is
the **only** authorised path between a :class:`~src.pipeline.contracts.tool_job.ToolJob`
and an ``argv`` ``list[str]`` — no other module is allowed to interpolate
strings into shell commands.

Hard guarantees enforced for every render:

1. **No shell.** The output is always a ``list[str]`` suitable for
   ``subprocess.run(..., shell=False)``. Whitespace, quotes, NULs and other
   control characters are rejected from every placeholder value, so a value
   can never split a shlex-tokenised template into a new argv element.
2. **Allow-listed placeholders only.** Templates may reference exclusively
   the names in :data:`ALLOWED_PLACEHOLDERS`; any other ``{name}`` raises
   :class:`TemplateRenderError` with ``placeholder=name``.
3. **Per-placeholder type contracts.** Each placeholder name has a typed
   validator (URL, hostname, port, ``/wordlists/``-rooted path, hex canary,
   …). Path-traversal in ``out_dir`` / ``in_dir`` / ``wordlist`` is rejected.
4. **No format-string surprises.** ``str.format`` / ``str.format_map`` /
   ``eval`` are never invoked; substitution is a single ``re.sub`` pass with
   literal replacement.
5. **Argv-safe.** :func:`render_argv` (preferred for YAML descriptors)
   preserves argv boundaries exactly — placeholder values are never split.
   :func:`render` applies ``shlex.split`` *after* substitution; since every
   validator forbids whitespace/quotes, no value can introduce a new token.

The allow-list is canonicalised in
:mod:`src.pipeline.contracts._placeholders`; both this module and
:mod:`src.pipeline.contracts.tool_job` import the same frozenset so the
contract layer and the templating layer can never drift apart.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from collections.abc import Callable, Mapping
from typing import Final

from src.pipeline.contracts._placeholders import ALLOWED_PLACEHOLDERS

# Re-export the canonical allow-list under this module's public namespace so
# legacy imports (``from src.sandbox.templating import ALLOWED_PLACEHOLDERS``)
# keep working without forcing every caller to update its import path.
__all__ = [
    "ALLOWED_PLACEHOLDERS",
    "TemplateRenderError",
    "extract_placeholders",
    "redact_argv_for_logging",
    "render",
    "render_argv",
    "validate_template",
]

_PLACEHOLDER_RE: Final[re.Pattern[str]] = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
_PLACEHOLDER_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z_][a-z0-9_]{0,31}$")

# Universal "value-killers": whitespace, quoting, NUL, ASCII control chars.
# These break argv boundaries (shlex.split) or quote-escape contexts and have
# no legitimate use in any rendered placeholder. Forbidden EVERYWHERE.
_UNIVERSAL_BAD: Final[frozenset[str]] = frozenset(
    {"'", '"', " ", "\t", "\n", "\r", "\x00", "\v", "\f"}
)

# Strict-token forbidden set (only enforced by ``_validate_safe_token``).
# Per-placeholder validators with their own RFC-ish charsets (URL, host, etc.)
# do not need this; they enforce a positive regex instead.
_STRICT_FORBIDDEN: Final[frozenset[str]] = frozenset(
    {
        ";",
        "|",
        "&",
        "$",
        "`",
        "<",
        ">",
        "*",
        "?",
        "\\",
        "{",
        "}",
        "(",
        ")",
        "[",
        "]",
        "!",
        "#",
        "%",
    }
)

# Catch-all safe-token regex for placeholders without a stricter contract.
_SAFE_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_./:@,=\-]+$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TemplateRenderError(ValueError):
    """Raised when a template or value violates the safe-templating contract.

    ``placeholder`` is the offending placeholder name (or ``None`` for
    template-shape errors). ``reason`` is a short, value-free explanation
    suitable for structured logs — the placeholder VALUE is never echoed.
    """

    def __init__(self, reason: str, *, placeholder: str | None = None) -> None:
        super().__init__(reason)
        self.placeholder = placeholder
        self.reason = reason


# ---------------------------------------------------------------------------
# Per-placeholder validators
# ---------------------------------------------------------------------------


def _check_universal(name: str, value: str) -> None:
    """Universal value-killer rejection — runs from every per-placeholder validator."""
    if not value:
        raise TemplateRenderError("empty value", placeholder=name)
    for char in value:
        if char in _UNIVERSAL_BAD or ord(char) < 0x20 or ord(char) == 0x7F:
            raise TemplateRenderError(
                "forbidden whitespace / quote / control character in value",
                placeholder=name,
            )


def _validate_safe_token(name: str, value: str) -> None:
    """Catch-all: strict alphanumeric+symbol charset for unspecified placeholders."""
    _check_universal(name, value)
    if len(value) > 256:
        raise TemplateRenderError("value exceeds 256 chars", placeholder=name)
    for char in value:
        if char in _STRICT_FORBIDDEN:
            raise TemplateRenderError(
                "forbidden character in safe-token value",
                placeholder=name,
            )
    if not _SAFE_TOKEN_RE.fullmatch(value):
        raise TemplateRenderError(
            "value contains characters outside the safe-token charset",
            placeholder=name,
        )


def _validate_url(name: str, value: str) -> None:
    _check_universal(name, value)
    if len(value) > 2048:
        raise TemplateRenderError("URL exceeds 2048 chars", placeholder=name)
    # RFC 3986 unreserved / reserved / percent-encoded characters, plus
    # IPv6 literal brackets. Whitespace / quotes / control chars are already
    # rejected by ``_check_universal``; backslash is not a valid URL char.
    if not re.fullmatch(r"https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%\-\[\]]+", value):
        raise TemplateRenderError(
            "URL must start with http:// or https:// and use only RFC-3986 chars",
            placeholder=name,
        )


def _validate_host(name: str, value: str) -> None:
    _check_universal(name, value)
    if len(value) > 253:
        raise TemplateRenderError("host length out of range (1..253)", placeholder=name)
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    if not re.fullmatch(
        r"(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)"
        r"(\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*",
        value,
    ):
        raise TemplateRenderError(
            "host must be an RFC-1123 hostname or an IP literal",
            placeholder=name,
        )


def _validate_port(name: str, value: str) -> None:
    _check_universal(name, value)
    if not re.fullmatch(r"[0-9]{1,5}", value):
        raise TemplateRenderError("port must be a 1..5 digit integer", placeholder=name)
    port = int(value)
    if not 1 <= port <= 65_535:
        raise TemplateRenderError("port must be in 1..65535", placeholder=name)


def _validate_domain(name: str, value: str) -> None:
    _check_universal(name, value)
    if len(value) > 253:
        raise TemplateRenderError(
            "domain length out of range (1..253)", placeholder=name
        )
    if not re.fullmatch(
        r"(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)"
        r"(\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+",
        value,
    ):
        raise TemplateRenderError(
            "domain must follow RFC-1035 (labels separated by dots)",
            placeholder=name,
        )


def _validate_ip(name: str, value: str) -> None:
    _check_universal(name, value)
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise TemplateRenderError(
            "ip is not a valid IPv4 / IPv6 literal", placeholder=name
        ) from exc


def _validate_cidr(name: str, value: str) -> None:
    _check_universal(name, value)
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise TemplateRenderError(
            "cidr is not a valid IPv4 / IPv6 network", placeholder=name
        ) from exc


def _validate_ports(name: str, value: str) -> None:
    _check_universal(name, value)
    if not re.fullmatch(r"[0-9,\-]{1,128}", value):
        raise TemplateRenderError(
            "ports must be a comma/range list of digits (e.g. 80,443,1000-2000)",
            placeholder=name,
        )


def _validate_canary(name: str, value: str) -> None:
    _check_universal(name, value)
    if not re.fullmatch(r"[0-9a-f]{16,64}", value):
        raise TemplateRenderError(
            "canary must be 16..64 lowercase hex characters",
            placeholder=name,
        )


def _validate_sandbox_path(prefix: str) -> Callable[[str, str], None]:
    """Build a validator that constrains values to a sandbox-internal path.

    Two prefix shapes are supported, distinguished by the trailing slash:

    * **Directory anchor** (e.g. ``/wordlists/``) — the value MUST start with
      the full prefix string. This requires the value to reference something
      *inside* the directory; a bare ``/wordlists`` is refused.
    * **Exact anchor** (e.g. ``/out``, ``/in``) — the value MUST be exactly
      the prefix OR start with ``prefix + "/"``. This guards against
      look-alike absolute paths such as ``/output/foo`` or ``/out_evil`` that
      would slip past a naive ``startswith(prefix)`` check.

    Path traversal (``..``), null bytes, duplicated slashes, and unsafe
    characters are refused for both shapes.
    """

    has_trailing_slash = prefix.endswith("/")
    nested_anchor = prefix if has_trailing_slash else prefix + "/"

    def _validator(name: str, value: str) -> None:
        _check_universal(name, value)
        if len(value) > 1024:
            raise TemplateRenderError("path exceeds 1024 chars", placeholder=name)
        if has_trailing_slash:
            accepted = value.startswith(nested_anchor)
        else:
            accepted = value == prefix or value.startswith(nested_anchor)
        if not accepted:
            raise TemplateRenderError(
                f"path must start with {prefix!r}",
                placeholder=name,
            )
        if ".." in value.split("/"):
            raise TemplateRenderError(
                "path traversal segment ('..') is forbidden",
                placeholder=name,
            )
        if "//" in value:
            raise TemplateRenderError(
                "duplicated slashes are forbidden", placeholder=name
            )
        if not re.fullmatch(r"/[A-Za-z0-9_./\-]+", value):
            raise TemplateRenderError(
                "sandbox path uses an unsafe charset",
                placeholder=name,
            )

    return _validator


def _validate_proto(name: str, value: str) -> None:
    _check_universal(name, value)
    if not re.fullmatch(r"[a-z][a-z0-9_+\-]{1,15}", value):
        raise TemplateRenderError(
            "proto must be a short lowercase identifier (e.g. ssh, http, smb)",
            placeholder=name,
        )


# Whitelist of brute-force / credential-stuffing target protocols accepted by
# Hydra / Medusa / Patator / Ncrack scheme prefixes (§4.12). The list is the
# intersection of the four tools' supported modules — any new protocol must be
# added explicitly so a misspelt or unsupported scheme cannot reach the sandbox
# command line. ARG-017.
_AUTH_TARGET_PROTOS: Final[frozenset[str]] = frozenset(
    {
        "ssh",
        "ftp",
        "ftps",
        "telnet",
        "smtp",
        "smtps",
        "imap",
        "imaps",
        "pop3",
        "pop3s",
        "smb",
        "smb2",
        "rdp",
        "vnc",
        "ldap",
        "ldaps",
        "mysql",
        "mssql",
        "postgres",
        "redis",
        "mongodb",
        "http-get",
        "http-post-form",
        "https-get",
        "https-post-form",
        "snmp",
    }
)


def _validate_target_proto(name: str, value: str) -> None:
    """Auth-target protocol validator (§4.12).

    Distinct from :func:`_validate_proto` because Hydra-style URIs use ``-``
    in scheme names (``http-post-form``) and we must refuse anything not in
    the explicit allowlist — a free-form lowercase identifier is too loose
    for the scheme position of ``hydra ssh://target.example``.
    """
    _check_universal(name, value)
    if value not in _AUTH_TARGET_PROTOS:
        raise TemplateRenderError(
            "target_proto must be one of the auth-tool supported schemes",
            placeholder=name,
        )


def _validate_canary_callback(name: str, value: str) -> None:
    """Validate a fully-qualified OAST callback URL (§4.11).

    Restricts to ``http(s)://<host>[/path]`` shape; rejects userinfo,
    credentials, and IPv4/IPv6 literal hosts (callbacks must resolve
    through DNS so the OAST plane can correlate them). Length capped at
    256 bytes — a callback used in argv must stay short to fit in
    sandboxed env / argv budgets.
    """
    _check_universal(name, value)
    if len(value) > 256:
        raise TemplateRenderError("canary_callback exceeds 256 chars", placeholder=name)
    if not re.fullmatch(
        r"https?://"
        r"([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)"
        r"(\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+"
        r"(:[0-9]{1,5})?"
        r"(/[A-Za-z0-9._~/\-]{0,128})?",
        value,
    ):
        raise TemplateRenderError(
            "canary_callback must be http(s)://<host>[:port][/path] with "
            "DNS-1123 hostname (no userinfo, no IP literals)",
            placeholder=name,
        )


def _validate_alnum_id(max_len: int) -> Callable[[str, str], None]:
    """Build a validator for short alphanumeric identifiers."""

    def _validator(name: str, value: str) -> None:
        _check_universal(name, value)
        if not re.fullmatch(rf"[A-Za-z0-9._\-]{{1,{max_len}}}", value):
            raise TemplateRenderError(
                f"value must be 1..{max_len} of [A-Za-z0-9._-]",
                placeholder=name,
            )

    return _validator


def _validate_int_string(max_len: int) -> Callable[[str, str], None]:
    def _validator(name: str, value: str) -> None:
        _check_universal(name, value)
        if not re.fullmatch(rf"[0-9]{{1,{max_len}}}", value):
            raise TemplateRenderError(
                f"value must be 1..{max_len} digits",
                placeholder=name,
            )

    return _validator


def _validate_size(name: str, value: str) -> None:
    _check_universal(name, value)
    if not re.fullmatch(r"[0-9]{1,12}(?:,[0-9]{1,12})*", value):
        raise TemplateRenderError(
            "size must be one or more comma-separated integers",
            placeholder=name,
        )


def _validate_image(name: str, value: str) -> None:
    _check_universal(name, value)
    if len(value) > 256:
        raise TemplateRenderError("image ref exceeds 256 chars", placeholder=name)
    if not re.fullmatch(r"[a-z0-9][a-z0-9._/:@\-]+", value):
        raise TemplateRenderError(
            "image ref must look like 'repo[/path]:tag[@sha256:...]'",
            placeholder=name,
        )


def _validate_params_csv(name: str, value: str) -> None:
    _check_universal(name, value)
    if not re.fullmatch(r"[A-Za-z0-9_,]{1,1024}", value):
        raise TemplateRenderError(
            "params must be a comma-separated list of [A-Za-z0-9_] tokens",
            placeholder=name,
        )


# ARG-019 §4.17 network-layer interface label (Responder, Hostapd, ettercap…).
# Linux kernel caps interface names at 15 chars (``IFNAMSIZ - 1``); we
# additionally restrict to alnum + ``._-`` to refuse any shell metachar even
# under the universal allowlist (no ``:``, no ``/``).
_IFACE_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,14}$"
)


def _validate_interface(name: str, value: str) -> None:
    _check_universal(name, value)
    if not _IFACE_NAME_RE.fullmatch(value):
        raise TemplateRenderError(
            "interface must be 1..15 chars of [A-Za-z0-9._-] (Linux IFNAMSIZ)",
            placeholder=name,
        )


# ARG-019 §4.17 LDAP / AD distinguished-name base (LDAP / Kerberos / AD
# enumerators: ldapsearch, kerbrute, bloodhound-python). RFC 4514 allows a
# generous charset, but we lock to the practical AD subset
# (``DC=``/``OU=``/``CN=``/``O=``/``L=`` + alnum + ``-`` + ``,``) — every
# real-world tenant fits, while rejecting LDAP injection meta-chars
# (``\``, ``/``, ``*``, ``(``, ``)``, ``;``, ``\x00``).
_BASEDN_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:DC|OU|CN|O|L|ST|C|UID)=[A-Za-z0-9 _.\-]{1,64}"
    r"(?:,(?:DC|OU|CN|O|L|ST|C|UID)=[A-Za-z0-9 _.\-]{1,64}){0,15}$"
)


def _validate_basedn(name: str, value: str) -> None:
    _check_universal(name, value)
    if len(value) > 512:
        raise TemplateRenderError("basedn exceeds 512 chars", placeholder=name)
    if not _BASEDN_RE.fullmatch(value):
        raise TemplateRenderError(
            "basedn must be a comma-separated RDN list "
            "(e.g. DC=corp,DC=local) using AD-subset attribute names",
            placeholder=name,
        )


# ARG-019 §4.18/§4.19 Authentication credential validator.
#
# **Deferred secret-store integration.** Today the auth-required tools that
# carry ``{user}`` / ``{pass}`` placeholders (impacket-secretsdump, evil-winrm,
# bloodhound-python, ntlmrelayx, smbclient…) receive credentials inline via
# the same templating pipeline as any other placeholder. This is acceptable
# only because:
#
#  1. The catalog tags every such tool with ``requires_approval: true``
#     (≥ 2 approvers) — the credential value never reaches the renderer
#     until a human reviewer has signed off on the job.
#  2. The validator below refuses whitespace, quoting, control chars,
#     ``${...}``-style shell expansion, and back-tick / pipe metacharacters,
#     so the value cannot ever break out of an argv slot or get re-evaluated
#     by an inner ``sh -c`` template.
#  3. Argv values are scrubbed before any ``argv``-bearing artefact is
#     persisted on disk: the sandbox calls
#     :func:`redact_argv_for_logging` (defined below) to replace every
#     credential placeholder value (``{user}`` / ``{pass}`` / ``{u}`` /
#     ``{p}`` / ``{password}`` / ``{username}``) with the literal token
#     ``[REDACTED]`` before serialising the dry-run argv JSON or emitting
#     any structured log record that carries ``argv`` in its ``extra``.
#     The unredacted argv only ever leaves the renderer as the in-memory
#     ``container.command`` list applied directly to the live Kubernetes
#     Job manifest; it is never written to disk and never echoed back into
#     ``logging``.
#
# **Migration path** (tracked under ARG-024 in the cycle backlog): when the
# secret store lands, ``ToolJob`` will accept ``{user}``/``{pass}`` only as
# **opaque secret references** (``vault://kv/data/argus/<scan_id>/<role>``);
# the dispatcher will resolve them out-of-band at sandbox-bind time and the
# argv-side placeholder will be hardened to refuse anything that doesn't
# match the secret-ref schema. Until then, the alnum_id contract below is
# the load-bearing guardrail.
_CREDENTIAL_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._@\-/+=]{1,128}$")


def _validate_credential(name: str, value: str) -> None:
    """Strict validator for ``{user}`` / ``{pass}`` placeholders (§4.17–§4.19).

    Wider than ``_validate_alnum_id(128)`` (we allow ``@``, ``/``, ``+``,
    ``=`` so passwords containing base64 padding or domain-prefixed user
    principals like ``svc@CORP.LOCAL`` pass), but still refuses every shell
    metacharacter and control sequence — see the deferred-secret-store
    comment above.
    """
    _check_universal(name, value)
    if not _CREDENTIAL_RE.fullmatch(value):
        raise TemplateRenderError(
            "credential value must be 1..128 of [A-Za-z0-9._@\\-/+=] "
            "(deferred: full secret-store integration tracked under ARG-024)",
            placeholder=name,
        )


_PLACEHOLDER_VALIDATORS: Final[dict[str, Callable[[str, str], None]]] = {
    "url": _validate_url,
    "host": _validate_host,
    "port": _validate_port,
    "domain": _validate_domain,
    "ip": _validate_ip,
    "cidr": _validate_cidr,
    "params": _validate_params_csv,
    "wordlist": _validate_sandbox_path("/wordlists/"),
    "canary": _validate_canary,
    "out_dir": _validate_sandbox_path("/out"),
    "in_dir": _validate_sandbox_path("/in"),
    "ports": _validate_ports,
    "ports_range": _validate_ports,
    "proto": _validate_proto,
    "community": _validate_alnum_id(64),
    "community_string": _validate_alnum_id(64),
    # ``{u}`` / ``{p}`` keep the historical short-form alnum_id contract for
    # backwards compatibility with §4.12 evil-winrm flag style; the canonical
    # ``{user}`` / ``{pass}`` use the wider credential charset (see
    # ``_validate_credential`` for the deferred secret-store rationale).
    "u": _validate_alnum_id(128),
    "p": _validate_alnum_id(128),
    "user": _validate_credential,
    "pass": _validate_credential,
    "fmt": _validate_alnum_id(32),
    "mode": _validate_int_string(5),
    "module": _validate_alnum_id(64),
    "mod": _validate_alnum_id(64),
    "org": _validate_alnum_id(128),
    "profile": _validate_alnum_id(64),
    "image": _validate_image,
    "session": _validate_alnum_id(64),
    "dc": _validate_host,
    "size": _validate_size,
    "safe": _validate_url,
    "rand": _validate_alnum_id(64),
    "s": _validate_alnum_id(64),
    # ARG-017 §4.11..4.13 additions.
    "hashes_file": _validate_sandbox_path("/in"),
    "canary_callback": _validate_canary_callback,
    "target_proto": _validate_target_proto,
    # ARG-018 §4.14/§4.15/§4.16 — sandbox-mounted source / IaC / artefact path.
    # Pinned to ``/in`` so SAST / SCA / IaC tools can only read from the
    # caller-mounted bundle (path traversal + duplicated-slash already refused
    # by the shared sandbox-path validator).
    "path": _validate_sandbox_path("/in"),
    # ARG-019 §4.17/§4.18/§4.19 — network protocol / binary / browser tools.
    # ``{interface}`` is a Linux IFNAMSIZ-bounded NIC label, ``{basedn}`` is
    # an AD-subset Distinguished Name, and ``{file}``/``{binary}``/``{script}``
    # are sandbox-rooted ``/in/``-prefixed paths (path traversal already
    # refused by the shared sandbox-path validator).
    "interface": _validate_interface,
    "basedn": _validate_basedn,
    "binary": _validate_sandbox_path("/in"),
    "file": _validate_sandbox_path("/in"),
    "script": _validate_sandbox_path("/in"),
    "scan_id": _validate_alnum_id(64),
    "tenant_id": _validate_alnum_id(64),
}


# ---------------------------------------------------------------------------
# Template inspection
# ---------------------------------------------------------------------------


def extract_placeholders(template: str | list[str]) -> set[str]:
    """Return the set of placeholder names referenced by ``template``.

    Accepts either a single string template or a list of token templates
    (the form stored in ``ToolDescriptor.command_template``).
    """
    tokens = template if isinstance(template, list) else [template]
    found: set[str] = set()
    for token in tokens:
        for match in _PLACEHOLDER_RE.finditer(token):
            found.add(match.group(1))
    return found


def validate_template(template: str | list[str]) -> set[str]:
    """Verify a template references only allow-listed placeholders.

    Returns the set of placeholder names found. Raises
    :class:`TemplateRenderError` with ``placeholder`` set when any name is
    outside :data:`ALLOWED_PLACEHOLDERS`. Used by
    :class:`~src.sandbox.tool_registry.ToolRegistry` at startup to fail closed
    on typos before any sandbox job is dispatched.
    """
    found = extract_placeholders(template)
    for name in sorted(found):
        if not _PLACEHOLDER_NAME_RE.fullmatch(name):
            raise TemplateRenderError("placeholder name is malformed", placeholder=name)
        if name not in ALLOWED_PLACEHOLDERS:
            raise TemplateRenderError(
                "placeholder is not in the sandbox allow-list",
                placeholder=name,
            )
    return found


# ---------------------------------------------------------------------------
# Substitution
# ---------------------------------------------------------------------------


def _validate_value(name: str, value: str) -> None:
    if not isinstance(value, str):
        raise TemplateRenderError(
            "placeholder value must be a string", placeholder=name
        )
    validator = _PLACEHOLDER_VALIDATORS.get(name, _validate_safe_token)
    validator(name, value)


def _substitute(token: str, context: Mapping[str, str]) -> str:
    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in ALLOWED_PLACEHOLDERS:
            raise TemplateRenderError(
                "placeholder is not in the sandbox allow-list",
                placeholder=name,
            )
        if name not in context:
            raise TemplateRenderError(
                "placeholder has no value in render context",
                placeholder=name,
            )
        value = context[name]
        _validate_value(name, value)
        return value

    return _PLACEHOLDER_RE.sub(_replace, token)


def render_argv(template_tokens: list[str], context: Mapping[str, str]) -> list[str]:
    """Render a pre-tokenised template (``ToolDescriptor.command_template``).

    Each entry of ``template_tokens`` becomes exactly one argv element;
    placeholder values never split across boundaries. Returns a fresh
    ``list[str]`` ready for ``subprocess.run(argv, shell=False)``.

    Raises :class:`TemplateRenderError` for any unknown placeholder, missing
    value, or value that fails its per-placeholder contract.
    """
    if not template_tokens:
        raise TemplateRenderError("template_tokens must be a non-empty list")
    rendered: list[str] = []
    for token in template_tokens:
        if not isinstance(token, str):
            raise TemplateRenderError("template tokens must be strings")
        if not token:
            raise TemplateRenderError("template tokens must be non-empty")
        rendered.append(_substitute(token, context))
    return rendered


def render(template: str, context: Mapping[str, str]) -> list[str]:
    """Render a single string template into an argv list.

    Substitution happens *before* ``shlex.split``; because per-placeholder
    validators forbid whitespace and quoting, no value can ever introduce a
    new argv element or shell directive after splitting.

    The list-form :func:`render_argv` is preferred for descriptors stored in
    YAML (it never round-trips through a shell parser). This string form
    exists for ad-hoc human-authored templates and tests.
    """
    if not isinstance(template, str):
        raise TemplateRenderError("template must be a string")
    if not template.strip():
        raise TemplateRenderError("template must not be empty")
    substituted = _substitute(template, context)
    argv = shlex.split(substituted, posix=True)
    if not argv:
        raise TemplateRenderError("template rendered to an empty argv")
    return argv


# ---------------------------------------------------------------------------
# Credential redaction for safe argv logging / persistence (ARG-019 C4)
# ---------------------------------------------------------------------------


# Placeholder names that carry credential material per the §4.17/§4.18/§4.19
# catalog: the long-form ``user``/``pass``/``password``/``username`` and the
# short-form ``u``/``p`` historically used by §4.12 evil-winrm flag style.
# Kept in lockstep with ``_PLACEHOLDER_VALIDATORS``: any new credential-typed
# placeholder MUST be added here OR the redaction layer will silently leak it
# into dry-run artefacts and structured logs.
_CREDENTIAL_PLACEHOLDER_NAMES: Final[frozenset[str]] = frozenset(
    {"user", "pass", "p", "u", "password", "username"}
)


# Sentinel emitted in place of every redacted argv token. Using a literal
# (rather than e.g. ``"***"``) makes it greppable in incident response and
# trivially distinguishable from a value that legitimately contains stars.
_REDACTION_SENTINEL: Final[str] = "[REDACTED]"


def redact_argv_for_logging(
    argv: list[str],
    placeholder_values: Mapping[str, str] | None = None,
) -> list[str]:
    """Replace credential values in ``argv`` with ``[REDACTED]`` for safe logging.

    Used by:
      * :mod:`src.sandbox.k8s_adapter` before writing the dry-run argv JSON
        artefact (``_write_dry_run_artifacts``) so the on-disk dump under
        ``dry_run_artifact_dir`` never echoes ``{user}``/``{pass}`` values.
      * :mod:`src.sandbox.k8s_adapter` before any structured logger call
        whose ``extra`` carries the rendered argv (today: none — guarded
        upfront so future logging additions stay safe).

    Args:
        argv: rendered command argument vector (output of
            :func:`render_argv` or :func:`render`).  The list is NOT
            mutated; a fresh list is returned in every case.
        placeholder_values: mapping of placeholder name → substituted
            string value (typically ``ToolJob.parameters``).  When
            ``None`` or empty, ``argv`` is returned unchanged (no
            credentials in scope means nothing to redact).

    Returns:
        A new ``list[str]`` of the same length as ``argv``, with every
        token whose value matches a credential-typed placeholder in
        ``placeholder_values`` replaced by :data:`_REDACTION_SENTINEL`
        (``"[REDACTED]"``).  Non-credential tokens pass through
        verbatim.

    Notes:
        * Redaction is value-based (exact string match), not
          position-based: tools that splice the credential into a
          composite argv token (e.g. ``-u{user}``) will only have the
          composite token redacted when the WHOLE token equals the
          credential value.  All §4.17 / §4.18 / §4.19 YAMLs use the
          ``["-u", "{user}"]`` two-token style precisely so redaction
          works token-by-token.
        * Empty credential values are skipped — there is nothing to
          match and ``[REDACTED]`` would alias every empty token.
    """
    if not placeholder_values:
        return list(argv)

    sensitive_values = {
        str(value)
        for name, value in placeholder_values.items()
        if name in _CREDENTIAL_PLACEHOLDER_NAMES and value
    }
    if not sensitive_values:
        return list(argv)

    return [
        _REDACTION_SENTINEL if token in sensitive_values else token for token in argv
    ]
