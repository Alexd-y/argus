"""Structured payload-build context (Backlog T3/T4).

:class:`PayloadContext` is the typed carrier of everything a payload template
needs at render time — the injection ``sink_type``, a unique ``canary`` marker,
the out-of-band ``oast_host`` callback domain, the target parameter, and the
baseline identifier used to derive IDOR neighbour probes. It replaces the ad-hoc
``{"url", "param", "user_input"}`` dictionary that previously left placeholders
like ``{canary}`` / ``{oast_host}`` / ``{baseline_id_minus_one}`` unresolved,
which forced :class:`~src.payloads.builder.PayloadBuilder` to raise and callers
to drop to a raw-LLM fallback.

The context never carries secrets into the placeholder map: ``auth_context``
(tokens / session cookies) is kept as executor-side metadata and is *never*
projected into template parameters, so signed catalog payloads cannot leak
credentials.

Encoding selection is driven by :func:`select_encoding_pipeline`, which only
ever returns a pipeline name the target family actually declares (or ``None``
to keep the family default). This guarantees sink-type routing can never
synthesise an "unknown encoding pipeline" error.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, StrictStr


class SinkType(StrEnum):
    """Where a payload is injected — drives encoding-pipeline selection.

    Values are lowercase so they round-trip cleanly through JSON and match the
    strings emitted by upstream finding producers (parsers / CWE agents).
    """

    URL = "url"
    QUERY = "query"
    PATH = "path"
    BODY = "body"
    JSON = "json"
    XML = "xml"
    HEADER = "header"
    COOKIE = "cookie"
    GRAPHQL = "graphql"
    HTML = "html"
    HTML_ATTR = "html_attr"
    GENERIC = "generic"


# Ordered encoding-pipeline preferences per sink type. The builder walks the
# tuple and selects the first name the target family declares; if none match it
# falls back to the family default (its first-declared pipeline, always
# ``identity``). Only names that can legitimately exist in the signed catalog
# appear here — currently: identity, url_only, html_entity, unicode_only.
_SINK_PIPELINE_PRIORITY: Final[dict[SinkType, tuple[str, ...]]] = {
    # URL / header / cookie sinks are URL-decoded by the server, so percent
    # encoding survives transport and reaches the vulnerable reflection point.
    SinkType.URL: ("url_only", "identity"),
    SinkType.QUERY: ("url_only", "identity"),
    SinkType.PATH: ("url_only", "identity"),
    SinkType.HEADER: ("url_only", "identity"),
    SinkType.COOKIE: ("url_only", "identity"),
    # HTML / XML reflection contexts want entity encoding for the delivery step.
    SinkType.HTML: ("html_entity", "unicode_only", "identity"),
    SinkType.HTML_ATTR: ("html_entity", "unicode_only", "identity"),
    SinkType.XML: ("html_entity", "identity"),
    # Structured bodies must NOT be percent-encoded — that would corrupt the
    # JSON/GraphQL grammar before it reaches the parser. Ship the raw bytes.
    SinkType.JSON: ("identity",),
    SinkType.BODY: ("identity",),
    SinkType.GRAPHQL: ("identity",),
    SinkType.GENERIC: ("identity",),
}

# RFC 6761 reserved TLD: never resolves, so payloads referencing an OAST host
# stay inert until a real out-of-band lease is wired in (Backlog P2). Using it
# keeps the builder path deterministic without emitting live callbacks.
DEFAULT_OAST_PLACEHOLDER: Final[str] = "oast.invalid"

# Deterministic base used when no numeric baseline is available, so IDOR
# templates ``{baseline_id_minus_one}`` / ``{baseline_id_plus_one}`` still build.
_DEFAULT_IDOR_BASE: Final[int] = 100_000


def select_encoding_pipeline(available: Iterable[str], sink_type: SinkType) -> str | None:
    """Return the best declared pipeline name for ``sink_type``.

    ``available`` is the set of pipeline names the target family declares.
    Returns ``None`` when the family declares no matching pipeline, signalling
    the builder to keep its default (first-declared) pipeline. The return value
    is therefore always either ``None`` or a name present in ``available`` — the
    function never invents a pipeline the family lacks.
    """
    names = set(available)
    for candidate in _SINK_PIPELINE_PRIORITY.get(sink_type, ("identity",)):
        if candidate in names:
            return candidate
    return None


class PayloadContext(BaseModel):
    """Typed placeholder + routing context for a single payload build.

    All fields are optional so the context degrades gracefully: only the
    non-``None`` fields are projected into template parameters by
    :meth:`to_parameters`, and explicit ``PayloadBuildRequest.parameters`` still
    win over context-derived values at merge time.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    sink_type: SinkType = SinkType.GENERIC
    # Optional explicit encoding-pipeline pin. When set AND declared by the
    # target family, it overrides sink-type routing; otherwise the builder falls
    # back to :func:`select_encoding_pipeline`. Never projected as a template
    # placeholder — it is build-time routing metadata only.
    encoding_pipeline: StrictStr | None = Field(default=None, max_length=64)
    target_url: StrictStr | None = Field(default=None, max_length=2048)
    parameter_name: StrictStr | None = Field(default=None, max_length=256)
    parameter_value: StrictStr | None = Field(default=None, max_length=8192)
    canary: StrictStr | None = Field(default=None, max_length=128)
    oast_host: StrictStr | None = Field(default=None, max_length=256)
    baseline_id: StrictStr | None = Field(default=None, max_length=128)
    target_domain: StrictStr | None = Field(default=None, max_length=256)
    # Session tokens / cookies for authenticated probing. Executor-side metadata
    # ONLY — never projected into template parameters (secret-leak guard).
    auth_context: dict[StrictStr, StrictStr] | None = Field(default=None)

    def to_parameters(self) -> dict[str, str]:
        """Project the context into the placeholder map consumed by templates.

        Only non-``None`` fields are emitted. ``auth_context`` is deliberately
        excluded so credentials never reach signed payload templates. IDOR
        neighbour probes are always emitted (harmless extra keys for families
        that don't reference them) so ``{baseline_id_minus_one}`` /
        ``{baseline_id_plus_one}`` templates build deterministically.
        """
        params: dict[str, str] = {}
        if self.target_url is not None:
            params["url"] = self.target_url
        if self.parameter_name is not None:
            params["param"] = self.parameter_name
        if self.parameter_value is not None:
            params["user_input"] = self.parameter_value
        if self.canary is not None:
            params["canary"] = self.canary
        if self.oast_host is not None:
            params["oast_host"] = self.oast_host
        if self.baseline_id is not None:
            params["baseline_id"] = self.baseline_id
        if self.target_domain is not None:
            params["target_domain"] = self.target_domain

        base = self._numeric_baseline()
        params["baseline_id_minus_one"] = str(base - 1)
        params["baseline_id_plus_one"] = str(base + 1)
        return params

    def _numeric_baseline(self) -> int:
        """Best-effort integer baseline from parameter_value / baseline_id."""
        for candidate in (self.parameter_value, self.baseline_id):
            if candidate is None:
                continue
            stripped = candidate.strip()
            if stripped.lstrip("-").isdigit():
                return int(stripped)
        return _DEFAULT_IDOR_BASE


__all__ = [
    "DEFAULT_OAST_PLACEHOLDER",
    "PayloadContext",
    "SinkType",
    "select_encoding_pipeline",
]
