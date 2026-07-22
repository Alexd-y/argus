"""Web Workbench extension platform (WB-P8).

The offline core is a **declarative check DSL** (BCheck-like): signed, data-only
security checks with matchers/groups/extractors and a FindingDTO mapping. Like
playbooks, a check is *data, not code* — it can never carry Python, shell
strings, or import paths (fail-closed ``extra="forbid"`` + frozen models).
"""

from src.web_workbench.extensions.check_dsl import (
    BooleanOp,
    CheckFinding,
    CheckScope,
    DeclarativeCheck,
    DslError,
    Extractor,
    Matcher,
    MatcherGroup,
    MatcherKind,
    MessagePart,
    check_finding_to_dto,
    evaluate_check,
    evaluate_checks,
    load_check,
)
from src.web_workbench.extensions.manifest import (
    ExtensionManifest,
    ExtensionPermission,
    ExtensionProvenance,
    ManifestError,
    SbomComponent,
    load_manifest,
    parse_manifest_bytes,
    verify_and_load,
)

__all__ = [
    "BooleanOp",
    "CheckFinding",
    "CheckScope",
    "DeclarativeCheck",
    "DslError",
    "ExtensionManifest",
    "ExtensionPermission",
    "ExtensionProvenance",
    "Extractor",
    "ManifestError",
    "Matcher",
    "MatcherGroup",
    "MatcherKind",
    "MessagePart",
    "SbomComponent",
    "check_finding_to_dto",
    "evaluate_check",
    "evaluate_checks",
    "load_check",
    "load_manifest",
    "parse_manifest_bytes",
    "verify_and_load",
]
