"""NucleiProfileCompiler — single argv builder for all nuclei invocations (§9.1)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlparse

import yaml

from src.core.unified_ai_metrics import record_nuclei_request
from src.eval.rates import record_template_compile
from src.execution_mode.mode import ExecutionMode, parse_execution_mode
from src.nuclei.schemas import NucleiCompileRequest, ScanProfile

_BACKEND_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
PROFILE_DIR: Final[Path] = _BACKEND_ROOT / "config" / "nuclei" / "profiles"
ARGUS_NUCLEI_TEMPLATES_DIR: Final[Path] = (
    _BACKEND_ROOT / "config" / "nuclei-templates" / "argus"
).resolve()


def _safe_http_url_for_argv(url: str) -> str | None:
    """Local copy of VA argv URL gate — avoids importing VA packages (circular import)."""
    u = (url or "").strip()
    if not u or len(u) > 2048:
        return None
    if any(c in u for c in ("\n", "\r", "\0", " ")):
        return None
    parsed = urlparse(u)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    return u


def _resolve_argus_templates_dir(candidate: str | Path | None = None) -> Path | None:
    """Accept only the repo-internal argus templates directory (G-6)."""
    if candidate is None:
        return ARGUS_NUCLEI_TEMPLATES_DIR if ARGUS_NUCLEI_TEMPLATES_DIR.is_dir() else None
    try:
        resolved = Path(candidate).resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if resolved == ARGUS_NUCLEI_TEMPLATES_DIR:
        return resolved
    if ARGUS_NUCLEI_TEMPLATES_DIR in resolved.parents:
        return resolved
    return None


def _coerce_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(str(v) for v in value)
    return (str(value),)


def load_scan_profile(profile: str | ScanProfile) -> ScanProfile:
    """Load a profile by id from ``backend/config/nuclei/profiles/``."""
    if isinstance(profile, ScanProfile):
        return profile
    profile_id = str(profile).strip()
    if not profile_id:
        raise ValueError("nuclei_profile_id_empty")
    path = PROFILE_DIR / f"{profile_id}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"nuclei_profile_not_found:{profile_id}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"nuclei_profile_invalid_yaml:{profile_id}")
    return ScanProfile.model_validate(raw)


_QUICK_DEFAULT_PROFILE_ID: Final[str] = "quick-default"
_QUICK_FALLBACK_PROFILE_ID: Final[str] = "fingerprint_safe"


def default_profile_id_for_mode(mode: str | ExecutionMode | None) -> str:
    """LAB → ``lab_unrestricted``; Quick → ``quick-default`` (else ``fingerprint_safe``)."""
    resolved = parse_execution_mode(mode)
    match resolved:
        case ExecutionMode.LAB_UNRESTRICTED:
            return "lab_unrestricted"
        case ExecutionMode.QUICK:
            quick_path = PROFILE_DIR / f"{_QUICK_DEFAULT_PROFILE_ID}.yaml"
            if quick_path.is_file():
                return _QUICK_DEFAULT_PROFILE_ID
            return _QUICK_FALLBACK_PROFILE_ID
        case ExecutionMode.PRODUCTION:
            return "vuln_default"
        case _:
            raise ValueError(f"unsupported_execution_mode:{resolved}")


def _is_lab_context(mode: ExecutionMode) -> bool:
    return mode is ExecutionMode.LAB_UNRESTRICTED


def _profile_provenance_hash(profile: ScanProfile) -> str:
    payload = profile.model_dump(mode="json")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class NucleiProfileCompiler:
    """Compile nuclei CLI argv from profile + mode — no duplicate argv builders."""

    @staticmethod
    def compile(
        profile: str | ScanProfile,
        mode: str | ExecutionMode,
        target_url: str,
        templates: Sequence[str] | None = None,
        *,
        use_argus_templates: bool = False,
        templates_dir: str | Path | None = None,
        allow_code: bool | None = None,
        allow_headless: bool | None = None,
        allow_javascript: bool | None = None,
        silent: bool = True,
        timeout_s: int | None = None,
        retries: int | None = None,
    ) -> list[str]:
        request = NucleiCompileRequest(
            profile=profile if isinstance(profile, ScanProfile) else str(profile),
            mode=str(mode),
            target_url=target_url,
            templates=tuple(templates or ()),
            use_argus_templates=use_argus_templates,
            templates_dir=str(templates_dir) if templates_dir is not None else None,
            allow_code=allow_code,
            allow_headless=allow_headless,
            allow_javascript=allow_javascript,
            silent=silent,
            timeout_s=timeout_s,
            retries=retries,
        )
        return NucleiProfileCompiler.compile_request(request)

    @staticmethod
    def compile_request(request: NucleiCompileRequest) -> list[str]:
        try:
            argv = NucleiProfileCompiler._compile_argv(request)
        except ValueError:
            record_template_compile(ok=False)
            raise
        record_template_compile(ok=bool(argv))
        return argv

    @staticmethod
    def _compile_argv(request: NucleiCompileRequest) -> list[str]:
        resolved_profile = (
            request.profile
            if isinstance(request.profile, ScanProfile)
            else load_scan_profile(request.profile)
        )
        resolved_mode = parse_execution_mode(request.mode)
        u = _safe_http_url_for_argv(request.target_url)
        if not u:
            return []

        match resolved_mode:
            case ExecutionMode.LAB_UNRESTRICTED:
                lab = _is_lab_context(resolved_mode)
            case ExecutionMode.PRODUCTION | ExecutionMode.QUICK:
                if resolved_profile.is_lab_unrestricted:
                    raise ValueError("lab_profile_requires_lab_unrestricted_mode")
                lab = _is_lab_context(resolved_mode)
            case _:
                raise ValueError(f"unsupported_execution_mode:{resolved_mode}")
        argv: list[str] = ["nuclei", "-u", u, "-jsonl", "-duc"]

        if not lab:
            argv.append("-ni")
            if resolved_profile.rate_limit_rps is not None:
                argv.extend(["-rate-limit", str(resolved_profile.rate_limit_rps)])
            if resolved_profile.concurrency is not None:
                argv.extend(["-c", str(resolved_profile.concurrency)])
            if resolved_profile.payload_concurrency is not None:
                argv.extend(["-pc", str(resolved_profile.payload_concurrency)])
            if resolved_profile.max_host_errors is not None:
                argv.extend(["-mhe", str(resolved_profile.max_host_errors)])
            if resolved_profile.max_requests_total is not None:
                argv.extend(["-rlm", str(resolved_profile.max_requests_total)])
            severity_allow = _coerce_tuple(resolved_profile.severity_allow)
            if severity_allow:
                argv.extend(["-severity", ",".join(severity_allow)])
            if resolved_profile.disable_code:
                argv.append("-disable-code")
            if resolved_profile.disable_javascript:
                argv.append("-disable-javascript")
            if resolved_profile.disable_headless:
                argv.append("-headless=false")
        else:
            # LAB: never inject conservative caps or disable flags (§9.6)
            code_allowed = (
                request.allow_code
                if request.allow_code is not None
                else resolved_profile.allow_code
            )
            headless_allowed = (
                request.allow_headless
                if request.allow_headless is not None
                else resolved_profile.allow_headless
            )
            js_allowed = (
                request.allow_javascript
                if request.allow_javascript is not None
                else resolved_profile.allow_javascript
            )
            if code_allowed:
                argv.append("-code")
            if headless_allowed:
                argv.append("-headless")
            if js_allowed:
                argv.append("-enable-javascript")

        timeout_val = request.timeout_s
        if timeout_val is None and isinstance(resolved_profile.timeout_s, int):
            timeout_val = resolved_profile.timeout_s
        if timeout_val is not None:
            argv.extend(["-timeout", str(timeout_val)])

        retries_val = request.retries
        if retries_val is None and isinstance(resolved_profile.retries, int):
            retries_val = resolved_profile.retries
        if retries_val is not None:
            argv.extend(["-retries", str(retries_val)])

        if request.silent:
            argv.append("-silent")

        template_paths: list[str] = list(request.templates)
        if request.use_argus_templates or request.templates_dir is not None:
            resolved_dir = _resolve_argus_templates_dir(request.templates_dir)
            if resolved_dir is not None and resolved_dir.is_dir():
                template_paths.append(str(resolved_dir))
        for tpl in template_paths:
            if tpl.strip():
                argv.extend(["-t", tpl.strip()])

        # Provenance hash is recorded for audit; not passed to CLI.
        _profile_provenance_hash(resolved_profile)
        record_nuclei_request(profile=resolved_profile.id, mode=resolved_mode.value)
        return argv
