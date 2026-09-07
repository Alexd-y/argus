"""Full-Surface credential-testing authorization policy.

Encodes the engagement rule: **credential brute-force / password testing is
authorized automatically only for the Full Surface profile** (``scan_profile=deep``
/ LAB execution). For every other profile it is force-disabled, even if a config
explicitly enabled it — a lighter scan must never turn into an account-locking
brute-force.

For Full Surface, when the operator supplies no (or a disabled) credential-testing
config, ARGUS provides a bounded default drawn from its own wordlist base
(curated default-credentials + top username/password lists), so the pipeline can
run WSTG-ATHN-02/03 without the operator hand-specifying credentials. The actual
``login_url`` is discovered during recon; username candidates can be augmented by
OSINT/LLM permutations downstream.
"""

from __future__ import annotations

from src.orchestration.auth_config import CredentialTestConfig

#: Profiles / execution modes that authorize credential brute-force.
FULL_SURFACE_PROFILES: frozenset[str] = frozenset({"deep"})
FULL_SURFACE_EXECUTION_MODES: frozenset[str] = frozenset({"lab", "lab_unrestricted"})


def is_full_surface(
    *,
    scan_profile: str | None = None,
    execution_mode: str | None = None,
) -> bool:
    """True when the scan is a Full Surface engagement (brute-force authorized)."""
    if scan_profile and str(scan_profile).strip().lower() in FULL_SURFACE_PROFILES:
        return True
    return bool(
        execution_mode and str(execution_mode).strip().lower() in FULL_SURFACE_EXECUTION_MODES
    )


def default_full_surface_credential_testing() -> CredentialTestConfig:
    """ARGUS's bounded default credential-testing set for Full Surface scans."""
    return CredentialTestConfig(
        enabled=True,
        credential_pair_wordlist="argus-default-credentials",
        username_wordlist="seclists-usernames-top",
        password_wordlist="seclists-passwords-top1000",
        max_attempts=500,
        rate_per_minute=60,
        lockout_aware=True,
        stop_on_success=True,
    )


def resolve_credential_testing(
    config: CredentialTestConfig | None,
    *,
    scan_profile: str | None = None,
    execution_mode: str | None = None,
) -> CredentialTestConfig | None:
    """Apply the Full-Surface authorization rule to a credential-testing config.

    * Not Full Surface → brute-force is unauthorized: a provided config is
      force-disabled (``enabled=False``); ``None`` stays ``None``.
    * Full Surface → authorized: an explicitly-enabled config is kept as-is; a
      missing/disabled config is replaced by ARGUS's bounded default set.
    """
    full = is_full_surface(scan_profile=scan_profile, execution_mode=execution_mode)
    if not full:
        if config is not None and config.enabled:
            return config.model_copy(update={"enabled": False})
        return config
    if config is None or not config.enabled:
        return default_full_surface_credential_testing()
    return config


__all__ = [
    "FULL_SURFACE_EXECUTION_MODES",
    "FULL_SURFACE_PROFILES",
    "default_full_surface_credential_testing",
    "is_full_surface",
    "resolve_credential_testing",
]
