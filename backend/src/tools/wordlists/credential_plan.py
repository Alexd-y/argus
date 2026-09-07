"""Bridge CredentialTestConfig → resolved wordlist files for brute-force adapters.

``build_credential_test_plan`` turns a bounded :class:`CredentialTestConfig`
(engagement config) plus a :class:`WordlistRegistry` into a
:class:`CredentialTestPlan` carrying resolved local file paths + the bounded
run parameters that the hydra/medusa/patator adapters consume as
``{in_dir}/users.txt`` / ``{in_dir}/pass.txt`` (or the ``/wordlists`` mount).

Kept pure and offline-testable: builtin lists resolve without network; remote
lists resolve only when already cached or ``allow_fetch=True``. Category
mismatches and "enabled but no usable credential source" are hard errors so a
misconfigured engagement fails closed rather than running an empty/again-wrong
brute-force.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from src.orchestration.auth_config import CredentialTestConfig
from src.tools.wordlists.registry import WordlistError, WordlistRegistry


@dataclass(frozen=True)
class CredentialTestPlan:
    enabled: bool
    username_path: Path | None = None
    password_path: Path | None = None
    credential_pair_path: Path | None = None
    inline_usernames: tuple[str, ...] = ()
    max_attempts: int = 0
    rate_per_minute: int = 0
    lockout_aware: bool = True
    stop_on_success: bool = True
    notes: tuple[str, ...] = field(default_factory=tuple)


def _resolve_category(
    registry: WordlistRegistry,
    wordlist_id: str | None,
    expected_category: str,
    *,
    allow_fetch: bool,
) -> Path | None:
    if not wordlist_id:
        return None
    entry = registry.get(wordlist_id)
    if entry.category != expected_category:
        raise WordlistError(
            f"wordlist {wordlist_id!r} is category {entry.category!r}, expected {expected_category!r}"
        )
    return registry.resolve(wordlist_id, allow_fetch=allow_fetch)


def build_credential_test_plan(
    config: CredentialTestConfig,
    registry: WordlistRegistry,
    *,
    allow_fetch: bool = False,
) -> CredentialTestPlan:
    """Resolve a credential-testing config into adapter-ready file paths.

    Raises :class:`WordlistError` on category mismatch or when testing is
    enabled but no usable credential source (a pair list, or a password list
    with at least one username) is available.
    """
    if not config.enabled:
        return CredentialTestPlan(enabled=False)

    username_path = _resolve_category(
        registry, config.username_wordlist, "username", allow_fetch=allow_fetch
    )
    password_path = _resolve_category(
        registry, config.password_wordlist, "password", allow_fetch=allow_fetch
    )
    pair_path = _resolve_category(
        registry, config.credential_pair_wordlist, "default_credentials", allow_fetch=allow_fetch
    )

    inline = tuple(config.usernames)
    has_username_source = bool(username_path or inline)
    usable = bool(pair_path) or (bool(password_path) and has_username_source)
    if not usable:
        raise WordlistError(
            "credential_testing enabled but no usable source: provide a "
            "credential_pair_wordlist, or a password_wordlist plus usernames/username_wordlist"
        )

    notes: list[str] = []
    if password_path and not has_username_source:
        notes.append("password list without usernames — ignored")

    return CredentialTestPlan(
        enabled=True,
        username_path=username_path,
        password_path=password_path,
        credential_pair_path=pair_path,
        inline_usernames=inline,
        max_attempts=config.max_attempts,
        rate_per_minute=config.rate_per_minute,
        lockout_aware=config.lockout_aware,
        stop_on_success=config.stop_on_success,
        notes=tuple(notes),
    )


__all__ = ["CredentialTestPlan", "build_credential_test_plan"]
