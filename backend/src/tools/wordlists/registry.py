"""Wordlist source registry (credential/username lists for auth testing).

Loads the metadata-only catalog (``backend/config/wordlists/catalog.yaml``) and
resolves a wordlist ``id`` to a local file path that the brute-force adapters
(hydra/medusa/patator/ncrack) consume as ``{in_dir}/pass.txt`` / ``users.txt``.

Design constraints:

* Large corpora are never committed — only a canonical source, the specific raw
  file URL, license and approximate size. The full SecLists set (350GB+) must
  not live in the repo (upstream README warns against storing it on a server).
* A tiny curated ``default-credentials.txt`` IS committed for offline
  WSTG-ATHN-02 default-credential checks.
* Remote lists are fetched on demand into ``cache_dir`` (gitignored) and, when a
  ``sha256`` is pinned in the catalog, verified. Fetch is opt-in
  (``allow_fetch``) so unit tests never touch the network.

Auth brute-force is a policy-gated (``requires_approval``), rate/lockout-aware
capability — use only against authorized targets.
"""

from __future__ import annotations

import hashlib
import os
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

WordlistCategory = Literal["password", "username", "credential_pair", "default_credentials"]

_VALID_CATEGORIES: frozenset[str] = frozenset(
    {"password", "username", "credential_pair", "default_credentials"}
)

_DEFAULT_CATALOG = Path(__file__).resolve().parents[3] / "config" / "wordlists" / "catalog.yaml"

# Hard ceiling on a fetched wordlist to avoid pulling multi-GB corpora inline.
_MAX_FETCH_BYTES = 64 * 1024 * 1024  # 64 MiB


class WordlistError(RuntimeError):
    """Raised on catalog validation / resolution failures."""


@dataclass(frozen=True)
class WordlistEntry:
    id: str
    name: str
    category: WordlistCategory
    builtin: bool = False
    path: str | None = None
    source: str | None = None
    fetch_url: str | None = None
    license: str | None = None
    approx_lines: int | None = None
    sha256: str | None = None
    description: str | None = None


def _coerce_entry(raw: dict) -> WordlistEntry:
    if not isinstance(raw, dict):
        raise WordlistError("wordlist entry must be a mapping")
    wid = str(raw.get("id") or "").strip()
    if not wid:
        raise WordlistError("wordlist entry missing 'id'")
    category = str(raw.get("category") or "").strip()
    if category not in _VALID_CATEGORIES:
        raise WordlistError(f"wordlist {wid!r} has invalid category {category!r}")
    builtin = bool(raw.get("builtin", False))
    path = raw.get("path")
    fetch_url = raw.get("fetch_url")
    if builtin and not path:
        raise WordlistError(f"builtin wordlist {wid!r} must define 'path'")
    if not builtin and not fetch_url:
        raise WordlistError(f"remote wordlist {wid!r} must define 'fetch_url'")
    return WordlistEntry(
        id=wid,
        name=str(raw.get("name") or wid),
        category=category,  # type: ignore[arg-type]
        builtin=builtin,
        path=str(path) if path else None,
        source=str(raw["source"]) if raw.get("source") else None,
        fetch_url=str(fetch_url) if fetch_url else None,
        license=str(raw["license"]) if raw.get("license") else None,
        approx_lines=int(raw["approx_lines"]) if raw.get("approx_lines") is not None else None,
        sha256=str(raw["sha256"]) if raw.get("sha256") else None,
        description=str(raw["description"]) if raw.get("description") else None,
    )


def load_catalog(catalog_path: Path | None = None) -> list[WordlistEntry]:
    """Load + validate the wordlist catalog. Raises WordlistError on drift."""
    path = catalog_path or _DEFAULT_CATALOG
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if data.get("schema_version") != "wordlist_catalog_v1":
        raise WordlistError("unexpected or missing schema_version in wordlist catalog")
    entries = [_coerce_entry(e) for e in (data.get("wordlists") or [])]
    seen: set[str] = set()
    for e in entries:
        if e.id in seen:
            raise WordlistError(f"duplicate wordlist id {e.id!r}")
        seen.add(e.id)
    return entries


class WordlistRegistry:
    """Resolve wordlist ids to local file paths for the brute-force adapters."""

    def __init__(
        self,
        *,
        catalog_path: Path | None = None,
        cache_dir: Path | None = None,
    ) -> None:
        self._catalog_path = catalog_path or _DEFAULT_CATALOG
        self._config_dir = self._catalog_path.parent
        self._entries = {e.id: e for e in load_catalog(self._catalog_path)}
        env_cache = os.environ.get("WORDLIST_CACHE_DIR")
        self._cache_dir = cache_dir or (Path(env_cache) if env_cache else self._config_dir / ".cache")

    def ids(self) -> list[str]:
        return list(self._entries)

    def get(self, wordlist_id: str) -> WordlistEntry:
        entry = self._entries.get(wordlist_id)
        if entry is None:
            raise WordlistError(f"unknown wordlist id {wordlist_id!r}")
        return entry

    def by_category(self, category: WordlistCategory) -> list[WordlistEntry]:
        return [e for e in self._entries.values() if e.category == category]

    def resolve(self, wordlist_id: str, *, allow_fetch: bool = False) -> Path:
        """Return a local path for the wordlist, fetching remote lists if allowed.

        Builtin lists resolve to their committed file. Remote lists resolve to a
        cached copy; when absent, they are fetched only if ``allow_fetch`` is
        True (unit tests keep it False → no network).
        """
        entry = self.get(wordlist_id)
        if entry.builtin:
            local = (self._config_dir / (entry.path or "")).resolve()
            if not local.is_file():
                raise WordlistError(f"builtin wordlist file missing: {local}")
            return local

        cached = (self._cache_dir / f"{entry.id}.txt").resolve()
        if cached.is_file():
            return cached
        if not allow_fetch:
            raise WordlistError(
                f"wordlist {wordlist_id!r} not cached; call resolve(..., allow_fetch=True) "
                "to download from its source"
            )
        return self._fetch(entry, cached)

    def _fetch(self, entry: WordlistEntry, dest: Path) -> Path:
        if not entry.fetch_url:
            raise WordlistError(f"wordlist {entry.id!r} has no fetch_url")
        dest.parent.mkdir(parents=True, exist_ok=True)
        # nosec B310 — fetch_url is a catalog-controlled https raw file, not user input.
        req = urllib.request.Request(entry.fetch_url, headers={"User-Agent": "argus-wordlist"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = resp.read(_MAX_FETCH_BYTES + 1)
        if len(payload) > _MAX_FETCH_BYTES:
            raise WordlistError(f"wordlist {entry.id!r} exceeds {_MAX_FETCH_BYTES} bytes cap")
        if entry.sha256:
            digest = hashlib.sha256(payload).hexdigest()
            if digest != entry.sha256:
                raise WordlistError(f"wordlist {entry.id!r} sha256 mismatch")
        dest.write_bytes(payload)
        return dest

    def load_credential_pairs(self, wordlist_id: str) -> list[tuple[str, str]]:
        """Parse a ``user:pass`` (default_credentials) list into pairs."""
        entry = self.get(wordlist_id)
        if entry.category != "default_credentials":
            raise WordlistError(f"wordlist {wordlist_id!r} is not a credential-pair list")
        path = self.resolve(wordlist_id)
        pairs: list[tuple[str, str]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or ":" not in stripped:
                continue
            user, _, password = stripped.partition(":")
            pairs.append((user, password))
        return pairs


__all__ = [
    "WordlistCategory",
    "WordlistEntry",
    "WordlistError",
    "WordlistRegistry",
    "load_catalog",
]
