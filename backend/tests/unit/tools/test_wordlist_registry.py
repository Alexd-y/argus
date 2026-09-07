"""Wordlist registry — catalog integrity, builtin resolution, credential pairs."""

from __future__ import annotations

from pathlib import Path

import pytest
from src.tools.wordlists.registry import (
    WordlistError,
    WordlistRegistry,
    load_catalog,
)


def test_catalog_loads_and_ids_unique():
    entries = load_catalog()
    ids = [e.id for e in entries]
    assert "argus-default-credentials" in ids
    assert "seclists-passwords-top10k" in ids
    assert len(ids) == len(set(ids))


def test_every_remote_entry_has_fetch_url_and_builtin_has_path():
    for e in load_catalog():
        if e.builtin:
            assert e.path
        else:
            assert e.fetch_url


def test_builtin_default_credentials_resolves_offline():
    reg = WordlistRegistry()
    path = reg.resolve("argus-default-credentials")  # builtin → no network
    assert path.is_file()
    assert path.name == "default-credentials.txt"


def test_default_credentials_parse_into_pairs():
    reg = WordlistRegistry()
    pairs = reg.load_credential_pairs("argus-default-credentials")
    assert ("admin", "admin") in pairs
    assert all(isinstance(u, str) and isinstance(p, str) for u, p in pairs)
    # Comments / blanks are skipped.
    assert all(not u.startswith("#") for u, _ in pairs)


def test_remote_not_cached_raises_without_fetch():
    reg = WordlistRegistry(cache_dir=Path("/nonexistent-argus-cache"))
    with pytest.raises(WordlistError, match="not cached"):
        reg.resolve("seclists-passwords-top10k", allow_fetch=False)


def test_by_category_filters():
    reg = WordlistRegistry()
    pw = {e.id for e in reg.by_category("password")}
    assert "seclists-passwords-top10k" in pw
    assert "argus-default-credentials" not in pw  # that one is default_credentials


def test_unknown_id_raises():
    reg = WordlistRegistry()
    with pytest.raises(WordlistError, match="unknown wordlist"):
        reg.get("does-not-exist")


def test_credential_pairs_rejects_non_pair_list():
    reg = WordlistRegistry()
    with pytest.raises(WordlistError, match="not a credential-pair"):
        reg.load_credential_pairs("seclists-passwords-top10k")


def test_invalid_catalog_schema_rejected(tmp_path):
    bad = tmp_path / "catalog.yaml"
    bad.write_text("schema_version: wrong\nwordlists: []\n", encoding="utf-8")
    with pytest.raises(WordlistError, match="schema_version"):
        load_catalog(bad)


def test_duplicate_ids_rejected(tmp_path):
    bad = tmp_path / "catalog.yaml"
    bad.write_text(
        "schema_version: wordlist_catalog_v1\n"
        "wordlists:\n"
        "  - {id: dup, name: A, category: password, fetch_url: 'http://x/a'}\n"
        "  - {id: dup, name: B, category: password, fetch_url: 'http://x/b'}\n",
        encoding="utf-8",
    )
    with pytest.raises(WordlistError, match="duplicate wordlist id"):
        load_catalog(bad)


def test_builtin_without_path_rejected(tmp_path):
    bad = tmp_path / "catalog.yaml"
    bad.write_text(
        "schema_version: wordlist_catalog_v1\n"
        "wordlists:\n"
        "  - {id: b, name: B, category: password, builtin: true}\n",
        encoding="utf-8",
    )
    with pytest.raises(WordlistError, match="must define 'path'"):
        load_catalog(bad)
