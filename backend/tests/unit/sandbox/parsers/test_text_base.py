"""Unit tests for :mod:`src.sandbox.parsers._text_base` (Backlog/dev1_md §11 — ARG-022).

Pinned contracts:

* ``parse_kv_lines`` strips comments / blank lines, splits on **first**
  separator, returns no value for separator-less lines.
* ``extract_regex_findings`` honours pattern insertion order so the
  per-parser severity ladder is preserved.
* ``redact_hash_string`` masks **every** known credential fingerprint
  shape (NT/LM, LM:NT pair, SHA-1, SHA-256, Kerberos blob) and never
  leaves a residual hex.
* ``redact_hashes_in_evidence`` returns a fresh dict (no in-place
  mutation), preserves non-string types, and survives empty input.
"""

from __future__ import annotations

import re
from typing import Final

from src.sandbox.parsers._text_base import (
    REDACTED_HASH_MARKER,
    REDACTED_KRB_HASH_MARKER,
    REDACTED_NT_HASH_MARKER,
    extract_regex_findings,
    parse_kv_lines,
    redact_hash_string,
    redact_hashes_in_evidence,
)


# Sample fingerprints used as canaries below.
_LM: Final[str] = "aad3b435b51404eeaad3b435b51404ee"
_NT: Final[str] = "31d6cfe0d16ae931b73c59d7e0c089c0"
_SHA1: Final[str] = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
_SHA256: Final[str] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_KRB: Final[str] = (
    "$krb5tgs$23$*sqlsvc$CONTOSO$cifs/dc01.contoso.local*$cafe1234$babefacecafe"
)


def test_parse_kv_lines_yields_trimmed_pairs() -> None:
    text = "alpha = 1\n  beta=  2  \n\ngamma = three words\n"
    assert list(parse_kv_lines(text)) == [
        ("alpha", "1"),
        ("beta", "2"),
        ("gamma", "three words"),
    ]


def test_parse_kv_lines_strips_inline_comments_and_blanks() -> None:
    text = "alpha = 1 # trailing comment\n# pure comment\n\nbeta = 2\n"
    assert list(parse_kv_lines(text)) == [("alpha", "1"), ("beta", "2")]


def test_parse_kv_lines_skips_lines_without_separator() -> None:
    text = "alpha = 1\nno separator here\nbeta = 2\n"
    pairs = list(parse_kv_lines(text))
    assert ("alpha", "1") in pairs
    assert ("beta", "2") in pairs
    assert all(":" not in p[0] and "=" not in p[0] for p in pairs)


def test_parse_kv_lines_splits_on_first_separator_only() -> None:
    text = "OID = STRING: keep = embedded\n"
    pairs = list(parse_kv_lines(text, sep="="))
    assert pairs == [("OID", "STRING: keep = embedded")]


def test_parse_kv_lines_handles_empty_input_safely() -> None:
    assert list(parse_kv_lines("")) == []
    assert list(parse_kv_lines("   \n  \n")) == []


def test_parse_kv_lines_skips_empty_keys() -> None:
    assert list(parse_kv_lines("= no key here\nactual = value\n")) == [
        ("actual", "value")
    ]


def test_extract_regex_findings_preserves_pattern_insertion_order() -> None:
    text = "match foo\nmatch bar\nmatch foo again\n"
    patterns = {
        "first": re.compile(r"match foo"),
        "second": re.compile(r"match bar"),
    }
    matches = list(extract_regex_findings(text, patterns))
    names = [name for name, _ in matches]
    assert names[0] == "first"
    assert "second" in names


def test_extract_regex_findings_yields_every_match() -> None:
    text = "foo foo foo\nbar bar"
    patterns = {"foo": re.compile(r"foo"), "bar": re.compile(r"bar")}
    matches = list(extract_regex_findings(text, patterns))
    foo_count = sum(1 for n, _ in matches if n == "foo")
    bar_count = sum(1 for n, _ in matches if n == "bar")
    assert foo_count == 3
    assert bar_count == 2


def test_extract_regex_findings_returns_nothing_for_empty_text() -> None:
    assert list(extract_regex_findings("", {"x": re.compile("x")})) == []


def test_redact_hash_string_masks_lm_nt_pair() -> None:
    sample = f"user:500:{_LM}:{_NT}:::"
    redacted = redact_hash_string(sample)
    assert _LM not in redacted
    assert _NT not in redacted
    assert REDACTED_NT_HASH_MARKER in redacted


def test_redact_hash_string_masks_sha256_and_sha1() -> None:
    sample = f"sha256={_SHA256} sha1={_SHA1}"
    redacted = redact_hash_string(sample)
    assert _SHA256 not in redacted
    assert _SHA1 not in redacted
    assert redacted.count(REDACTED_HASH_MARKER) == 2


def test_redact_hash_string_masks_kerberos_blob() -> None:
    sample = f"hash: {_KRB}"
    redacted = redact_hash_string(sample)
    assert "$krb5tgs$" not in redacted
    assert REDACTED_KRB_HASH_MARKER in redacted


def test_redact_hash_string_no_residual_hex_after_redaction() -> None:
    sample = f"{_LM}:{_NT} {_SHA256} {_SHA1} {_NT}"
    redacted = redact_hash_string(sample)
    pair_re = re.compile(r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b")
    long_hex_re = re.compile(r"\b[a-fA-F0-9]{32,}\b")
    assert not pair_re.search(redacted)
    assert not long_hex_re.search(redacted)


def test_redact_hash_string_preserves_short_hex_strings() -> None:
    sample = "object id: 0x1f4 short hex deadbeef"
    redacted = redact_hash_string(sample)
    assert "deadbeef" in redacted
    assert "0x1f4" in redacted


def test_redact_hash_string_returns_unchanged_for_empty_or_non_str() -> None:
    assert redact_hash_string("") == ""
    assert redact_hash_string("plain text") == "plain text"


def test_redact_hashes_in_evidence_returns_new_dict() -> None:
    original = {"user": "alice", "hash": _NT}
    redacted = redact_hashes_in_evidence(original)
    assert redacted is not original
    assert original["hash"] == _NT
    assert redacted["hash"] == REDACTED_NT_HASH_MARKER


def test_redact_hashes_in_evidence_skips_non_string_values() -> None:
    original: dict[str, str] = {"count": 5, "user": "alice", "hash": _NT}  # type: ignore[dict-item]
    redacted = redact_hashes_in_evidence(original)
    assert redacted["count"] == 5
    assert redacted["user"] == "alice"
    assert redacted["hash"] == REDACTED_NT_HASH_MARKER


def test_redact_hashes_in_evidence_handles_empty_dict() -> None:
    assert redact_hashes_in_evidence({}) == {}
