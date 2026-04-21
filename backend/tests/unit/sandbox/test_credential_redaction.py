"""Unit tests for :func:`src.sandbox.templating.redact_argv_for_logging`.

Pins the credential-redaction contract introduced by ARG-019 C4 to fix
the false claim in :mod:`src.sandbox.templating` that ``{user}`` /
``{pass}`` placeholder values were stripped from argv before any
``argv``-bearing artefact (dry-run dump, structured log) hit disk.

The helper is the only authorised redactor for argv values; every
sandbox call site (today: :mod:`src.sandbox.k8s_adapter`'s dry-run
artefact writer) MUST route through it so a future placeholder addition
only has to update one module to stay safe.

Invariants pinned here:

* Every credential-typed placeholder name in
  :data:`src.sandbox.templating._CREDENTIAL_PLACEHOLDER_NAMES` is
  redacted from any argv token whose value matches the placeholder
  value byte-for-byte.
* Non-credential placeholders pass through verbatim (``{target}`` /
  ``{ip}`` / ``{port}`` / …) — the helper is value-based, not
  position-based.
* The input argv list is never mutated; a fresh list is returned in
  every case.
* Empty / missing ``placeholder_values`` is the safe pass-through path
  (no placeholders means no credentials in scope means nothing to
  redact).
* Empty credential values are skipped (``""`` would alias every empty
  argv token to ``[REDACTED]``).
"""

from __future__ import annotations

import pytest

from src.sandbox.templating import redact_argv_for_logging


# ---------------------------------------------------------------------------
# Happy paths — the canonical §4.17 / §4.18 / §4.19 credential cases
# ---------------------------------------------------------------------------


def test_redact_credentials_replaces_user_pass_in_argv() -> None:
    """The §4.17 ``crackmapexec`` / ``evil_winrm`` two-token style — the
    canonical case the helper exists to defend.
    """
    argv = ["nxc", "smb", "10.0.0.1", "-u", "admin", "-p", "P@ssw0rd"]
    redacted = redact_argv_for_logging(
        argv,
        placeholder_values={"user": "admin", "pass": "P@ssw0rd"},
    )
    assert redacted == [
        "nxc",
        "smb",
        "10.0.0.1",
        "-u",
        "[REDACTED]",
        "-p",
        "[REDACTED]",
    ]


def test_redact_credentials_handles_short_form_u_and_p() -> None:
    """The historical §4.12 ``evil_winrm`` short-form aliases (``{u}`` /
    ``{p}``) are also covered — they share the credential placeholder
    set with the long-form names.
    """
    argv = ["evil-winrm", "-i", "10.0.0.5", "-u", "Administrator", "-p", "Hunter2!"]
    redacted = redact_argv_for_logging(
        argv,
        placeholder_values={"u": "Administrator", "p": "Hunter2!"},
    )
    assert redacted == [
        "evil-winrm",
        "-i",
        "10.0.0.5",
        "-u",
        "[REDACTED]",
        "-p",
        "[REDACTED]",
    ]


def test_redact_credentials_handles_password_username_aliases() -> None:
    """``password`` / ``username`` aliases (the long-form spellings used
    by some §4.18 mobile / §4.19 browser scenarios) are also redacted.
    """
    argv = ["scan", "--user", "alice", "--password", "TopSecret"]
    redacted = redact_argv_for_logging(
        argv,
        placeholder_values={"username": "alice", "password": "TopSecret"},
    )
    assert redacted == ["scan", "--user", "[REDACTED]", "--password", "[REDACTED]"]


# ---------------------------------------------------------------------------
# Pass-through paths — non-credential placeholders, no creds, empty input
# ---------------------------------------------------------------------------


def test_redact_credentials_passthrough_when_no_creds() -> None:
    """Non-credential placeholders (``{ip}`` / ``{port}`` / ``{target}``)
    pass through verbatim — the helper only ever touches values that
    correspond to credential placeholder names.
    """
    argv = ["nmap", "-sV", "10.0.0.1"]
    redacted = redact_argv_for_logging(
        argv, placeholder_values={"ip": "10.0.0.1", "ports": "443"}
    )
    assert redacted == argv


def test_redact_credentials_passthrough_when_placeholder_values_is_none() -> None:
    """``None`` is the safe pass-through path — no placeholder context
    means we cannot match anything, so the argv leaves untouched.
    """
    argv = ["nmap", "-sV", "10.0.0.1"]
    redacted = redact_argv_for_logging(argv, placeholder_values=None)
    assert redacted == argv


def test_redact_credentials_passthrough_when_placeholder_values_is_empty() -> None:
    """An empty dict is functionally identical to ``None`` — both are
    the no-credential-context path.
    """
    argv = ["nmap", "-sV", "10.0.0.1"]
    redacted = redact_argv_for_logging(argv, placeholder_values={})
    assert redacted == argv


def test_redact_credentials_skips_empty_credential_value() -> None:
    """An empty credential value MUST NOT alias every empty argv token
    to ``[REDACTED]`` — that would be a worse leak than the bug it tries
    to fix (silent argv mangling).
    """
    argv = ["scan", "--user", "alice", "--note", ""]
    redacted = redact_argv_for_logging(
        argv,
        placeholder_values={"user": "alice", "pass": ""},
    )
    assert redacted == ["scan", "--user", "[REDACTED]", "--note", ""]


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------


def test_redact_credentials_does_not_mutate_input() -> None:
    """The input argv list MUST be unchanged after the call — callers
    expect the original argv to remain available for cluster apply.
    """
    argv = ["nxc", "-u", "admin"]
    snapshot = list(argv)
    _ = redact_argv_for_logging(argv, placeholder_values={"user": "admin"})
    assert argv == snapshot


def test_redact_credentials_returns_fresh_list_each_call() -> None:
    """Every call returns a new list; mutating the result MUST NOT
    leak back into a previously redacted argv.
    """
    argv = ["nxc", "-u", "admin"]
    a = redact_argv_for_logging(argv, placeholder_values={"user": "admin"})
    b = redact_argv_for_logging(argv, placeholder_values={"user": "admin"})
    assert a is not b
    assert a == b
    a.append("__sentinel__")
    assert "__sentinel__" not in b


def test_redact_credentials_value_match_not_position_match() -> None:
    """The helper redacts by VALUE, not by position: a credential
    appearing as part of a composite token (e.g. ``-uadmin``) is NOT
    redacted because the whole-token match fails.  The §4.17 / §4.18 /
    §4.19 catalog uses two-token ``-u {user}`` style precisely to keep
    this contract enforceable; the test pins the contract so a future
    YAML that splices credentials into composite tokens fails review.
    """
    argv = ["nxc", "-uadmin", "-pHunter2"]
    redacted = redact_argv_for_logging(
        argv,
        placeholder_values={"user": "admin", "pass": "Hunter2"},
    )
    assert redacted == argv


def test_redact_credentials_redacts_every_occurrence_of_value() -> None:
    """If a credential value appears multiple times in argv (e.g. the
    same secret passed both as ``-u`` and embedded in a connection
    string token built up at the YAML level — not what we do today, but
    a defensible defence-in-depth) every occurrence is replaced.
    """
    argv = ["tool", "-u", "shared", "--note", "shared"]
    redacted = redact_argv_for_logging(argv, placeholder_values={"user": "shared"})
    assert redacted == ["tool", "-u", "[REDACTED]", "--note", "[REDACTED]"]


def test_redact_credentials_ignores_non_credential_placeholder_names() -> None:
    """Only the closed set of credential placeholder names triggers
    redaction — values keyed by ``{target}`` / ``{ip}`` / ``{port}``
    are never scrubbed even if they happen to be sensitive in some
    deployment.
    """
    argv = ["nmap", "-sV", "10.0.0.1", "-p", "443"]
    redacted = redact_argv_for_logging(
        argv,
        placeholder_values={
            "ip": "10.0.0.1",
            "port": "443",
            "target": "10.0.0.1",
        },
    )
    assert redacted == argv


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_redact_credentials_on_empty_argv_returns_empty_list() -> None:
    redacted = redact_argv_for_logging([], placeholder_values={"user": "admin"})
    assert redacted == []


@pytest.mark.parametrize(
    "credential_name",
    ["user", "pass", "u", "p", "username", "password"],
)
def test_redact_credentials_covers_every_credential_placeholder_name(
    credential_name: str,
) -> None:
    """Cohort-level pin: every placeholder name in the closed credential
    set MUST trigger redaction.  Drift here means a placeholder was
    quietly added to ``_PLACEHOLDER_VALIDATORS`` without updating
    ``_CREDENTIAL_PLACEHOLDER_NAMES``.
    """
    argv = ["tool", "--flag", "secret-value"]
    redacted = redact_argv_for_logging(
        argv, placeholder_values={credential_name: "secret-value"}
    )
    assert redacted == ["tool", "--flag", "[REDACTED]"]


def test_redact_credentials_coerces_non_string_values_to_str() -> None:
    """Defence in depth: ``ToolJob.parameters`` is typed
    ``dict[str, str]`` and the templating layer rejects non-strings, but
    the redactor still coerces values to ``str`` so a future caller that
    forwards a mixed dict (e.g. a debug helper) does not silently fail
    open.
    """
    argv = ["tool", "-u", "42"]
    redacted = redact_argv_for_logging(
        argv,
        placeholder_values={"user": "42"},
    )
    assert redacted == ["tool", "-u", "[REDACTED]"]
