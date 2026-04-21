"""Unit tests for :mod:`src.sandbox.templating`.

Covers Backlog/dev1_md §18 — the safe-templating layer is the only authorised
path between user-supplied parameters and a sandbox argv list, so every
shell-meta character has its own negative test and every per-placeholder
contract has at least one happy + one rejection case.
"""

from __future__ import annotations

import pytest

from src.sandbox.templating import (
    ALLOWED_PLACEHOLDERS,
    TemplateRenderError,
    extract_placeholders,
    render,
    render_argv,
    validate_template,
)


# ---------------------------------------------------------------------------
# Allow-list happy paths
# ---------------------------------------------------------------------------


_HAPPY_VALUES: dict[str, str] = {
    "url": "https://example.com/api?q=1",
    "host": "scanme.nmap.org",
    "port": "443",
    "domain": "example.com",
    "ip": "10.20.30.40",
    "cidr": "10.0.0.0/24",
    "params": "id,name,token_type",
    "wordlist": "/wordlists/seclists/common.txt",
    "canary": "deadbeefcafebabe",
    "out_dir": "/out/job-42",
    "in_dir": "/in/recon",
    "ports": "80,443,8000-8100",
    "ports_range": "1-1024",
    "proto": "ssh",
    "community": "public",
    "community_string": "internal",
    "u": "admin",
    "p": "Passw0rd",
    "user": "admin",
    "pass": "Passw0rd",
    "fmt": "json",
    "mode": "1",
    "module": "exploit_smb",
    "mod": "smb_login",
    "org": "argus_corp",
    "profile": "default",
    "image": "argus/nmap:7.94",
    "session": "session_42",
    "dc": "dc01.example.com",
    "size": "1024,2048",
    "safe": "https://safe.example.com/canary",
    "rand": "abcdef0123",
    "s": "session-7",
    "scan_id": "scan_abc",
    "tenant_id": "tenant_42",
    "hashes_file": "/in/hashes.txt",
    "canary_callback": "https://canary.argus.example.com/abc123",
    "target_proto": "ssh",
    "path": "/in/source",
    "interface": "eth0",
    "binary": "/in/sample.bin",
    "file": "/in/payload.json",
    "script": "/in/scenarios/login.js",
    "basedn": "DC=example,DC=com",
}


def test_allow_list_covers_every_placeholder_in_validators() -> None:
    """Every allow-listed placeholder must have a happy-path canonical value."""
    missing = ALLOWED_PLACEHOLDERS - _HAPPY_VALUES.keys()
    assert not missing, f"missing canonical values for: {sorted(missing)}"


@pytest.mark.parametrize("placeholder", sorted(ALLOWED_PLACEHOLDERS))
def test_each_placeholder_accepts_its_happy_value(placeholder: str) -> None:
    template_tokens = ["echo", "{" + placeholder + "}"]
    argv = render_argv(template_tokens, {placeholder: _HAPPY_VALUES[placeholder]})
    assert argv == ["echo", _HAPPY_VALUES[placeholder]]


# ---------------------------------------------------------------------------
# render() / render_argv() happy + invariants
# ---------------------------------------------------------------------------


def test_render_returns_list_of_strings() -> None:
    argv = render("nmap -Pn {host}", {"host": "example.com"})
    assert argv == ["nmap", "-Pn", "example.com"]
    assert all(isinstance(a, str) for a in argv)


def test_render_argv_preserves_argv_boundaries() -> None:
    template = ["wget", "{url}", "-O", "{out_dir}/dump.bin"]
    argv = render_argv(
        template, {"url": "https://example.com/x", "out_dir": "/out/job"}
    )
    assert argv == ["wget", "https://example.com/x", "-O", "/out/job/dump.bin"]


def test_render_argv_does_not_split_values_with_inner_dashes() -> None:
    template = ["fingerprint", "{params}"]
    argv = render_argv(template, {"params": "a,b,c"})
    assert argv == ["fingerprint", "a,b,c"]


def test_extract_placeholders_handles_string_and_list_forms() -> None:
    assert extract_placeholders("nmap -p {ports} {host}") == {"ports", "host"}
    assert extract_placeholders(["nmap", "-p", "{ports}", "{host}"]) == {
        "ports",
        "host",
    }


def test_validate_template_returns_found_set() -> None:
    found = validate_template(["nmap", "-Pn", "{host}", "-oX", "{out_dir}/o.xml"])
    assert found == {"host", "out_dir"}


# ---------------------------------------------------------------------------
# Negative cases: forbidden placeholders / template shape
# ---------------------------------------------------------------------------


def test_unknown_placeholder_in_template_rejected() -> None:
    with pytest.raises(TemplateRenderError) as exc_info:
        validate_template("nmap {unknown_thing}")
    assert exc_info.value.placeholder == "unknown_thing"


def test_render_unknown_placeholder_rejected() -> None:
    with pytest.raises(TemplateRenderError) as exc_info:
        render("nmap {unknown_thing}", {"unknown_thing": "value"})
    assert exc_info.value.placeholder == "unknown_thing"


def test_render_missing_value_in_context_rejected() -> None:
    with pytest.raises(TemplateRenderError) as exc_info:
        render("nmap {host}", {})
    assert exc_info.value.placeholder == "host"


def test_render_argv_rejects_empty_template() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv([], {})


def test_render_argv_rejects_non_string_token() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["nmap", 42], {})  # type: ignore[list-item]


def test_render_argv_rejects_empty_token() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["nmap", ""], {})


def test_render_rejects_non_string_template() -> None:
    with pytest.raises(TemplateRenderError):
        render(123, {})  # type: ignore[arg-type]


def test_render_rejects_blank_template() -> None:
    with pytest.raises(TemplateRenderError):
        render("   ", {})


def test_validate_template_rejects_empty_placeholder_via_extract() -> None:
    # ``{}`` is not a valid placeholder pattern; extract returns empty set.
    assert extract_placeholders("nmap {}") == set()


# ---------------------------------------------------------------------------
# Negative cases: forbidden characters in values
# ---------------------------------------------------------------------------


_FORBIDDEN_SHELL_META = [
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
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    "!",
    "#",
    "%",
]


@pytest.mark.parametrize("char", _FORBIDDEN_SHELL_META)
def test_safe_token_rejects_each_shell_metachar(char: str) -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["echo", "{org}"], {"org": f"abc{char}def"})


_UNIVERSAL_BAD_CHARS = ["'", '"', " ", "\t", "\n", "\r", "\x00", "\v", "\f"]


@pytest.mark.parametrize("char", _UNIVERSAL_BAD_CHARS)
def test_universal_bad_chars_rejected_for_url(char: str) -> None:
    with pytest.raises(TemplateRenderError) as exc_info:
        render_argv(["wget", "{url}"], {"url": f"https://example.com/{char}"})
    assert exc_info.value.placeholder == "url"


@pytest.mark.parametrize("char", _UNIVERSAL_BAD_CHARS)
def test_universal_bad_chars_rejected_for_host(char: str) -> None:
    with pytest.raises(TemplateRenderError) as exc_info:
        render_argv(["nmap", "{host}"], {"host": f"example{char}.com"})
    assert exc_info.value.placeholder == "host"


# ---------------------------------------------------------------------------
# Per-placeholder edge cases
# ---------------------------------------------------------------------------


def test_url_must_be_http_or_https() -> None:
    with pytest.raises(TemplateRenderError) as exc_info:
        render_argv(["wget", "{url}"], {"url": "ftp://example.com/foo"})
    assert exc_info.value.placeholder == "url"


def test_url_too_long_rejected() -> None:
    long_url = "https://example.com/" + ("a" * 2050)
    with pytest.raises(TemplateRenderError):
        render_argv(["wget", "{url}"], {"url": long_url})


def test_port_outside_range_rejected() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["nmap", "-p", "{port}"], {"port": "70000"})


def test_port_zero_rejected() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["nmap", "-p", "{port}"], {"port": "0"})


def test_port_non_digit_rejected() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["nmap", "-p", "{port}"], {"port": "8a"})


def test_ip_invalid_rejected() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["ping", "{ip}"], {"ip": "999.999.999.999"})


def test_ip_v6_accepted() -> None:
    argv = render_argv(["ping", "{ip}"], {"ip": "2001:db8::1"})
    assert argv == ["ping", "2001:db8::1"]


def test_cidr_invalid_rejected() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["masscan", "{cidr}"], {"cidr": "10.0.0.0/64"})


def test_domain_must_have_dot() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["amass", "-d", "{domain}"], {"domain": "no_dot"})


def test_canary_too_short_rejected() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["echo", "{canary}"], {"canary": "abc"})


def test_canary_too_long_rejected() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["echo", "{canary}"], {"canary": "a" * 80})


def test_canary_non_hex_rejected() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["echo", "{canary}"], {"canary": "ZZZZZZZZZZZZZZZZ"})


def test_wordlist_must_start_with_wordlists_prefix() -> None:
    with pytest.raises(TemplateRenderError) as exc_info:
        render_argv(["ffuf", "-w", "{wordlist}"], {"wordlist": "/etc/passwd"})
    assert exc_info.value.placeholder == "wordlist"


def test_out_dir_path_traversal_rejected() -> None:
    with pytest.raises(TemplateRenderError) as exc_info:
        render_argv(["nmap", "-oX", "{out_dir}/x.xml"], {"out_dir": "/out/../etc"})
    assert exc_info.value.placeholder == "out_dir"


def test_out_dir_double_slash_rejected() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["nmap", "-oX", "{out_dir}/x.xml"], {"out_dir": "/out//job"})


def test_out_dir_must_start_with_prefix() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["nmap", "-oX", "{out_dir}/x.xml"], {"out_dir": "/tmp/foo"})


def test_in_dir_must_start_with_prefix() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["cp", "{in_dir}/file"], {"in_dir": "/etc"})


# ---------------------------------------------------------------------------
# Sandbox-path prefix tightening — guards against look-alike directories
# (e.g. /output/foo, /out_evil, /internal/secrets) that a naive startswith
# check would have accepted but that violate the documented "/out", "/in"
# sandbox-internal contract.
# ---------------------------------------------------------------------------


def test_out_dir_lookalike_directory_rejected() -> None:
    """``/output/foo`` must NOT satisfy the ``/out`` prefix anchor."""
    with pytest.raises(TemplateRenderError) as exc_info:
        render_argv(["nmap", "-oX", "{out_dir}/x.xml"], {"out_dir": "/output/foo"})
    assert exc_info.value.placeholder == "out_dir"


def test_out_dir_lookalike_underscore_suffix_rejected() -> None:
    """``/out_evil`` must NOT satisfy the ``/out`` prefix anchor."""
    with pytest.raises(TemplateRenderError) as exc_info:
        render_argv(["nmap", "-oX", "{out_dir}/x.xml"], {"out_dir": "/out_evil"})
    assert exc_info.value.placeholder == "out_dir"


def test_in_dir_lookalike_directory_rejected() -> None:
    """``/internal/secrets`` must NOT satisfy the ``/in`` prefix anchor."""
    with pytest.raises(TemplateRenderError) as exc_info:
        render_argv(["cp", "{in_dir}/file"], {"in_dir": "/internal/secrets"})
    assert exc_info.value.placeholder == "in_dir"


def test_out_dir_exact_prefix_accepted() -> None:
    """The bare prefix ``/out`` is a legitimate sandbox-mount root."""
    argv = render_argv(["nmap", "-oX", "{out_dir}"], {"out_dir": "/out"})
    assert argv == ["nmap", "-oX", "/out"]


def test_out_dir_nested_path_accepted() -> None:
    """Nested paths under ``/out/`` remain accepted after the tightening."""
    argv = render_argv(["nmap", "-oX", "{out_dir}"], {"out_dir": "/out/scan_42"})
    assert argv == ["nmap", "-oX", "/out/scan_42"]


def test_placeholder_allowlist_is_single_source_of_truth() -> None:
    """``_placeholders.ALLOWED_PLACEHOLDERS`` is the only definition of the set.

    Both :mod:`src.sandbox.templating` and
    :mod:`src.pipeline.contracts.tool_job` MUST re-export the same frozenset
    instance, otherwise YAMLs and ``ToolJob`` parameters can drift apart and
    declare placeholders that the other side silently rejects (Backlog/dev1_md §18).
    """
    from src.pipeline.contracts._placeholders import ALLOWED_PLACEHOLDERS as canon
    from src.pipeline.contracts.tool_job import (
        _ALLOWED_PARAM_KEYS as via_tool_job,
    )
    from src.sandbox.templating import ALLOWED_PLACEHOLDERS as via_templating

    assert via_templating is canon
    assert via_tool_job is canon


def test_proto_lowercase_only() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["hydra", "-s", "{proto}"], {"proto": "SSH"})


def test_mode_must_be_digits_only() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["tool", "{mode}"], {"mode": "1a"})


def test_image_format_enforced() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["docker", "run", "{image}"], {"image": "Bad Image!"})


def test_size_csv_only_digits() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["tool", "-s", "{size}"], {"size": "1024,abc"})


def test_safe_must_be_url() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["tool", "{safe}"], {"safe": "not-a-url"})


def test_render_argv_rejects_non_string_value() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["nmap", "{host}"], {"host": 123})  # type: ignore[dict-item]


def test_render_argv_rejects_empty_value() -> None:
    with pytest.raises(TemplateRenderError):
        render_argv(["nmap", "{host}"], {"host": ""})


# ---------------------------------------------------------------------------
# render() defence in depth: shell-metachar values cannot escape argv
# ---------------------------------------------------------------------------


def test_render_does_not_split_value_into_extra_argv() -> None:
    # If a forbidden value somehow slipped through, render() would still
    # be safe because shlex.split runs with posix=True; here we assert the
    # validator catches it BEFORE substitution so the shell never sees it.
    with pytest.raises(TemplateRenderError):
        render("echo {org}", {"org": "abc; rm -rf /"})


def test_render_does_not_invoke_format_machinery() -> None:
    # ``{1}`` would be a positional ``str.format`` reference; our regex
    # only matches snake_case names so ``{1}`` is left literal and shlex
    # parses it as the bare token ``{1}``.
    argv = render("echo {1}", {})
    assert argv == ["echo", "{1}"]


def test_render_argv_returns_fresh_list() -> None:
    template = ["nmap", "{host}"]
    argv = render_argv(template, {"host": "example.com"})
    argv.append("X")
    assert template == ["nmap", "{host}"]
