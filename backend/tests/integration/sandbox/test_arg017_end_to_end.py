"""End-to-end integration test: ARG-017 §4.11 / §4.12 / §4.13 vertical slice.

Wires up the three subsystems ARG-017 ships in lockstep — YAML
descriptors, templating-rendered argv, and parser dispatch — against
the real :mod:`src.sandbox.tool_registry` and the real
:mod:`src.sandbox.parsers` registry. No mocks for the registry layers;
only the *raw* interactsh JSONL payload is synthesised.

Concretely the test verifies:

1. Loading the production catalog through :class:`ToolRegistry` yields
   descriptors for the twenty §4.11 / §4.12 / §4.13 tools, each with
   the documented per-tool ``parse_strategy`` / ``image`` / ``phase`` /
   ``risk_level`` / ``requires_approval`` contract.
2. Rendering each descriptor's ``command_template`` with sandbox-
   internal placeholders produces a clean argv whose tokens are free of
   any unrendered ``{...}`` placeholder.
3. Feeding a synthetic interactsh JSONL stream into
   :func:`dispatch_parse` with the descriptor's strategy yields the
   expected SSRF / INFO finding(s) — the ARG-017 first-class parser
   contract for the OAST receivers.
4. Both interactsh-family parsers write the deterministic JSONL
   evidence sidecar (``interactsh_findings.jsonl``) tagged with the
   source ``tool_id``.
5. The new network policies (``oast-egress``, ``auth-bruteforce``,
   ``offline-no-egress``) are present in the templates registry — a
   YAML cannot reference an undefined policy.

Hard isolation: the ``loaded_registry`` fixture builds an *isolated*
tool catalog under ``tmp_path`` containing only the twenty ARG-017
YAMLs (plus a fresh dev signing key) so the test cannot be flaked by
parallel batches that may land broken descriptors in the production
``backend/config/tools/`` tree (the registry is fail-closed: ANY broken
peer aborts the whole load).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from collections.abc import Mapping
from typing import Final

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel
from src.sandbox.adapter_base import ParseStrategy, ToolCategory
from src.sandbox.network_policies import NETWORK_POLICY_NAMES
from src.sandbox.parsers import dispatch_parse
from src.sandbox.parsers.interactsh_parser import (
    EVIDENCE_SIDECAR_NAME as INTERACTSH_SIDECAR,
)
from src.sandbox.signing import (
    KeyManager,
    SignatureRecord,
    SignaturesFile,
    compute_yaml_hash,
    load_private_key_bytes,
    sign_blob,
)
from src.sandbox.templating import render_argv
from src.sandbox.tool_registry import ToolRegistry


# ---------------------------------------------------------------------------
# ARG-017 tool inventory — pinned to mirror Backlog/dev1_md §4.11/§4.12/§4.13
# ---------------------------------------------------------------------------


_ARG017_OAST_TOOL_IDS: Final[tuple[str, ...]] = (
    "interactsh_client",
    "oastify_client",
    "ssrfmap",
    "gopherus",
    "oast_dns_probe",
)


_ARG017_AUTH_TOOL_IDS: Final[tuple[str, ...]] = (
    "hydra",
    "medusa",
    "patator",
    "ncrack",
    "crackmapexec",
    "kerbrute",
    "smbclient",
    "snmp_check",
    "evil_winrm",
    "impacket_examples",
)


# Per-tool image expectations for the §4.12 auth cohort.
# ARG-058 / T03 relocated the 6 AD/SMB/SNMP/Kerberos tools to the
# dedicated ``argus-kali-network`` image; the 4 generic brute-forcers
# (hydra / medusa / patator / ncrack) stay on ``argus-kali-web`` because
# they target HTTP/HTTPS auth surfaces packaged in the web image.
_ARG017_AUTH_IMAGE_BY_TOOL: Final[Mapping[str, str]] = {
    "hydra": "argus-kali-web:latest",
    "medusa": "argus-kali-web:latest",
    "patator": "argus-kali-web:latest",
    "ncrack": "argus-kali-web:latest",
    "crackmapexec": "argus-kali-network:latest",
    "evil_winrm": "argus-kali-network:latest",
    "impacket_examples": "argus-kali-network:latest",
    "kerbrute": "argus-kali-network:latest",
    "smbclient": "argus-kali-network:latest",
    "snmp_check": "argus-kali-network:latest",
}


# Lock-step guard: the per-tool image map MUST cover exactly the
# §4.12 auth roster — neither dropping a tool nor adding a stranger.
assert _ARG017_AUTH_IMAGE_BY_TOOL.keys() == set(_ARG017_AUTH_TOOL_IDS), (
    "drift: _ARG017_AUTH_IMAGE_BY_TOOL keys must equal _ARG017_AUTH_TOOL_IDS"
)


_ARG017_HASH_TOOL_IDS: Final[tuple[str, ...]] = (
    "hashcat",
    "john",
    "ophcrack",
    "hashid",
    "hash_analyzer",
)


_ARG017_TOOL_IDS: Final[tuple[str, ...]] = (
    *_ARG017_OAST_TOOL_IDS,
    *_ARG017_AUTH_TOOL_IDS,
    *_ARG017_HASH_TOOL_IDS,
)


# Per-tool placeholder kits. Every tool consumes the placeholders we
# enumerate below; the templating layer rejects any non-allowlisted
# placeholder so the kit doubles as documentation for what each tool
# actually requires.
_PLACEHOLDER_KIT: Final[dict[str, dict[str, str]]] = {
    # §4.11 — OAST receivers + ssrfmap + gopherus + canary probe
    "interactsh_client": {"out_dir": "/out"},
    "oastify_client": {"out_dir": "/out"},
    "ssrfmap": {
        "in_dir": "/in",
        "out_dir": "/out",
        "params": "id,page,callback",
    },
    "gopherus": {"out_dir": "/out"},
    "oast_dns_probe": {
        "out_dir": "/out",
        "rand": "argus0123456789abcdef",
    },
    # §4.12 — auth bruteforcers + lateral movement
    "hydra": {
        "in_dir": "/in",
        "out_dir": "/out",
        "host": "192.0.2.10",
        "port": "22",
        "target_proto": "ssh",
    },
    "medusa": {
        "in_dir": "/in",
        "out_dir": "/out",
        "host": "192.0.2.10",
        "mod": "ssh",
    },
    "patator": {
        "in_dir": "/in",
        "out_dir": "/out",
        "host": "192.0.2.10",
        "module": "ssh_login",
    },
    "ncrack": {
        "in_dir": "/in",
        "out_dir": "/out",
        "host": "192.0.2.10",
        "port": "22",
    },
    "crackmapexec": {
        "out_dir": "/out",
        "host": "192.0.2.10",
        "user": "alice",
        "pass": "Spring2026",
    },
    "kerbrute": {
        "in_dir": "/in",
        "out_dir": "/out",
        "dc": "dc.example.local",
        "domain": "example.local",
    },
    "smbclient": {
        "out_dir": "/out",
        "host": "192.0.2.10",
        "user": "alice",
        "pass": "Spring2026",
    },
    "snmp_check": {
        "out_dir": "/out",
        "host": "192.0.2.10",
        "community": "public",
    },
    "evil_winrm": {
        "in_dir": "/in",
        "out_dir": "/out",
        "host": "192.0.2.10",
        "user": "alice",
        "pass": "Spring2026",
    },
    "impacket_examples": {
        "out_dir": "/out",
        "domain": "example.local",
        "user": "alice",
        "pass": "Spring2026",
        "dc": "192.0.2.20",
    },
    # §4.13 — hash crackers + classifiers
    "hashcat": {
        "in_dir": "/in",
        "out_dir": "/out",
        "mode": "1000",
        "hashes_file": "/in/hashes.txt",
        "wordlist": "/wordlists/rockyou.txt",
    },
    "john": {
        "in_dir": "/in",
        "out_dir": "/out",
        "fmt": "raw-md5",
        "hashes_file": "/in/hashes.txt",
        "wordlist": "/wordlists/rockyou.txt",
    },
    "ophcrack": {
        "in_dir": "/in",
        "out_dir": "/out",
        "hashes_file": "/in/hashes.txt",
    },
    "hashid": {
        "in_dir": "/in",
        "out_dir": "/out",
        "hashes_file": "/in/hashes.txt",
    },
    "hash_analyzer": {
        "in_dir": "/in",
        "out_dir": "/out",
        "hashes_file": "/in/hashes.txt",
    },
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def production_catalog_dir() -> Path:
    """Resolve ``backend/config/tools/`` from this test file's location."""
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]
    catalog = backend_dir / "config" / "tools"
    assert catalog.is_dir(), f"expected catalog dir at {catalog}"
    return catalog


@pytest.fixture(scope="module")
def isolated_catalog(
    tmp_path_factory: pytest.TempPathFactory,
    production_catalog_dir: Path,
) -> Path:
    """Build an isolated, freshly-signed mirror of the twenty ARG-017 YAMLs.

    Defence-in-depth: copy the twenty §4.11/§4.12/§4.13 descriptors into
    ``tmp_path / tools``, generate a one-shot dev keypair, sign them,
    and write a clean ``SIGNATURES`` manifest. The result is a
    self-contained registry directory that the test can load with
    :class:`ToolRegistry` regardless of the state of the production
    catalog.
    """
    catalog_root = tmp_path_factory.mktemp("arg017_catalog")
    tools_dir = catalog_root / "tools"
    keys_dir = tools_dir / "_keys"
    tools_dir.mkdir(parents=True)
    keys_dir.mkdir(parents=True)

    for tool_id in _ARG017_TOOL_IDS:
        src = production_catalog_dir / f"{tool_id}.yaml"
        assert src.is_file(), f"source YAML missing: {src}"
        shutil.copy2(src, tools_dir / f"{tool_id}.yaml")

    priv_path, _, key_id = KeyManager.generate_dev_keypair(
        keys_dir, name="arg017_e2e_signing"
    )
    private_key = load_private_key_bytes(priv_path.read_bytes())
    priv_path.unlink()

    signatures = SignaturesFile()
    for tool_id in _ARG017_TOOL_IDS:
        rel = f"{tool_id}.yaml"
        yaml_path = tools_dir / rel
        signatures.upsert(
            SignatureRecord(
                sha256_hex=compute_yaml_hash(yaml_path),
                relative_path=rel,
                signature_b64=sign_blob(private_key, yaml_path.read_bytes()),
                public_key_id=key_id,
            )
        )
    signatures.write(tools_dir / "SIGNATURES")
    return tools_dir


@pytest.fixture(scope="module")
def loaded_registry(isolated_catalog: Path) -> ToolRegistry:
    """Load the isolated ARG-017 catalog and return the registry instance."""
    registry = ToolRegistry(tools_dir=isolated_catalog)
    registry.load()
    return registry


@pytest.fixture(scope="module")
def registry_summary(isolated_catalog: Path):  # type: ignore[no-untyped-def]
    """Return the :class:`RegistrySummary` captured from a fresh ``load()``."""
    return ToolRegistry(tools_dir=isolated_catalog).load()


# ---------------------------------------------------------------------------
# Catalog inventory invariant (isolated)
# ---------------------------------------------------------------------------


def test_isolated_catalog_loads_exactly_twenty_arg017_tools(
    registry_summary,  # type: ignore[no-untyped-def]
) -> None:
    """The isolated ARG-017 catalog must hold exactly the twenty tools we copied."""
    assert registry_summary.total == len(_ARG017_TOOL_IDS), (
        f"isolated catalog expected exactly {len(_ARG017_TOOL_IDS)} ARG-017 tools, "
        f"got {registry_summary.total}; per-phase breakdown: "
        f"{registry_summary.by_phase}"
    )


def test_isolated_catalog_includes_all_twenty_arg017_tools(
    loaded_registry: ToolRegistry,
) -> None:
    """Every ARG-017 tool must be discoverable by ``tool_id`` after the load."""
    missing = [tid for tid in _ARG017_TOOL_IDS if loaded_registry.get(tid) is None]
    assert not missing, f"missing ARG-017 tool descriptors after load: {missing}"


# ---------------------------------------------------------------------------
# Network policy templates exist for the new policies
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "policy_name", ("oast-egress", "auth-bruteforce", "offline-no-egress")
)
def test_arg017_network_policies_are_known_templates(policy_name: str) -> None:
    """Every new ARG-017 network policy must be registered in the templates."""
    assert policy_name in NETWORK_POLICY_NAMES, (
        f"network policy {policy_name!r} missing from templates registry — "
        f"a YAML cannot reference an undefined policy at boot"
    )


# ---------------------------------------------------------------------------
# YAML → render — every ARG-017 tool template must round-trip cleanly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", _ARG017_TOOL_IDS)
def test_argv_renders_clean_with_sandbox_placeholders(
    loaded_registry: ToolRegistry, tool_id: str
) -> None:
    """Render each descriptor's command_template with sandbox-internal
    placeholders and audit the rendered argv.

    ``render_argv`` validates every placeholder value and refuses any
    that contains shell-meaningful characters. We then re-audit the
    output as defence-in-depth: rendered tokens must contain no
    leftover ``{...}`` sequence (a bug class where a placeholder name
    is misspelled and silently survives substitution would otherwise
    hide).
    """
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None, f"{tool_id} missing from isolated catalog"

    placeholders = _PLACEHOLDER_KIT[tool_id]
    argv = render_argv(list(descriptor.command_template), placeholders)

    assert argv, f"{tool_id}: rendered argv must be non-empty"
    for token in argv:
        assert "{" not in token and "}" not in token, (
            f"{tool_id}: rendered argv contains leftover placeholder "
            f"in token {token!r}: {argv!r}"
        )


# ---------------------------------------------------------------------------
# Per-tool descriptor contract (image / phase / risk / approval)
# ---------------------------------------------------------------------------


def test_oast_descriptors_carry_correct_phase_and_image(
    loaded_registry: ToolRegistry,
) -> None:
    """§4.11 OAST descriptors must run on argus-kali-web in vuln_analysis."""
    for tool_id in _ARG017_OAST_TOOL_IDS:
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.image == "argus-kali-web:latest", (
            f"{tool_id}: must run on argus-kali-web:latest"
        )
        assert descriptor.phase is ScanPhase.VULN_ANALYSIS, (
            f"{tool_id}: §4.11 OAST tools live in vuln_analysis"
        )


def test_auth_descriptors_carry_correct_image_and_policy(
    loaded_registry: ToolRegistry,
) -> None:
    """§4.12 auth descriptors carry the correct per-tool image and the
    shared ``auth-bruteforce`` policy.

    Image expectations split per ARG-058 / T03:
    - ``hydra`` / ``medusa`` / ``patator`` / ``ncrack`` stay on
      ``argus-kali-web:latest`` (HTTP/HTTPS auth surface tooling).
    - The 6 AD / SMB / SNMP / Kerberos / WinRM tools moved to the
      dedicated ``argus-kali-network:latest`` image.
    """
    for tool_id in _ARG017_AUTH_TOOL_IDS:
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        expected_image = _ARG017_AUTH_IMAGE_BY_TOOL[tool_id]
        assert descriptor.image == expected_image, (
            f"{tool_id}: expected {expected_image}, got {descriptor.image}"
        )
        assert descriptor.network_policy.name == "auth-bruteforce", (
            f"{tool_id}: §4.12 auth tools must ride auth-bruteforce policy"
        )
        assert descriptor.category is ToolCategory.AUTH


def test_hash_descriptors_carry_correct_image_and_policy(
    loaded_registry: ToolRegistry,
) -> None:
    """§4.13 hash descriptors must run on argus-kali-cloud, fully offline."""
    for tool_id in _ARG017_HASH_TOOL_IDS:
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.image == "argus-kali-cloud:latest", (
            f"{tool_id}: must run on argus-kali-cloud:latest"
        )
        assert descriptor.network_policy.name == "offline-no-egress", (
            f"{tool_id}: §4.13 hash tools must ride offline-no-egress policy"
        )
        assert descriptor.phase is ScanPhase.POST_EXPLOITATION


def test_long_running_crackers_require_approval(
    loaded_registry: ToolRegistry,
) -> None:
    """The 3 long-running §4.13 crackers require approval; passive
    classifiers do not.
    """
    for tool_id in ("hashcat", "john", "ophcrack"):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.requires_approval is True, (
            f"{tool_id}: long-running cracker must require approval"
        )
        assert descriptor.risk_level is RiskLevel.HIGH

    for tool_id in ("hashid", "hash_analyzer"):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.requires_approval is False, (
            f"{tool_id}: passive classifier must NOT require approval"
        )


# ---------------------------------------------------------------------------
# interactsh parser dispatch — JSONL → SSRF / INFO findings
# ---------------------------------------------------------------------------


_INTERACTSH_PAYLOAD: Final[bytes] = (
    "\n".join(
        [
            json.dumps(
                {
                    "protocol": "http",
                    "unique-id": "c2vhx10sxxx",
                    "full-id": "c2vhx10sxxx.oast.argus.local",
                    "remote-address": "203.0.113.55:48372",
                    "timestamp": "2026-04-19T12:34:56.123456789Z",
                    "raw-request": (
                        "GET /tok HTTP/1.1\r\nHost: oast.argus.local\r\n\r\n"
                    ),
                    "raw-response": "HTTP/1.1 200 OK\r\n\r\n",
                }
            ),
            json.dumps(
                {
                    "protocol": "smtp",
                    "unique-id": "smtp_id",
                    "full-id": "smtp.oast.argus.local",
                    "remote-address": "203.0.113.99:25",
                    "timestamp": "2026-04-19T12:35:00Z",
                    "raw-request": "EHLO target\r\nMAIL FROM:<x@argus>\r\n",
                    "raw-response": "250 OK\r\n",
                    "smtp-from": "x@argus",
                }
            ),
            json.dumps(
                {
                    "protocol": "dns",
                    "unique-id": "dns_id",
                    "full-id": "dns.oast.argus.local",
                    "remote-address": "198.51.100.10:53",
                    "timestamp": "2026-04-19T12:35:30Z",
                    "q-type": "A",
                }
            ),
        ]
    )
    + "\n"
).encode("utf-8")


@pytest.mark.parametrize("tool_id", ("interactsh_client", "oastify_client"))
def test_interactsh_dispatch_yields_protocol_split_findings(
    loaded_registry: ToolRegistry, tmp_path: Path, tool_id: str
) -> None:
    """3-record interactsh stream → 2 SSRF/CONFIRMED + 1 INFO/LIKELY findings.

    Both interactsh-family variants share the parser, so the same
    payload must produce equivalent findings under either ``tool_id``.
    The protocol split (HTTP + SMTP → SSRF, DNS → INFO) is pinned from
    the ARG-017 §4.11 contract.
    """
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None
    assert descriptor.parse_strategy is ParseStrategy.JSON_LINES

    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()

    findings = dispatch_parse(
        descriptor.parse_strategy,
        _INTERACTSH_PAYLOAD,
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert len(findings) == 3, (
        f"{tool_id}: 3-record interactsh stream must yield 3 findings, "
        f"got {len(findings)}"
    )

    categories = sorted(f.category.value for f in findings)
    assert categories == sorted(
        [
            FindingCategory.SSRF.value,
            FindingCategory.SSRF.value,
            FindingCategory.INFO.value,
        ]
    ), f"{tool_id}: protocol split mismatch, got {categories}"

    confidences = sorted(f.confidence.value for f in findings)
    assert confidences == sorted(
        [
            ConfidenceLevel.CONFIRMED.value,
            ConfidenceLevel.CONFIRMED.value,
            ConfidenceLevel.LIKELY.value,
        ]
    ), f"{tool_id}: confidence ladder mismatch, got {confidences}"

    assert all(918 in f.cwe for f in findings), (
        f"{tool_id}: every finding must declare CWE-918 (SSRF)"
    )
    assert all("WSTG-INPV-19" in f.owasp_wstg for f in findings), (
        f"{tool_id}: every finding must declare WSTG-INPV-19"
    )


@pytest.mark.parametrize("tool_id", ("interactsh_client", "oastify_client"))
def test_interactsh_dispatch_writes_evidence_sidecar(
    loaded_registry: ToolRegistry, tmp_path: Path, tool_id: str
) -> None:
    """Both interactsh variants must persist a JSONL sidecar."""
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None

    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()

    findings = dispatch_parse(
        descriptor.parse_strategy,
        _INTERACTSH_PAYLOAD,
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings

    sidecar = artifacts_dir / INTERACTSH_SIDECAR
    assert sidecar.is_file(), (
        f"{tool_id}: interactsh parser must write the {INTERACTSH_SIDECAR} sidecar"
    )
    parsed = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(parsed) == len(findings)
    assert all(rec.get("tool_id") == tool_id for rec in parsed), (
        f"{tool_id}: every sidecar record must carry the source tool_id"
    )


def test_interactsh_canonical_artifact_round_trip(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """Writing the canonical ``interactsh.jsonl`` artifact and then dispatching
    with garbage stdout still produces the same finding set — proves the
    dispatch flow respects the ``-o /out/interactsh.jsonl`` contract
    documented in the YAML.
    """
    descriptor = loaded_registry.get("interactsh_client")
    assert descriptor is not None

    artifacts_dir = tmp_path / "interactsh_client"
    artifacts_dir.mkdir()
    canonical = artifacts_dir / "interactsh.jsonl"
    canonical.write_bytes(_INTERACTSH_PAYLOAD)

    findings = dispatch_parse(
        descriptor.parse_strategy,
        b"<<<garbage>>>\n",
        b"",
        artifacts_dir,
        tool_id="interactsh_client",
    )
    assert len(findings) == 3, (
        "interactsh parser must prefer canonical artifact over stdout"
    )
