"""Integration test: ARG-026 hardening contract for sandbox container images.

Performs **static analysis** of the six sandbox-image Dockerfiles
(``sandbox/images/argus-kali-{web,cloud,browser,full,recon,network}/Dockerfile``)
and asserts the supply-chain + runtime invariants documented in the Cycle 3
plan §3 ARG-026 + Cycle 5 ARG-048 (which lifted the matrix from 4 → 6
profiles by delivering ``recon`` for Backlog §4.1/§4.2 reconnaissance and
``network`` for Backlog §4.17 protocol exploitation):

1.  Multi-stage build pattern: every Dockerfile contains at least one
    ``FROM ... AS <name>`` builder stage AND a final ``FROM`` stage that is
    NOT a builder.
2.  Final-stage ``USER 65532`` directive is present (matches the k8s
    ``securityContext.runAsUser`` contract from Cycle 1 ARG-004).
3.  ``HEALTHCHECK`` directive is present in the final stage.
4.  ``LABEL argus.sbom.path="/usr/share/doc/sbom.cdx.json"`` is present
    (allows downstream Trivy / Grype to locate the baked-in SBOM without
    spelunking the image).
5.  Required OCI labels are present: ``org.opencontainers.image.title``,
    ``description``, ``source`` (ARGUS supply-chain provenance metadata).
6.  Required ARGUS labels are present: ``argus.image.profile``,
    ``argus.image.cycle`` (joins the catalog's image references back to
    the supply-chain build pipeline).
7.  No SUID-introducing patterns: no ``RUN chmod +s``, no
    ``RUN chmod u+s`` / ``g+s`` patterns. Tools must inherit the host's
    SUID surface (``su``, ``sudo``, ``mount``, ``passwd`` from apt) but
    we MUST NOT add new SUID bits at build time.
8.  Shared helpers (healthcheck.sh, generate_sbom.sh) exist and are
    referenced by every image.

This test is **Docker-daemon-free** (parses Dockerfiles as text). The
docker-build smoke test is gated behind ``@pytest.mark.requires_docker``
and lives in ``test_image_build_smoke.py`` (Cycle 5 follow-up — out of
scope for ARG-026).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest


# ---------------------------------------------------------------------------
# Repository layout — single source of truth for paths consumed by the test.
# ---------------------------------------------------------------------------
REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[4]
SANDBOX_IMAGES_DIR: Final[Path] = REPO_ROOT / "sandbox" / "images"
SHARED_HELPERS_DIR: Final[Path] = SANDBOX_IMAGES_DIR / "_shared"

#: The six supported image profiles. New profiles MUST be added here AND
#: get a Dockerfile + healthcheck wiring; the test fails closed otherwise.
#: ARG-048 (Cycle 5) added ``recon`` (passive + active recon, Backlog §4.1/§4.2)
#: and ``network`` (protocol exploitation, Backlog §4.17), bringing the matrix
#: to 6 profiles.
IMAGE_PROFILES: Final[tuple[str, ...]] = (
    "web",
    "cloud",
    "browser",
    "full",
    "recon",
    "network",
)

#: Per-profile cycle of introduction. The four ARG-026 profiles share the
#: original cycle label; the two ARG-048 profiles carry their own. The
#: ``argus.image.cycle`` LABEL must match these exact strings — drift is
#: caught by ``TestLabels.test_argus_image_cycle_label_matches_introduction``.
EXPECTED_CYCLE_PER_PROFILE: Final[dict[str, str]] = {
    "web": "ARG-026",
    "cloud": "ARG-026",
    "browser": "ARG-026",
    "full": "ARG-026",
    "recon": "ARG-048",
    "network": "ARG-048",
}

#: The exact sandbox uid/gid baked into the k8s securityContext.
EXPECTED_UID: Final[str] = "65532"
EXPECTED_GID: Final[str] = "65532"

#: Path inside every image where the SBOM is baked in.
EXPECTED_SBOM_PATH: Final[str] = "/usr/share/doc/sbom.cdx.json"

#: Required OCI labels — see https://github.com/opencontainers/image-spec
REQUIRED_OCI_LABELS: Final[tuple[str, ...]] = (
    "org.opencontainers.image.title",
    "org.opencontainers.image.description",
    "org.opencontainers.image.source",
)

#: ARGUS-specific labels for build-pipeline traceability.
REQUIRED_ARGUS_LABELS: Final[tuple[str, ...]] = (
    "argus.image.profile",
    "argus.image.cycle",
)


# ---------------------------------------------------------------------------
# Dockerfile parser. We intentionally roll our own regex-based parser
# instead of pulling `dockerfile-parse` (not in requirements.txt). The
# directives we care about (FROM, USER, LABEL, HEALTHCHECK, RUN) all have a
# stable single-line shape that the multi-line continuation handler below
# normalises before grep.
# ---------------------------------------------------------------------------


def _strip_comments_and_continuations(text: str) -> list[str]:
    """Return a list of normalised, comment-free directive lines.

    Joins backslash-continuation lines into single logical directives.
    Strips leading whitespace. Drops blank lines and pure-comment lines.
    """
    raw_lines = text.splitlines()
    logical: list[str] = []
    buffer: list[str] = []
    for raw in raw_lines:
        line = raw.rstrip()
        # Skip pure-comment lines but only when no continuation buffer is
        # open — Docker treats `\` followed by a comment as a syntax error,
        # but we don't need to police that here.
        stripped = line.lstrip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if line.endswith("\\"):
            buffer.append(line[:-1].rstrip())
            continue
        buffer.append(line)
        logical.append(" ".join(part.strip() for part in buffer if part.strip()))
        buffer = []
    if buffer:
        logical.append(" ".join(part.strip() for part in buffer if part.strip()))
    return logical


def _parse_stages(directives: list[str]) -> list[dict[str, object]]:
    """Group directives into stages keyed by FROM boundaries.

    Returns a list of ``{base, alias, directives}`` dicts. ``alias`` is the
    optional `AS <name>` label.
    """
    stages: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    from_re = re.compile(
        r"^FROM\s+(?P<base>\S+)(?:\s+AS\s+(?P<alias>\S+))?", re.IGNORECASE
    )
    for line in directives:
        match = from_re.match(line)
        if match:
            if current is not None:
                stages.append(current)
            current = {
                "base": match.group("base"),
                "alias": match.group("alias"),
                "directives": [line],
            }
            continue
        if current is None:
            # Pre-FROM directives (ARG, syntax pragma) — ignored for stage
            # accounting.
            continue
        current["directives"].append(line)  # type: ignore[union-attr]
    if current is not None:
        stages.append(current)
    return stages


def _final_stage(stages: list[dict[str, object]]) -> dict[str, object]:
    """Return the **last** stage that is NOT a builder (alias=None or alias!=builder)."""
    if not stages:
        raise AssertionError("no FROM directives found")
    # The last stage in document order is the runtime stage by Docker
    # convention. Multi-stage builds put the runtime stage at the bottom.
    return stages[-1]


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def dockerfile_paths() -> dict[str, Path]:
    """Map each image profile to its Dockerfile path."""
    return {
        profile: SANDBOX_IMAGES_DIR / f"argus-kali-{profile}" / "Dockerfile"
        for profile in IMAGE_PROFILES
    }


@pytest.fixture(scope="module")
def dockerfile_directives(dockerfile_paths: dict[str, Path]) -> dict[str, list[str]]:
    """Parsed directives keyed by image profile."""
    out: dict[str, list[str]] = {}
    for profile, path in dockerfile_paths.items():
        assert path.is_file(), f"Dockerfile missing for profile={profile}: {path}"
        out[profile] = _strip_comments_and_continuations(
            path.read_text(encoding="utf-8")
        )
    return out


@pytest.fixture(scope="module")
def dockerfile_stages(
    dockerfile_directives: dict[str, list[str]],
) -> dict[str, list[dict[str, object]]]:
    return {profile: _parse_stages(d) for profile, d in dockerfile_directives.items()}


# ---------------------------------------------------------------------------
# Tests — one assertion class per contract item, parametrised across profiles.
# ---------------------------------------------------------------------------


class TestStructure:
    """Structural invariants — file existence, multi-stage pattern."""

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_dockerfile_exists(
        self, profile: str, dockerfile_paths: dict[str, Path]
    ) -> None:
        path = dockerfile_paths[profile]
        assert path.is_file(), f"Dockerfile missing for profile={profile}: {path}"
        # Sanity: must be non-trivial. Stub headers are only ~50 lines, real
        # multi-stage builds are ≥80.
        assert path.stat().st_size > 1500, (
            f"Dockerfile for {profile} looks like a stub (size {path.stat().st_size} B)"
        )

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_multistage_pattern(
        self, profile: str, dockerfile_stages: dict[str, list[dict[str, object]]]
    ) -> None:
        stages = dockerfile_stages[profile]
        builder_count = sum(1 for s in stages if s["alias"] is not None)
        non_builder_count = sum(1 for s in stages if s["alias"] is None)
        assert builder_count >= 1, (
            f"{profile}: expected ≥1 `FROM ... AS <name>` builder stage; got {builder_count}"
        )
        assert non_builder_count >= 1, (
            f"{profile}: expected ≥1 final non-builder `FROM` stage; got {non_builder_count}"
        )
        # The very last stage must NOT have an alias (runtime is the
        # consumed image; it must not be tagged as a builder).
        final = _final_stage(stages)
        assert final["alias"] is None, (
            f"{profile}: final stage must not be tagged AS <alias>; got alias={final['alias']}"
        )


class TestUserDirective:
    """Final-stage `USER 65532` is mandatory (k8s `runAsUser` contract)."""

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_final_stage_user_65532(
        self, profile: str, dockerfile_stages: dict[str, list[dict[str, object]]]
    ) -> None:
        final = _final_stage(dockerfile_stages[profile])
        directives: list[str] = final["directives"]  # type: ignore[assignment]
        user_lines = [
            d
            for d in directives
            if re.match(rf"^USER\s+{re.escape(EXPECTED_UID)}(\s|:|$)", d, re.IGNORECASE)
        ]
        assert user_lines, (
            f"{profile}: final stage MUST contain `USER {EXPECTED_UID}`; "
            f"matched none in: {[d for d in directives if d.upper().startswith('USER')]}"
        )

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_useradd_creates_correct_uid(
        self, profile: str, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        """The USER directive only takes effect if a matching system user exists."""
        text = " ".join(dockerfile_directives[profile])
        # Look for either `useradd ... --uid 65532` or `useradd -u 65532` plus a
        # matching gid / group. Allow long and short flags, allow either order.
        uid_pattern = re.compile(
            r"useradd[^&|;\n]*?(?:--uid\s+|\s-u\s+){uid}\b".format(uid=EXPECTED_UID)
        )
        groupadd_pattern = re.compile(
            r"groupadd[^&|;\n]*?(?:--gid\s+|\s-g\s+){gid}\b".format(gid=EXPECTED_GID)
        )
        assert uid_pattern.search(text), (
            f"{profile}: must create the runtime user with uid={EXPECTED_UID} "
            f"(`useradd --uid {EXPECTED_UID} ...` or `useradd -u {EXPECTED_UID} ...`)"
        )
        assert groupadd_pattern.search(text), (
            f"{profile}: must create the runtime group with gid={EXPECTED_GID} "
            f"(`groupadd --gid {EXPECTED_GID} ...` or `groupadd -g {EXPECTED_GID} ...`)"
        )


class TestHealthcheck:
    """HEALTHCHECK directive is mandatory in the final stage."""

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_healthcheck_present(
        self, profile: str, dockerfile_stages: dict[str, list[dict[str, object]]]
    ) -> None:
        final = _final_stage(dockerfile_stages[profile])
        directives: list[str] = final["directives"]  # type: ignore[assignment]
        hc_lines = [d for d in directives if d.upper().startswith("HEALTHCHECK")]
        assert hc_lines, (
            f"{profile}: final stage MUST contain a HEALTHCHECK directive; "
            f"none found among {len(directives)} directives"
        )

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_healthcheck_invokes_shared_script(
        self, profile: str, dockerfile_stages: dict[str, list[dict[str, object]]]
    ) -> None:
        final = _final_stage(dockerfile_stages[profile])
        directives: list[str] = final["directives"]  # type: ignore[assignment]
        hc_lines = [d for d in directives if d.upper().startswith("HEALTHCHECK")]
        assert any("/usr/local/bin/healthcheck.sh" in d for d in hc_lines), (
            f"{profile}: HEALTHCHECK should invoke /usr/local/bin/healthcheck.sh; "
            f"got {hc_lines}"
        )


class TestLabels:
    """OCI + ARGUS labels are mandatory and must not regress."""

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_oci_labels_present(
        self, profile: str, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        text = " ".join(dockerfile_directives[profile])
        for label in REQUIRED_OCI_LABELS:
            pattern = re.compile(re.escape(label) + r"\s*=", re.IGNORECASE)
            assert pattern.search(text), (
                f"{profile}: required OCI LABEL {label!r} is missing from Dockerfile"
            )

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_argus_labels_present(
        self, profile: str, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        text = " ".join(dockerfile_directives[profile])
        for label in REQUIRED_ARGUS_LABELS:
            pattern = re.compile(re.escape(label) + r"\s*=", re.IGNORECASE)
            assert pattern.search(text), (
                f"{profile}: required ARGUS LABEL {label!r} is missing from Dockerfile"
            )

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_argus_image_profile_label_matches_directory(
        self, profile: str, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        text = " ".join(dockerfile_directives[profile])
        match = re.search(r'argus\.image\.profile\s*=\s*"([^"]+)"', text)
        assert match, f"{profile}: argus.image.profile label not found"
        assert match.group(1) == profile, (
            f"{profile}: argus.image.profile label is {match.group(1)!r}, expected {profile!r}"
        )

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_argus_image_cycle_label_matches_introduction(
        self, profile: str, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        """``argus.image.cycle`` LABEL must match the cycle that introduced the profile.

        ARG-026 introduced ``web/cloud/browser/full``; ARG-048 added
        ``recon/network``. Mixing them would obscure provenance during a
        supply-chain audit (cosign certificate identity → image profile →
        introducing cycle), so the test is fail-closed per profile.
        """
        text = " ".join(dockerfile_directives[profile])
        match = re.search(r'argus\.image\.cycle\s*=\s*"([^"]+)"', text)
        assert match, f"{profile}: argus.image.cycle label not found"
        expected = EXPECTED_CYCLE_PER_PROFILE[profile]
        assert match.group(1) == expected, (
            f"{profile}: argus.image.cycle should be {expected!r}, "
            f"got {match.group(1)!r}"
        )

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_sbom_path_label_present(
        self, profile: str, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        text = " ".join(dockerfile_directives[profile])
        match = re.search(r'argus\.sbom\.path\s*=\s*"([^"]+)"', text)
        assert match, (
            f"{profile}: argus.sbom.path label is mandatory (per ARG-026 contract)"
        )
        assert match.group(1) == EXPECTED_SBOM_PATH, (
            f"{profile}: argus.sbom.path should be {EXPECTED_SBOM_PATH!r}, "
            f"got {match.group(1)!r}"
        )


class TestSbomGeneration:
    """SBOM must be generated at build time and live at the labelled path."""

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_sbom_generation_step_present(
        self, profile: str, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        text = " ".join(dockerfile_directives[profile])
        # The wrapper script `generate_sbom.sh` MUST be invoked at build
        # time. We allow either an absolute call or a chained `&&` form.
        assert "generate_sbom.sh" in text, (
            f"{profile}: SBOM generation step missing — Dockerfile must invoke "
            f"/usr/local/bin/generate_sbom.sh at build time"
        )
        # And it must target the canonical SBOM path.
        assert EXPECTED_SBOM_PATH in text, (
            f"{profile}: Dockerfile must reference the canonical SBOM path "
            f"{EXPECTED_SBOM_PATH}; instead reference is missing or different"
        )


class TestNoSuidIntroduction:
    """Image MUST NOT introduce new SUID bits at build time."""

    #: Patterns that would set the SUID bit. Any single match is a fail.
    _SUID_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
        re.compile(r"chmod\s+\+s\b", re.IGNORECASE),
        re.compile(r"chmod\s+u\+s\b", re.IGNORECASE),
        re.compile(r"chmod\s+g\+s\b", re.IGNORECASE),
        re.compile(r"chmod\s+ug\+s\b", re.IGNORECASE),
        re.compile(r"chmod\s+0?[2467][0-7]{3}\b", re.IGNORECASE),
        re.compile(r"chmod\s+a\+s\b", re.IGNORECASE),
    )

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_no_suid_introduction(
        self, profile: str, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        text = "\n".join(dockerfile_directives[profile])
        offenders: list[str] = []
        for line in text.splitlines():
            for pat in self._SUID_PATTERNS:
                if pat.search(line):
                    offenders.append(line.strip())
        assert not offenders, (
            f"{profile}: Dockerfile MUST NOT add SUID bits at build time; "
            f"offending lines: {offenders}"
        )


class TestSharedHelpers:
    """Shared helper scripts exist and are referenced by every Dockerfile."""

    def test_healthcheck_helper_exists(self) -> None:
        path = SHARED_HELPERS_DIR / "healthcheck.sh"
        assert path.is_file(), f"shared healthcheck.sh missing at {path}"
        content = path.read_text(encoding="utf-8")
        assert content.startswith("#!"), "healthcheck.sh must start with a shebang"
        assert "exit 0" in content, (
            "healthcheck.sh must have a deterministic success path"
        )

    def test_sbom_generator_helper_exists(self) -> None:
        path = SHARED_HELPERS_DIR / "generate_sbom.sh"
        assert path.is_file(), f"shared generate_sbom.sh missing at {path}"
        content = path.read_text(encoding="utf-8")
        assert content.startswith("#!"), "generate_sbom.sh must start with a shebang"
        # Must support BOTH the syft path (for cloud image) and the dpkg
        # fallback (for everything else).
        assert "syft" in content, "generate_sbom.sh must support syft when present"
        assert "dpkg-query" in content, (
            "generate_sbom.sh must fall back to dpkg-query when syft is absent"
        )
        # The CycloneDX envelope is mandatory — Trivy / Grype rely on it.
        assert "CycloneDX" in content, (
            "generate_sbom.sh must emit a CycloneDX-format envelope"
        )

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_dockerfile_copies_helpers(
        self, profile: str, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        text = " ".join(dockerfile_directives[profile])
        assert "_shared/healthcheck.sh" in text, (
            f"{profile}: Dockerfile must COPY _shared/healthcheck.sh into the image"
        )
        assert "_shared/generate_sbom.sh" in text, (
            f"{profile}: Dockerfile must COPY _shared/generate_sbom.sh into the image"
        )


class TestProfileSpecificContracts:
    """Profile-specific guards beyond the cross-cutting contract."""

    def test_browser_image_documents_no_suid_chromium(
        self, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        """Browser image must explicitly remove the Chromium SUID sandbox."""
        text = " ".join(dockerfile_directives["browser"])
        assert "chrome-sandbox" in text, (
            "browser: Dockerfile must reference chrome-sandbox removal "
            "(rm -f /usr/lib/chromium/chrome-sandbox) to maintain the no-SUID contract"
        )

    def test_cloud_image_ships_syft(
        self, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        """Cloud image is the canonical SBOM toolbox — must ship syft."""
        text = " ".join(dockerfile_directives["cloud"])
        assert "syft" in text, (
            "cloud: Dockerfile must install syft (canonical SBOM tool)"
        )

    def test_full_image_is_superset_of_others(
        self, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        """Full image must contain at least one signature tool from each slim image."""
        text = " ".join(dockerfile_directives["full"])
        # Web signature: nuclei. Cloud signature: trivy. Browser signature: chromium.
        assert "nuclei" in text, (
            "full: must contain nuclei (web profile signature tool)"
        )
        assert "trivy" in text, (
            "full: must contain trivy (cloud profile signature tool)"
        )
        assert "chromium" in text, (
            "full: must contain chromium (browser profile signature tool)"
        )

    def test_recon_image_carries_passive_and_active_recon_signatures(
        self, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        """Recon image must carry §4.1 passive AND §4.2 active recon markers.

        ARG-048 split recon out of the ``full`` image so that recon-only
        scans can mount a 2-3× smaller surface area. The test guards both
        ends of the recon spectrum: at least one passive OSINT helper
        (subfinder for §4.1) and at least one active scanner (nmap for
        §4.2). Drift in either direction is a regression.
        """
        text = " ".join(dockerfile_directives["recon"])
        # Passive (§4.1) signature: subfinder is the canonical Go CLI.
        assert "subfinder" in text, (
            "recon: must contain subfinder (Backlog §4.1 passive recon signature)"
        )
        # Active (§4.2) signature: nmap is the canonical port scanner.
        assert "nmap" in text, (
            "recon: must contain nmap (Backlog §4.2 active recon signature)"
        )

    def test_network_image_carries_protocol_exploitation_signatures(
        self, dockerfile_directives: dict[str, list[str]]
    ) -> None:
        """Network image must carry §4.17 protocol exploitation markers.

        ARG-048 introduced this profile to host SMB / LDAP / SNMP / IKE /
        impacket tooling that doesn't belong in the leaner web or recon
        images. The test guards two canonical signatures: snmp (community
        bruteforce surface) and impacket (Windows / Active Directory
        exploitation suite). Either dropping below the bar trips drift.
        """
        text = " ".join(dockerfile_directives["network"])
        assert "snmp" in text, (
            "network: must contain snmp tooling (Backlog §4.17 SNMP recon)"
        )
        assert "impacket" in text, (
            "network: must contain impacket (Backlog §4.17 SMB / Kerberos / NTLM)"
        )


class TestBaseImagePin:
    """All six images MUST pin the same kalilinux/kali-rolling tag."""

    @pytest.mark.parametrize("profile", IMAGE_PROFILES)
    def test_base_image_is_pinned(
        self, profile: str, dockerfile_stages: dict[str, list[dict[str, object]]]
    ) -> None:
        for stage in dockerfile_stages[profile]:
            base = stage["base"]
            assert isinstance(base, str)
            # Must be the kali-rolling base — no alpine drift, no debian
            # bookworm fallback (the supply-chain audit assumes kali).
            assert base.startswith("kalilinux/kali-rolling:"), (
                f"{profile}: base image must be kalilinux/kali-rolling:<pin>; got {base!r}"
            )
            assert ":latest" not in base, (
                f"{profile}: base image MUST NOT use :latest tag (reproducibility); got {base!r}"
            )
