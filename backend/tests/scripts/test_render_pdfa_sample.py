"""C7-T02 / ARG-058-followup — unit tests for ``scripts/render_pdfa_sample``.

Covers the C7-T02 (Wave 2) extensions to the B6-T01 sample renderer:

* ``--fixture-variant`` argparse routing (basic / cyrillic / longtable /
  images / per_tenant) including byte-stability of the basic legacy path.
* ``--tenant-id`` plumbing for the per-tenant resolver (mocked).
* Deterministic 1×1 sRGB PNG generation for the images variant (stdlib
  only, no Pillow dependency).
* ``ExitStack``-managed tempdir lifecycle: PNGs exist when LaTeX runs,
  tempdir is gone after success AND after failure.

Test architecture
-----------------
* ``LatexBackend`` is patched at the renderer's import site so pdflatex
  never actually runs. The mocked ``render`` method writes a fake PDF
  byte-string to ``output_path`` so the post-render
  ``output.exists() && size > 0`` guard in :func:`main` is satisfied
  without touching real LaTeX tooling.
* ``resolve_tenant_pdf_archival_format`` is patched as an
  :class:`unittest.mock.AsyncMock` so the in-memory aiosqlite session
  inside ``_resolve_per_tenant_format`` is bypassed entirely.
* The basic-variant SHA-256 is pinned as a *golden snapshot* to detect
  drift in the rendered LaTeX source — hashing the LaTeX string instead
  of the full PDF avoids flakiness from pdfTeX's runtime metadata, while
  still failing loudly if the tier-template content silently changes.
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scripts._pdfa_fixtures import (
    PNG_TOKEN_1,
    PNG_TOKEN_2,
    VARIANTS,
    get_variant,
)
from scripts.render_pdfa_sample import (
    _build_latex_source_for_variant,
    _inject_resolved_format,
    _inject_variant_body,
    _parse_args,
    _png_chunk,
    _resolve_per_tenant_format,
    _write_deterministic_png,
    main,
)

# ---------------------------------------------------------------------------
# Pinned constants
# ---------------------------------------------------------------------------
#
# Basic-variant LaTeX source SHA-256 — bumping this signals that either
# (a) the midgard tier template changed (legitimate, update this constant
#     and the linked ai_docs entry), or
# (b) the renderer's basic-variant code path stopped being byte-identical
#     to the pre-C7-T02 output (regression — investigate before merge).
# Computed against tier='midgard', scan_completed_at='2024-01-01T00:00:00+00:00'.
_BASIC_LATEX_SHA256 = (
    "046ed76fe84e70bd43d064c5186a33b5049db05cc2fe09893017d6fc1509f67e"
)

_DETERMINISTIC_TIMESTAMP = "2024-01-01T00:00:00+00:00"


# ---------------------------------------------------------------------------
# Test scaffolding — fake PDF backend that never invokes pdflatex
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _BackendCapture:
    """Records every call to the patched LatexBackend instance.

    Attributes:
        render_calls: List of kwargs each ``render`` invocation received.
        png_paths_at_render: Resolved PNG paths discovered in the LaTeX
            source the moment ``render`` was called. Empty list when the
            variant carries no images.
        png_existed_at_render: ``True`` only if every PNG path actually
            existed on disk at the moment ``render`` was called — the
            invariant test #5 asserts.
    """

    render_calls: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    png_paths_at_render: list[Path] = dataclasses.field(default_factory=list)
    png_existed_at_render: bool = False


def _fake_backend(
    capture: _BackendCapture,
    *,
    render_returns: bool = True,
    raise_inside_render: BaseException | None = None,
) -> MagicMock:
    """Return a MagicMock LatexBackend instance wired for the renderer.

    The mock's ``render`` side-effect:

    1. Records every kwarg into ``capture.render_calls``.
    2. Scans ``latex_template_content`` for ``\\includegraphics`` paths
       and, for each, asserts the file exists on disk RIGHT NOW (before
       the renderer's tempdir is dismantled by ExitStack on the return
       path). This is the "PNGs exist when LaTeX runs" invariant.
    3. Writes a small fake PDF byte-string to ``output_path`` so the
       post-render ``output.exists() && size > 0`` guard in
       :func:`scripts.render_pdfa_sample.main` is satisfied.
    4. Optionally raises ``raise_inside_render`` AFTER (1)/(2)/(3) so
       failure-path tests can verify cleanup still happens.
    """
    backend = MagicMock(name="LatexBackend.instance")
    backend.is_available.return_value = True

    def _render(**kwargs: Any) -> bool:
        capture.render_calls.append(dict(kwargs))

        latex = kwargs.get("latex_template_content", "") or ""
        # ARGUS_PNG_PATH sentinels MUST be replaced before we get here,
        # otherwise the renderer skipped the substitution branch.
        assert PNG_TOKEN_1 not in latex, (
            "PNG_TOKEN_1 sentinel was not replaced before render() — "
            "check _build_latex_source_for_variant routing"
        )
        assert PNG_TOKEN_2 not in latex
        paths = [
            Path(m)
            for m in re.findall(
                r"\\includegraphics\[[^\]]*\]\{([^}]+)\}", latex
            )
        ]
        capture.png_paths_at_render = paths
        capture.png_existed_at_render = bool(paths) and all(
            p.exists() and p.stat().st_size > 0 for p in paths
        )

        output_path: Path = kwargs["output_path"]
        output_path.write_bytes(b"%PDF-1.5\nfake-pdf-bytes-for-test")

        if raise_inside_render is not None:
            raise raise_inside_render
        return render_returns

    backend.render.side_effect = _render
    return backend


@pytest.fixture
def backend_capture() -> _BackendCapture:
    return _BackendCapture()


@pytest.fixture
def patched_backend(
    backend_capture: _BackendCapture,
) -> Iterator[MagicMock]:
    """Patch the renderer's LatexBackend class to return our fake instance."""
    fake = _fake_backend(backend_capture)
    with patch(
        "scripts.render_pdfa_sample.LatexBackend",
        return_value=fake,
    ) as mock_cls:
        yield mock_cls


# ---------------------------------------------------------------------------
# Section A — argparse routing
# ---------------------------------------------------------------------------


class TestArgparseRouting:
    """``_parse_args`` accepts every variant + rejects unknowns at exit-2."""

    def test_default_variant_is_basic(self) -> None:
        args = _parse_args(["--output", "x.pdf"])
        assert args.fixture_variant == "basic"

    def test_default_tenant_id_is_none(self) -> None:
        args = _parse_args(["--output", "x.pdf"])
        assert args.tenant_id is None

    @pytest.mark.parametrize("name", sorted(VARIANTS))
    def test_each_variant_name_is_selectable(self, name: str) -> None:
        args = _parse_args(
            ["--fixture-variant", name, "--output", "x.pdf"]
        )
        assert args.fixture_variant == name

    def test_unknown_variant_exits_with_code_2(self) -> None:
        with pytest.raises(SystemExit) as excinfo:
            _parse_args(["--fixture-variant", "does-not-exist"])
        assert excinfo.value.code == 2

    def test_tenant_id_flag_round_trips(self) -> None:
        args = _parse_args(
            [
                "--fixture-variant",
                "per_tenant",
                "--tenant-id",
                "acme",
                "--output",
                "x.pdf",
            ]
        )
        assert args.tenant_id == "acme"

    def test_legacy_tier_flag_still_supported(self) -> None:
        """``--tier`` must still parse for backwards-compat with B6-T01 callers."""
        args = _parse_args(
            ["--tier", "asgard", "--output", "x.pdf"]
        )
        assert args.tier == "asgard"


# ---------------------------------------------------------------------------
# Section B — basic variant byte-stability (SHA-256 golden snapshot)
# ---------------------------------------------------------------------------


class TestBasicVariantByteStability:
    """``--fixture-variant=basic`` is byte-identical to the pre-C7-T02 render."""

    def test_basic_latex_source_sha256_matches_pinned(self) -> None:
        variant = get_variant("basic")
        latex_source = _build_latex_source_for_variant(
            tier="midgard",
            variant=variant,
            scan_completed_at=_DETERMINISTIC_TIMESTAMP,
            tenant_id=None,
            image_paths=None,
        )
        actual = hashlib.sha256(latex_source.encode("utf-8")).hexdigest()
        assert actual == _BASIC_LATEX_SHA256, (
            f"basic-variant LaTeX source drifted: expected SHA-256\n"
            f"  {_BASIC_LATEX_SHA256}\n"
            f"got\n"
            f"  {actual}\n"
            "If the midgard tier template legitimately changed, update "
            "_BASIC_LATEX_SHA256 in this file AND link the ai_docs entry "
            "in your commit message."
        )

    def test_basic_latex_source_carries_no_variant_body_marker(self) -> None:
        """Basic must NOT carry the BEGIN/END comment markers other variants do."""
        variant = get_variant("basic")
        latex_source = _build_latex_source_for_variant(
            tier="midgard",
            variant=variant,
            scan_completed_at=_DETERMINISTIC_TIMESTAMP,
            tenant_id=None,
            image_paths=None,
        )
        assert "BEGIN ARGUS variant body" not in latex_source
        assert "ARGUS per-tenant resolver:" not in latex_source

    def test_basic_latex_source_is_deterministic_across_invocations(
        self,
    ) -> None:
        """Two consecutive renders must produce identical LaTeX source."""
        variant = get_variant("basic")
        first = _build_latex_source_for_variant(
            tier="midgard",
            variant=variant,
            scan_completed_at=_DETERMINISTIC_TIMESTAMP,
            tenant_id=None,
            image_paths=None,
        )
        second = _build_latex_source_for_variant(
            tier="midgard",
            variant=variant,
            scan_completed_at=_DETERMINISTIC_TIMESTAMP,
            tenant_id=None,
            image_paths=None,
        )
        assert first == second


# ---------------------------------------------------------------------------
# Section C — non-basic variants compose correctly
# ---------------------------------------------------------------------------


class TestNonBasicVariantComposition:
    """Each non-basic variant body lands inside the rendered LaTeX."""

    def test_cyrillic_variant_injects_body_with_marker(self) -> None:
        latex_source = _build_latex_source_for_variant(
            tier="midgard",
            variant=get_variant("cyrillic"),
            scan_completed_at=_DETERMINISTIC_TIMESTAMP,
            tenant_id=None,
            image_paths=None,
        )
        assert "BEGIN ARGUS variant body (cyrillic)" in latex_source
        assert "END ARGUS variant body (cyrillic)" in latex_source
        # Cyrillic content is preserved verbatim through the injection.
        assert any(0x0400 <= ord(c) <= 0x04FF for c in latex_source)

    def test_longtable_variant_injects_longtable_environment(self) -> None:
        latex_source = _build_latex_source_for_variant(
            tier="midgard",
            variant=get_variant("longtable"),
            scan_completed_at=_DETERMINISTIC_TIMESTAMP,
            tenant_id=None,
            image_paths=None,
        )
        assert r"\begin{longtable}" in latex_source
        assert r"\end{longtable}" in latex_source

    def test_images_variant_requires_image_paths(self, tmp_path: Path) -> None:
        with pytest.raises(RuntimeError, match="image_paths"):
            _build_latex_source_for_variant(
                tier="midgard",
                variant=get_variant("images"),
                scan_completed_at=_DETERMINISTIC_TIMESTAMP,
                tenant_id=None,
                image_paths=None,
            )

    def test_images_variant_substitutes_png_sentinels(
        self, tmp_path: Path
    ) -> None:
        png1 = tmp_path / "p1.png"
        png2 = tmp_path / "p2.png"
        png1.write_bytes(b"\x89PNG\r\n\x1a\n")
        png2.write_bytes(b"\x89PNG\r\n\x1a\n")

        latex_source = _build_latex_source_for_variant(
            tier="midgard",
            variant=get_variant("images"),
            scan_completed_at=_DETERMINISTIC_TIMESTAMP,
            tenant_id=None,
            image_paths=(png1, png2),
        )
        assert PNG_TOKEN_1 not in latex_source
        assert PNG_TOKEN_2 not in latex_source
        assert png1.as_posix() in latex_source
        assert png2.as_posix() in latex_source


# ---------------------------------------------------------------------------
# Section D — per-tenant resolver wiring
# ---------------------------------------------------------------------------


class TestPerTenantResolver:
    """Per-tenant variant consults the resolver and embeds the resolved format."""

    def test_per_tenant_calls_resolver_once_with_tenant_id(
        self, patched_backend: MagicMock, tmp_path: Path
    ) -> None:
        del patched_backend
        with patch(
            "scripts.render_pdfa_sample.resolve_tenant_pdf_archival_format",
            new_callable=AsyncMock,
        ) as mock_resolver:
            mock_resolver.return_value = "pdfa-2u"
            output = tmp_path / "per_tenant.pdf"
            rc = main(
                [
                    "--fixture-variant",
                    "per_tenant",
                    "--tenant-id",
                    "acme",
                    "--output",
                    str(output),
                ]
            )
            assert rc == 0, f"main() returned non-zero exit code: {rc}"
            assert mock_resolver.await_count == 1, (
                f"resolver should be called exactly once; got "
                f"await_count={mock_resolver.await_count}"
            )
            call = mock_resolver.await_args
            assert call is not None
            # ``resolve_tenant_pdf_archival_format(session, tenant_id)`` —
            # second positional is the tenant id.
            assert call.args[1] == "acme", (
                f"resolver was called with the wrong tenant id: "
                f"args={call.args!r}"
            )

    def test_per_tenant_resolver_return_value_lands_in_latex_preamble(
        self, patched_backend: MagicMock, backend_capture: _BackendCapture,
        tmp_path: Path,
    ) -> None:
        del patched_backend
        sentinel_format = "pdfa-2u"
        with patch(
            "scripts.render_pdfa_sample.resolve_tenant_pdf_archival_format",
            new_callable=AsyncMock,
        ) as mock_resolver:
            mock_resolver.return_value = sentinel_format
            output = tmp_path / "per_tenant.pdf"
            rc = main(
                [
                    "--fixture-variant",
                    "per_tenant",
                    "--tenant-id",
                    "acme",
                    "--output",
                    str(output),
                ]
            )
            assert rc == 0
            assert backend_capture.render_calls, "render was never called"
            latex = backend_capture.render_calls[0]["latex_template_content"]
            preamble, _, _ = latex.partition(r"\begin{document}")
            assert f"resolved_format={sentinel_format}" in preamble, (
                f"resolved format {sentinel_format!r} must land in the "
                f"preamble; got preamble tail:\n{preamble[-400:]}"
            )
            assert "tenant_id=acme" in preamble


# ---------------------------------------------------------------------------
# Section D2 — _resolve_per_tenant_format integration (DEBUG-5)
# ---------------------------------------------------------------------------
#
# These tests exercise the REAL aiosqlite + SQLAlchemy path the CI
# matrix leg now relies on. They do NOT mock
# ``resolve_tenant_pdf_archival_format`` — they spin up the in-memory
# engine, seed a tenant row, and assert the resolver round-trips the
# expected value. This is the test the reviewer asked for in DEBUG-5
# (Option A): the per_tenant matrix leg cannot silently fall back to a
# preamble smoke test anymore.


class TestResolverIntegration:
    """Real round-trip against in-memory aiosqlite (no mock)."""

    def test_resolver_returns_seeded_pdfa_2u_for_known_tenant(self) -> None:
        """Seed a tenant with override="pdfa-2u" → resolver returns it."""
        result = _resolve_per_tenant_format("acme", "pdfa-2u")
        assert result == "pdfa-2u", (
            f"resolver did not round-trip the seeded override; got {result!r}. "
            "If this fails, the per_tenant CI matrix leg is no longer "
            "exercising the real resolver path - the gate is degraded."
        )

    def test_resolver_returns_default_for_no_override_and_no_seed(self) -> None:
        """No override + tenant_id without a row → resolver returns "standard".

        Defensive: when override is None we skip the seed, so the
        resolver query against the empty ``tenants`` table returns
        ``PDF_ARCHIVAL_FORMAT_DEFAULT``.
        """
        result = _resolve_per_tenant_format("nobody", None)
        assert result == "standard"

    def test_resolver_round_trip_assertion_raises_on_mismatch(self) -> None:
        """If the resolver returns wrong value (mocked) → RuntimeError fires.

        This is the safety belt: the matrix leg must FAIL LOUD if the
        resolver is broken, not silently return a "correct-looking"
        format. Mock the resolver to return a different format from
        the seeded override and assert the renderer raises.
        """
        with patch(
            "scripts.render_pdfa_sample.resolve_tenant_pdf_archival_format",
            new_callable=AsyncMock,
        ) as mock_resolver:
            mock_resolver.return_value = "standard"
            with pytest.raises(RuntimeError) as exc:
                _resolve_per_tenant_format("acme", "pdfa-2u")

            msg = str(exc.value)
            assert "resolver" in msg
            assert "pdfa-2u" in msg
            assert "standard" in msg
            assert "acme" in msg


# ---------------------------------------------------------------------------
# Section E — images variant tempdir lifecycle
# ---------------------------------------------------------------------------


class TestImagesTempdirLifecycle:
    """PNGs exist when LaTeX runs; tempdir cleaned up on success AND failure."""

    def test_images_variant_writes_two_pngs_before_render(
        self,
        patched_backend: MagicMock,
        backend_capture: _BackendCapture,
        tmp_path: Path,
    ) -> None:
        del patched_backend
        output = tmp_path / "images.pdf"
        rc = main(
            ["--fixture-variant", "images", "--output", str(output)]
        )
        assert rc == 0, f"main() returned non-zero: {rc}"
        # Backend was called once with both PNGs present on disk.
        assert backend_capture.render_calls, "render was never called"
        assert len(backend_capture.png_paths_at_render) == 2, (
            f"expected exactly 2 PNG paths; got "
            f"{backend_capture.png_paths_at_render}"
        )
        assert backend_capture.png_existed_at_render, (
            "PNGs should exist on disk at the moment LaTeX is invoked"
        )

    def test_images_tempdir_is_cleaned_up_after_success(
        self,
        patched_backend: MagicMock,
        backend_capture: _BackendCapture,
        tmp_path: Path,
    ) -> None:
        del patched_backend
        output = tmp_path / "images.pdf"
        rc = main(
            ["--fixture-variant", "images", "--output", str(output)]
        )
        assert rc == 0
        assert backend_capture.png_paths_at_render
        for png in backend_capture.png_paths_at_render:
            assert not png.exists(), (
                f"tempdir PNG {png} should be cleaned up after main() "
                "returns successfully"
            )
        # Parent directory (the TemporaryDirectory itself) is also gone.
        for png in backend_capture.png_paths_at_render:
            assert not png.parent.exists(), (
                f"tempdir parent {png.parent} should be cleaned up after "
                "successful run"
            )

    def test_images_tempdir_is_cleaned_up_after_failure(
        self,
        backend_capture: _BackendCapture,
        tmp_path: Path,
    ) -> None:
        """Tempdir cleanup must also fire when render() raises."""
        backend = _fake_backend(
            backend_capture,
            raise_inside_render=RuntimeError("simulated latexmk crash"),
        )
        output = tmp_path / "images.pdf"
        with patch(
            "scripts.render_pdfa_sample.LatexBackend",
            return_value=backend,
        ):
            with pytest.raises(RuntimeError, match="simulated latexmk crash"):
                main(
                    ["--fixture-variant", "images", "--output", str(output)]
                )
        # Render still got the PNG paths before crashing.
        assert backend_capture.png_paths_at_render, (
            "expected PNG paths to be captured even on failure path"
        )
        # ExitStack guarantees cleanup on the exception path.
        for png in backend_capture.png_paths_at_render:
            assert not png.exists(), (
                f"tempdir PNG {png} must be cleaned up after a render "
                "exception (try/finally / ExitStack invariant)"
            )
            assert not png.parent.exists()


# ---------------------------------------------------------------------------
# Section F — PNG generator (stdlib only)
# ---------------------------------------------------------------------------


class TestPngGenerator:
    """``_write_deterministic_png`` emits valid 16×16 sRGB PNG bytes."""

    def test_signature_and_size(self, tmp_path: Path) -> None:
        path = tmp_path / "x.png"
        _write_deterministic_png(path, red=200, green=60, blue=60)
        data = path.read_bytes()
        assert data[:8] == b"\x89PNG\r\n\x1a\n", (
            "PNG file must start with the canonical 8-byte signature"
        )
        # 16×16 RGB PNG with uniform fill compresses to ~120 bytes
        # (signature + IHDR + sRGB + tiny IDAT + IEND); guard against
        # accidentally writing a multi-MB file via a wrong loop. Upper
        # bound is generous so a future zlib-level tweak does not break
        # the test.
        assert 80 <= len(data) <= 400, f"unexpected PNG size: {len(data)}"

    def test_canvas_is_16x16_rgb(self, tmp_path: Path) -> None:
        """IHDR must encode width=16, height=16, bit-depth=8, colour-type=2.

        DEBUG-6 bumped the canvas from 1×1 to 16×16 so verapdf
        actually exercises the image-tree validation rules instead of
        short-circuiting on a trivial-size raster.
        """
        path = tmp_path / "x.png"
        _write_deterministic_png(path, red=10, green=20, blue=30)
        data = path.read_bytes()
        # IHDR chunk layout (after the 8-byte signature):
        #   4-byte length || 4-byte type "IHDR" || 13-byte data || 4-byte CRC
        # Data: 4-byte width | 4-byte height | 1-byte bit-depth | 1-byte
        # colour-type | 1-byte compression | 1-byte filter | 1-byte interlace.
        ihdr_offset = 8 + 4 + 4  # past signature + length + "IHDR" type
        width = int.from_bytes(data[ihdr_offset:ihdr_offset + 4], "big")
        height = int.from_bytes(
            data[ihdr_offset + 4:ihdr_offset + 8], "big",
        )
        bit_depth = data[ihdr_offset + 8]
        colour_type = data[ihdr_offset + 9]
        assert width == 16, f"expected width=16, got {width}"
        assert height == 16, f"expected height=16, got {height}"
        assert bit_depth == 8
        assert colour_type == 2  # RGB

    def test_carries_required_chunks(self, tmp_path: Path) -> None:
        path = tmp_path / "x.png"
        _write_deterministic_png(path, red=10, green=20, blue=30)
        data = path.read_bytes()
        # Chunk types appear as ASCII bytes in the file body.
        for chunk_type in (b"IHDR", b"sRGB", b"IDAT", b"IEND"):
            assert chunk_type in data, (
                f"PNG missing required chunk: {chunk_type!r}"
            )

    def test_rejects_out_of_range_samples(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="0..255"):
            _write_deterministic_png(
                tmp_path / "bad.png", red=300, green=0, blue=0
            )
        with pytest.raises(ValueError, match="0..255"):
            _write_deterministic_png(
                tmp_path / "bad.png", red=0, green=-1, blue=0
            )

    def test_chunk_crc_matches_zlib_crc32(self) -> None:
        """``_png_chunk`` CRC must equal ``zlib.crc32(type + data)``."""
        import zlib

        data = b"hello-png-chunk"
        chunk = _png_chunk(b"IHDR", data)
        # Layout: 4-byte length || 4-byte type || data || 4-byte CRC.
        crc_bytes = chunk[-4:]
        expected = (zlib.crc32(b"IHDR" + data) & 0xFFFFFFFF).to_bytes(
            4, "big"
        )
        assert crc_bytes == expected


# ---------------------------------------------------------------------------
# Section G — LaTeX mutation helpers
# ---------------------------------------------------------------------------


class TestLatexMutationHelpers:
    """``_inject_*`` helpers raise on missing markers and produce stable output."""

    def test_inject_variant_body_inserts_before_end_document(self) -> None:
        latex = "\\documentclass{article}\\begin{document}body\\end{document}"
        out = _inject_variant_body(latex, "MORE", "test-variant")
        assert "MORE" in out
        # The original \end{document} must still terminate the file.
        assert out.endswith("\\end{document}")
        # Body marker comments are present.
        assert "BEGIN ARGUS variant body (test-variant)" in out
        assert "END ARGUS variant body (test-variant)" in out

    def test_inject_variant_body_raises_when_marker_missing(self) -> None:
        with pytest.raises(RuntimeError, match=r"\\end\{document\}"):
            _inject_variant_body("no end marker here", "x", "v")

    def test_inject_resolved_format_lands_in_preamble(self) -> None:
        latex = (
            "\\documentclass{article}\n"
            "\\usepackage{lmodern}\n"
            "\\begin{document}body\\end{document}"
        )
        out = _inject_resolved_format(latex, "acme", "pdfa-2u")
        # The injected line lives BEFORE \begin{document}.
        preamble, _, _ = out.partition(r"\begin{document}")
        assert "tenant_id=acme" in preamble
        assert "resolved_format=pdfa-2u" in preamble

    def test_inject_resolved_format_raises_when_marker_missing(self) -> None:
        with pytest.raises(RuntimeError, match=r"\\begin\{document\}"):
            _inject_resolved_format("no begin marker here", "acme", "pdfa-2u")
