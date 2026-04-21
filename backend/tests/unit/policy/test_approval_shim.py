"""Structural tests for the :mod:`src.policy.approval` backward-compat shim.

T02 split the legacy monolithic ``approval`` module into:

* :mod:`src.policy.approval_dto` — pure pydantic DTOs.
* :mod:`src.policy.approval_service` — :class:`ApprovalService` engine.

This file's job is to guarantee the *shim* (``src.policy.approval``)
keeps the **exact** public surface the codebase had before T02. Every
existing call site of the form ``from src.policy.approval import X``
must continue to work — and the rebound symbol must be the *same*
object as the canonical one in the new module, not just a name match.
A re-creation (e.g. accidentally subclassing or wrapping) would silently
break ``isinstance`` / ``is`` checks across the codebase.

Business-logic tests live in ``test_approval.py``; this file is purely
about *import topology*. No fixtures from ``conftest.py`` are needed.
"""

from __future__ import annotations

import __future__ as _future_module
import ast
from pathlib import Path

import pytest

from src.policy import approval as approval_shim
from src.policy import approval_dto, approval_service

# Canonical pre-T02 public API — kept in lockstep with the imports at the
# top of ``test_approval.py``. ``test_legacy_names_match_test_approval_import_block``
# below verifies the two lists do not drift.
_LEGACY_PUBLIC_NAMES: tuple[str, ...] = (
    "APPROVAL_FAILURE_REASONS",
    "ApprovalAction",
    "ApprovalError",
    "ApprovalRequest",
    "ApprovalService",
    "ApprovalSignature",
    "ApprovalStatus",
)

# Names that come from the DTO module specifically. ``ApprovalService``
# is intentionally absent here — it lives in ``approval_service``.
_DTO_NAMES: tuple[str, ...] = (
    "APPROVAL_FAILURE_REASONS",
    "ApprovalAction",
    "ApprovalError",
    "ApprovalRequest",
    "ApprovalSignature",
    "ApprovalStatus",
)


# ---------------------------------------------------------------------------
# Surface area — every legacy name must still resolve.
# ---------------------------------------------------------------------------


class TestShimSurface:
    @pytest.mark.parametrize("name", _LEGACY_PUBLIC_NAMES)
    def test_legacy_name_resolves_through_shim(self, name: str) -> None:
        """``from src.policy.approval import <name>`` keeps working post-T02."""
        assert hasattr(approval_shim, name), (
            f"shim regressed: ``src.policy.approval.{name}`` no longer importable"
        )

    def test_shim_all_matches_legacy_surface(self) -> None:
        """``__all__`` is the contract; tests pin it to the expected set."""
        assert set(approval_shim.__all__) == set(_LEGACY_PUBLIC_NAMES)

    def test_shim_all_is_sorted(self) -> None:
        """Sorted ``__all__`` is the project convention (see policy.__init__)."""
        assert list(approval_shim.__all__) == sorted(approval_shim.__all__)


# ---------------------------------------------------------------------------
# Identity — re-exports must be the SAME object, not a re-creation.
# ---------------------------------------------------------------------------


class TestShimIdentity:
    """``shim.X is canonical.X`` — silent rebinding would break isinstance."""

    @pytest.mark.parametrize("name", _DTO_NAMES)
    def test_dto_symbol_is_same_object_as_dto_module(self, name: str) -> None:
        """``approval.X is approval_dto.X`` — no shadowing, no rebinding.

        If the shim accidentally re-defined a class (or wrapped it), an
        ``isinstance(req, src.policy.approval.ApprovalRequest)`` check
        would fail for objects built via ``approval_dto.ApprovalRequest``.
        That is exactly the regression this test guards against.
        """
        shim_obj = getattr(approval_shim, name)
        dto_obj = getattr(approval_dto, name)
        assert shim_obj is dto_obj, (
            f"{name} is rebound by the shim — clients get a different object "
            "depending on which import path they used."
        )

    def test_service_symbol_is_same_object_as_service_module(self) -> None:
        """``approval.ApprovalService is approval_service.ApprovalService``."""
        assert approval_shim.ApprovalService is approval_service.ApprovalService


# ---------------------------------------------------------------------------
# Package re-export — ``from src.policy import ApprovalService`` works.
# ---------------------------------------------------------------------------


class TestPackageReExport:
    """The package ``__init__`` MUST surface every legacy name as well."""

    @pytest.mark.parametrize("name", _LEGACY_PUBLIC_NAMES)
    def test_legacy_name_reachable_from_package_root(self, name: str) -> None:
        """``from src.policy import <name>`` keeps working post-T02."""
        import src.policy as policy_pkg

        assert hasattr(policy_pkg, name), (
            f"``from src.policy import {name}`` regressed — drops convenience "
            "alias used widely across the test suite."
        )
        # Identity must hold here too — the package init MUST re-bind to
        # the same object the shim exposes; no double indirection.
        assert getattr(policy_pkg, name) is getattr(approval_shim, name)

    def test_package_all_lists_every_legacy_name(self) -> None:
        """``src.policy.__all__`` includes every legacy approval symbol."""
        import src.policy as policy_pkg

        for name in _LEGACY_PUBLIC_NAMES:
            assert name in policy_pkg.__all__, (
                f"src.policy.__all__ no longer advertises {name!r}; "
                "``from src.policy import *`` will drop it."
            )


# ---------------------------------------------------------------------------
# Drift guards — detect accidental new exports / drift from test_approval.py.
# ---------------------------------------------------------------------------


class TestShimDriftGuards:
    def test_shim_has_no_runtime_only_extras(self) -> None:
        """The shim exports ONLY the legacy names — no new public symbols.

        A new public name silently added by the shim would be a hidden
        API that is not advertised through the canonical modules
        (``approval_dto`` / ``approval_service``). Such drift defeats
        the point of the layered split.

        ``dir(module)`` includes side-effects of ``from __future__ import
        annotations`` (Python rebinds ``annotations`` to a
        :class:`__future__._Feature` instance in the importing module's
        namespace). Filtering by attribute *type* — instead of a brittle
        name allow-list — keeps the guard robust if Python adds new
        future flags later.
        """
        public = {
            n
            for n in dir(approval_shim)
            if not n.startswith("_")
            and not isinstance(
                getattr(approval_shim, n, None), _future_module._Feature
            )
        }
        extras = public - set(_LEGACY_PUBLIC_NAMES)
        assert extras == set(), (
            f"shim exposes unexpected public names: {sorted(extras)}"
        )

    def test_legacy_names_match_test_approval_import_block(self) -> None:
        """The canonical list is kept in lockstep with ``test_approval.py``.

        If anybody updates the legacy import block in ``test_approval.py``,
        this test fires loudly so the shim coverage stays accurate.
        """
        test_file = Path(__file__).parent / "test_approval.py"
        tree = ast.parse(test_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module == "src.policy.approval"
            ):
                imported = sorted(alias.name for alias in node.names)
                assert imported == sorted(_LEGACY_PUBLIC_NAMES), (
                    "test_approval.py legacy import block has drifted from "
                    "_LEGACY_PUBLIC_NAMES.\n"
                    f"  test_approval.py imports: {imported!r}\n"
                    f"  _LEGACY_PUBLIC_NAMES   : {sorted(_LEGACY_PUBLIC_NAMES)!r}"
                )
                return
        pytest.fail(
            "test_approval.py no longer imports from src.policy.approval — "
            "the shim coverage is out of date."
        )

    def test_shim_does_not_shadow_dto_module_object(self) -> None:
        """Submodule access must reach the real DTO module, not a wrapper.

        ``src.policy.approval`` MUST NOT bind a name called ``approval_dto``
        on itself in a way that masks the real submodule. Sanity check
        that ``src.policy.approval_dto`` is still the canonical module
        the shim re-exports from.
        """
        import sys

        assert "src.policy.approval_dto" in sys.modules
        assert "src.policy.approval_service" in sys.modules
        assert sys.modules["src.policy.approval_dto"] is approval_dto
        assert sys.modules["src.policy.approval_service"] is approval_service
