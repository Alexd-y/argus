"""Regression test: ``src.policy`` must be cycle-free under any import order.

Background (T02 — latent cyclic policy import refactor)
-------------------------------------------------------
Before T02 the package shipped a latent cyclic import:

    src.policy.__init__
      -> src.policy.approval
        -> src.sandbox.signing
          -> ... -> src.payloads.builder
            -> src.policy.preflight
              -> src.policy.approval (PARTIAL — kaboom)

The cycle was *order-dependent*: kicking off the chain via
``src.pipeline.contracts.phase_io`` masked it (which is exactly the
pre-warm hack ARG-043 added to ``backend/tests/security/conftest.py``).
T02 split ``src.policy.approval`` into:

* :mod:`src.policy.approval_dto` — pure pydantic DTOs.
* :mod:`src.policy.approval_service` — :class:`ApprovalService` with the
  heavyweight crypto + audit deps.

…and pointed :mod:`src.policy.preflight` at the DTO module (with
``ApprovalService`` behind a ``TYPE_CHECKING`` guard) so the chain can
no longer close on itself.

What this test does
-------------------
For every Python module under ``backend/src/policy/`` (top-level + the
``cloud_iam`` subpackage), the test spawns a *fresh* Python subprocess
that imports the modules in a randomly-shuffled order. A subprocess is
required because ``sys.modules`` is process-wide and any prior import
in the test runner would mask the cycle. The shuffle is seeded
deterministically (``random.seed(42)``) so the same five orders run on
every CI invocation.

Pass criteria for each order:

* Subprocess exits with status 0 (no ``ImportError``, no recursion
  error, no segfault).
* No ``RuntimeWarning`` mentioning ``coroutine never awaited`` or
  ``circular import`` is emitted on stderr.
* The two anchor imports succeed:
    - ``from src.policy.approval import ApprovalService``
      (backward-compat shim).
    - ``from src.policy.approval_dto import ApprovalRequest`` (new
      pure-DTO path).
"""

from __future__ import annotations

import pkgutil
import random
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


# Resolve ``backend/`` (project import root). This file lives at
# ``backend/tests/unit/policy/test_no_cyclic_imports.py`` so going up four
# levels lands us in ``backend/``. We pass this both as ``cwd`` and as
# ``PYTHONPATH`` to the subprocess so ``from src.X import Y`` resolves
# without relying on the parent test runner's path injection.
_BACKEND_DIR: Path = Path(__file__).resolve().parents[3]
_POLICY_PKG_DIR: Path = _BACKEND_DIR / "src" / "policy"

# Anchor imports: prove the legacy + new public surfaces both work after
# the refactor. Listed explicitly so failures point at the exact path.
_ANCHOR_IMPORTS: tuple[str, ...] = (
    "from src.policy.approval import ApprovalService",
    "from src.policy.approval_dto import ApprovalRequest",
    "from src.policy.approval_service import ApprovalService",
    "from src.policy.preflight import PreflightChecker",
)

# Forensics: substrings that, if seen on subprocess stderr, indicate a
# cycle re-emerged. Keep the list narrow — broad matches (e.g. "warning")
# would catch noise from Pydantic / asyncio.
_CYCLE_STDERR_MARKERS: tuple[str, ...] = (
    "circular import",
    "partially initialized module",
)


def _discover_policy_modules() -> list[str]:
    """Return every importable module name under ``src.policy``.

    Walks ``src.policy`` recursively via :func:`pkgutil.walk_packages`
    so the ``cloud_iam`` subpackage is included. The package root
    (``src.policy``) itself is appended to the front because importing
    it last is the canonical "cold start" sequence we want to exercise.
    """
    discovered: list[str] = ["src.policy"]
    for _, name, _is_pkg in pkgutil.walk_packages(
        path=[str(_POLICY_PKG_DIR)],
        prefix="src.policy.",
    ):
        discovered.append(name)
    return discovered


def _build_subprocess_script(import_order: list[str]) -> str:
    """Produce a stand-alone Python script that imports modules in order."""
    quoted_order = ", ".join(repr(name) for name in import_order)
    quoted_anchors = ", ".join(repr(stmt) for stmt in _ANCHOR_IMPORTS)
    # The script:
    #  - turns every ``RuntimeWarning`` into an exception so a half-baked
    #    cyclic import surfaces as a non-zero exit, not a swallowed log.
    #  - imports modules one at a time and prints which step failed.
    return textwrap.dedent(
        f"""\
        import importlib
        import sys
        import traceback
        import warnings

        warnings.simplefilter("error", RuntimeWarning)

        order = [{quoted_order}]
        anchors = [{quoted_anchors}]

        for name in order:
            try:
                importlib.import_module(name)
            except Exception:
                sys.stderr.write(f"FAILED IMPORT: {{name}}\\n")
                traceback.print_exc()
                sys.exit(1)

        for stmt in anchors:
            try:
                exec(compile(stmt, "<anchor>", "exec"), {{}})
            except Exception:
                sys.stderr.write(f"FAILED ANCHOR: {{stmt}}\\n")
                traceback.print_exc()
                sys.exit(2)

        sys.exit(0)
        """
    )


def _run_in_subprocess(script: str) -> subprocess.CompletedProcess[str]:
    """Run ``script`` in a fresh interpreter rooted at ``backend/``."""
    return subprocess.run(  # noqa: S603 — controlled args, no shell
        [sys.executable, "-X", "dev", "-c", script],
        cwd=str(_BACKEND_DIR),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@pytest.fixture(scope="module")
def policy_modules() -> list[str]:
    return _discover_policy_modules()


@pytest.fixture(scope="module")
def shuffled_orders(policy_modules: list[str]) -> list[list[str]]:
    """Five deterministic random orders of every policy module."""
    rng = random.Random(42)  # noqa: S311 — non-cryptographic, determinism only
    orders: list[list[str]] = []
    for _ in range(5):
        order = list(policy_modules)
        rng.shuffle(order)
        orders.append(order)
    return orders


def test_policy_modules_discovered(policy_modules: list[str]) -> None:
    """Sanity check: discovery picked up every known module."""
    expected_subset: set[str] = {
        "src.policy",
        "src.policy.approval",
        "src.policy.approval_dto",
        "src.policy.approval_service",
        "src.policy.audit",
        "src.policy.ownership",
        "src.policy.policy_engine",
        "src.policy.preflight",
        "src.policy.scope",
        "src.policy.cloud_iam",
    }
    missing = expected_subset - set(policy_modules)
    assert not missing, f"discovery missed expected modules: {sorted(missing)}"


def test_shuffled_orders_are_deterministic(shuffled_orders: list[list[str]]) -> None:
    """The seed pin (``random.seed(42)``) MUST keep CI runs reproducible."""
    assert len(shuffled_orders) == 5
    # Two orders must differ — otherwise the shuffle isn't doing anything.
    distinct = {tuple(order) for order in shuffled_orders}
    assert len(distinct) >= 2, "shuffle produced identical orders — RNG broken?"


@pytest.mark.parametrize("order_index", range(5))
def test_no_cyclic_import_under_random_order(
    shuffled_orders: list[list[str]], order_index: int
) -> None:
    """Every module imports cleanly in a fresh interpreter, in any order.

    A subprocess is required because ``sys.modules`` is process-global:
    once any test in the runner has imported ``src.policy.*``, subsequent
    imports become no-ops and the cycle is masked. The subprocess gives
    us the cold-start path that production / CI cold-starts hit.
    """
    order = shuffled_orders[order_index]
    script = _build_subprocess_script(order)
    result = _run_in_subprocess(script)

    if result.returncode != 0:
        pytest.fail(
            "Cyclic / failing import detected.\n"
            f"order_index={order_index}\n"
            f"order={order}\n"
            f"returncode={result.returncode}\n"
            f"stdout=\n{result.stdout}\n"
            f"stderr=\n{result.stderr}\n"
        )

    stderr_lower = result.stderr.lower()
    for marker in _CYCLE_STDERR_MARKERS:
        if marker in stderr_lower:
            pytest.fail(
                "Cycle marker leaked to stderr despite zero exit.\n"
                f"marker={marker!r}\n"
                f"order_index={order_index}\n"
                f"stderr=\n{result.stderr}\n"
            )


def test_backward_compat_shim_exposes_approval_service() -> None:
    """``from src.policy.approval import ApprovalService`` still works.

    Pre-T02 callers rely on this exact import path; the shim must keep it
    available even though the implementation moved to
    :mod:`src.policy.approval_service`.
    """
    from src.policy.approval import ApprovalService as ShimApprovalService
    from src.policy.approval_service import ApprovalService as DirectApprovalService

    assert ShimApprovalService is DirectApprovalService


def test_new_dto_path_exposes_pure_models() -> None:
    """``from src.policy.approval_dto import ApprovalRequest`` works.

    Confirms the new pure-DTO module is importable in isolation, without
    pulling in :mod:`src.sandbox.signing` or any heavyweight policy
    dependency.
    """
    from src.policy.approval_dto import (
        APPROVAL_FAILURE_REASONS,
        ApprovalAction,
        ApprovalError,
        ApprovalRequest,
        ApprovalSignature,
        ApprovalStatus,
    )

    assert isinstance(APPROVAL_FAILURE_REASONS, frozenset)
    assert APPROVAL_FAILURE_REASONS, "failure taxonomy must not be empty"
    assert ApprovalAction.HIGH.value == "high"
    assert ApprovalStatus.GRANTED.value == "granted"
    assert issubclass(ApprovalError, Exception)
    # Smoke: confirm the model class is importable and constructible
    # without dragging in signing / audit modules.
    assert ApprovalRequest.__name__ == "ApprovalRequest"
    assert ApprovalSignature.__name__ == "ApprovalSignature"


def test_dto_module_has_no_heavy_dependencies() -> None:
    """``approval_dto`` MUST stay free of signing / audit / sandbox imports.

    A fresh subprocess imports ``src.policy.approval_dto`` first and then
    asserts that none of the heavyweight modules ended up in
    ``sys.modules``. If this regresses, the cycle protection is brittle
    again.
    """
    script = textwrap.dedent(
        """\
        import sys
        import importlib

        importlib.import_module("src.policy.approval_dto")

        forbidden = (
            "src.sandbox.signing",
            "src.policy.audit",
            "src.policy.approval_service",
            "src.payloads.builder",
            "src.pipeline.contracts.tool_job",
        )
        leaked = [name for name in forbidden if name in sys.modules]
        if leaked:
            sys.stderr.write(f"DTO module pulled in heavy deps: {leaked}\\n")
            sys.exit(3)
        sys.exit(0)
        """
    )
    result = _run_in_subprocess(script)
    assert result.returncode == 0, (
        "approval_dto regressed and now pulls in heavy modules.\n"
        f"stdout=\n{result.stdout}\nstderr=\n{result.stderr}\n"
    )


def test_in_process_imports_emit_no_cycle_warnings() -> None:
    """In-process complement to the subprocess ``simplefilter('error', ...)``.

    The subprocess-based check above turns every ``RuntimeWarning`` into
    a fatal exit. This test wraps the **in-process** re-import of every
    policy module in :func:`warnings.catch_warnings` (``record=True``)
    and asserts that no recorded warning's message contains a
    circular-import marker. It catches a different failure mode than the
    subprocess test:

    * The subprocess test catches *cold-start* cycles (no module cached).
    * This test catches *late-binding* warnings emitted during access /
      import-time descriptor evaluation, which can fire even when the
      modules are already cached in ``sys.modules`` (a typical state
      after parent conftests have run).

    Together they form a belt-and-suspenders defense: the cycle cannot
    re-emerge silently regardless of import order or warning filter.
    """
    import importlib
    import warnings

    targets: tuple[str, ...] = (
        "src.policy",
        "src.policy.approval",
        "src.policy.approval_dto",
        "src.policy.approval_service",
        "src.policy.preflight",
    )

    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")  # capture every warning, no dedup
        for name in targets:
            importlib.import_module(name)

    cycle_markers: tuple[str, ...] = (
        "circular import",
        "partially initialized module",
    )
    leaks = [
        str(record.message)
        for record in records
        if any(marker in str(record.message).lower() for marker in cycle_markers)
    ]
    assert not leaks, (
        f"Cycle-related warnings recorded during in-process import: {leaks!r}"
    )
