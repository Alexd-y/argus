"""Registry isolation for the sandbox parser-dispatch integration tests.

The parser dispatch registry (``src.sandbox.parsers._TOOL_TO_PARSER`` /
``_REGISTRY``) is process-global. Tests in *other* suites (e.g. MCP tool
catalog / dispatch tests) register or override parsers, and a per-file
``yield; reset_registry()`` only cleans up *after* a test — it does not
protect the *first* test in this package from state leaked by a preceding
suite. That made assertions like ``test_..._have_no_parser[skipfish]``
order-dependent: they passed in isolation (529/529) but failed inside the
full run.

Resetting to the default surface BOTH before and after every test in this
package makes the result independent of execution order, without weakening
any assertion.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from src.sandbox.parsers import reset_registry


@pytest.fixture(autouse=True)
def _isolate_parser_registry() -> Iterator[None]:
    reset_registry()
    yield
    reset_registry()
