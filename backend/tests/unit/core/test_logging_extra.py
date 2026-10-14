"""Worker/console logging must not drop structured ``extra`` fields.

Regression guard: Celery hijacked worker logging with a formatter that dropped
``extra={...}``, so ``evidence_arbiter_verdict`` (model_tier→arbiter_tier) was
invisible in ``podman logs``. configure_logging now renders extra in both the
JSON sink and the console formatter, and the Celery ``setup_logging`` signal
installs it on workers.
"""

from __future__ import annotations

import json
import logging

import pytest
from src.core.logging_config import ConsoleExtraFormatter, configure_logging


def _record(**extra: object) -> logging.LogRecord:
    rec = logging.LogRecord(
        name="argus.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="evidence_arbiter_verdict",
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(rec, key, value)
    return rec


def test_console_formatter_appends_extra() -> None:
    fmt = ConsoleExtraFormatter("%(levelname)s %(name)s %(message)s")
    out = fmt.format(_record(model_tier=3, arbiter_tier=2, applied_tier=2, finding_id="abc"))
    assert "evidence_arbiter_verdict" in out
    assert "model_tier=3" in out
    assert "arbiter_tier=2" in out
    assert "applied_tier=2" in out
    assert "finding_id='abc'" in out


def test_console_formatter_no_extra_is_plain() -> None:
    fmt = ConsoleExtraFormatter("%(levelname)s %(message)s")
    out = fmt.format(_record())
    assert out == "INFO evidence_arbiter_verdict"


@pytest.fixture
def _restore_root_logging():
    root = logging.getLogger()
    saved = list(root.handlers)
    saved_level = root.level
    yield
    for h in list(root.handlers):
        root.removeHandler(h)
    for h in saved:
        root.addHandler(h)
    root.setLevel(saved_level)


def test_configure_logging_console_renders_extra(monkeypatch, capsys, _restore_root_logging) -> None:
    from src.core import logging_config

    monkeypatch.setattr(logging_config.settings, "log_format", "console", raising=False)
    configure_logging()
    logging.getLogger("argus.test").info(
        "evidence_arbiter_verdict", extra={"model_tier": 3, "arbiter_tier": 1}
    )
    err = capsys.readouterr().out
    assert "evidence_arbiter_verdict" in err
    assert "model_tier=3" in err and "arbiter_tier=1" in err


def test_configure_logging_json_includes_extra(monkeypatch, capsys, _restore_root_logging) -> None:
    from src.core import logging_config

    monkeypatch.setattr(logging_config.settings, "log_format", "json", raising=False)
    configure_logging()
    logging.getLogger("argus.test").info(
        "evidence_arbiter_verdict", extra={"model_tier": 3, "arbiter_tier": 1, "applied_tier": 1}
    )
    line = capsys.readouterr().out.strip().splitlines()[-1]
    payload = json.loads(line)
    assert payload["message"] == "evidence_arbiter_verdict"
    assert payload["model_tier"] == 3
    assert payload["arbiter_tier"] == 1
    assert payload["applied_tier"] == 1


def test_celery_setup_logging_signal_installs_argus_logging(monkeypatch) -> None:
    import src.celery_app as celery_app

    called = {"n": 0}
    monkeypatch.setattr(
        "src.core.logging_config.configure_logging",
        lambda: called.__setitem__("n", called["n"] + 1),
    )
    celery_app._configure_argus_worker_logging()
    assert called["n"] == 1
