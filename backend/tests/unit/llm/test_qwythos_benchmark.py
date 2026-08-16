"""Qwythos 8k/32k/64k context-window benchmark (DoD §22)."""

from __future__ import annotations

from src.llm.qwythos_benchmark import (
    WINDOWS_TOKENS,
    evaluate_window,
    live_qwythos_invoke,
    run_qwythos_benchmark,
    synthetic_prompt_tokens,
)


def test_windows_cover_8k_32k_64k() -> None:
    assert WINDOWS_TOKENS == (8192, 32768, 65536)


def test_synthetic_prompt_tokens_does_not_materialise_payload() -> None:
    assert synthetic_prompt_tokens(8192) == 8192


def test_overflow_rejected_without_invoke() -> None:
    result = evaluate_window(tokens=65536, advertised_max_context=32768)
    assert result.accepted is False
    assert result.error_code == "context_overflow"


def test_full_benchmark_accepts_when_model_is_64k() -> None:
    results = run_qwythos_benchmark(advertised_max_context=65536)
    assert [r.accepted for r in results] == [True, True, True]


def test_live_invoke_hook_records_latency() -> None:
    def invoke(tokens: int) -> tuple[bool, int, str | None]:
        return True, 12, None

    results = run_qwythos_benchmark(advertised_max_context=65536, invoke=invoke)
    assert all(r.latency_ms == 12 for r in results)


def test_live_http_ping_when_url_set(monkeypatch) -> None:
    class _Response:
        status_code = 200

    class _Client:
        def __init__(self, *args: object, **kwargs: object) -> None:
            return None

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> bool:
            return False

        def post(self, url: str, json: dict) -> _Response:
            assert url.endswith("/chat/completions")
            assert json["max_tokens"] == 1
            return _Response()

    monkeypatch.setenv("QWYTHOS_URL", "http://qwythos:8000/v1")
    monkeypatch.setattr("src.llm.qwythos_benchmark.httpx.Client", _Client)
    ok, latency_ms, error_code = live_qwythos_invoke(8192, base_url="http://qwythos:8000/v1")
    assert ok is True
    assert error_code is None
    assert latency_ms >= 0
    results = run_qwythos_benchmark(advertised_max_context=65536)
    assert [r.accepted for r in results] == [True, True, True]
