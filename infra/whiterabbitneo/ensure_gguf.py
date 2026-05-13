"""Скачать WhiteRabbitNeo-V3 GGUF в /models при отсутствии файла (CPU / llama.cpp).

Путь к файлу: WRB_GGUF_PATH (выставляет entrypoint из --model или WRB_CPU_QUANT).
Репозиторий: bartowski/WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-GGUF (проверен, существует).
"""
from __future__ import annotations

import os
from pathlib import Path

MIN_BYTES = 500 * 1024 * 1024
_REPO_CANDIDATES = [
    os.environ.get("WRB_GGUF_REPO"),
    "bartowski/WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-GGUF",
    "TheBloke/WhiteRabbitNeo-7B-GGUF",
    "WhiteRabbitNeo/WhiteRabbitNeo-7B",
]


def _hf_token() -> str | None:
    raw = (os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_HUB_TOKEN") or "").strip()
    return raw or None


def _is_unauthorized(exc: BaseException) -> bool:
    s = f"{type(exc).__name__} {exc!s}".lower()
    if "401" in s or "unauthorized" in s or "invalid username" in s:
        return True
    cause = getattr(exc, "__cause__", None)
    if cause is not None and cause is not exc:
        return _is_unauthorized(cause)
    ctx = getattr(exc, "__context__", None)
    if ctx is not None and ctx is not exc:
        return _is_unauthorized(ctx)
    return False


def _download(filename: str, parent: Path, token: bool | str | None, repo: str) -> Path:
    from huggingface_hub import hf_hub_download

    path = hf_hub_download(
        repo_id=repo,
        filename=filename,
        local_dir=str(parent),
        token=token,
    )
    return Path(path).resolve()


def main() -> int:
    quant = (os.environ.get("WRB_CPU_QUANT") or "Q4_K_M").strip()
    default = Path("/models") / f"WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-{quant}.gguf"
    dest = Path(os.environ.get("WRB_GGUF_PATH") or str(default)).resolve()

    if dest.is_file() and dest.stat().st_size >= MIN_BYTES:
        print(f"[WRB] GGUF уже есть: {dest} ({dest.stat().st_size} bytes)", flush=True)
        return 0

    filename = dest.name
    parent = dest.parent
    parent.mkdir(parents=True, exist_ok=True)
    hub_token = _hf_token()
    token_arg: bool | str = hub_token if hub_token else False

    candidates = [r for r in _REPO_CANDIDATES if r]

    for repo in candidates:
        print(f"[WRB] Пробуем {filename} из {repo} …", flush=True)
        try:
            got = _download(filename, parent, token_arg, repo)
            if got.is_file() and got.stat().st_size >= MIN_BYTES:
                print(f"[WRB] Модель готова: {got} ({got.stat().st_size} bytes)", flush=True)
                return 0
        except Exception as e:
            if _is_unauthorized(e):
                print(f"[WRB] 401 от {repo}, пробуем без токена …", flush=True)
                try:
                    got = _download(filename, parent, False, repo)
                    if got.is_file() and got.stat().st_size >= MIN_BYTES:
                        print(f"[WRB] Модель готова (без токена): {got} ({got.stat().st_size} bytes)", flush=True)
                        return 0
                except Exception:
                    print(f"[WRB] Без токена тоже ошибка: {repo}", flush=True)
            else:
                print(f"[WRB] Ошибка загрузки из {repo}: {e}", flush=True)

    print(
        "[WRB] Все источники исчерпаны. "
        "Укажите WRB_GGUF_REPO с существующим репозиторием. "
        "Проверьте https://huggingface.co/bartowski",
        flush=True,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
