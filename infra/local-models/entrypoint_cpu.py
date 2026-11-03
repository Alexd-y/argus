"""CPU entrypoint: llama.cpp OpenAI-compatible server from MODEL_PATH."""

from __future__ import annotations

import os
import sys


def main() -> None:
    model = (os.environ.get("MODEL_PATH") or "").strip()
    if not model:
        raise SystemExit("MODEL_PATH is required")
    extra = sys.argv[1:]
    # Register the served model under MODEL_ID so an OpenAI-compatible request whose
    # `model` field is the logical id (e.g. the router's "qwythos-9b-claude-mythos-5-1m")
    # resolves to the loaded GGUF instead of 404-ing on an unknown model. Caller-supplied
    # --model_alias in `extra` still wins (not added when already present).
    model_id = (os.environ.get("MODEL_ID") or "").strip()
    alias_args: list[str] = []
    if model_id and "--model_alias" not in extra:
        alias_args = ["--model_alias", model_id]
    argv = [
        sys.executable,
        "-m",
        "llama_cpp.server",
        "--model",
        model,
        "--n_ctx",
        os.environ.get("N_CTX", "4096"),
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
        *alias_args,
        *extra,
    ]
    os.execvp(sys.executable, argv)


if __name__ == "__main__":
    main()
