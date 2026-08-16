"""CPU entrypoint: llama.cpp OpenAI-compatible server from MODEL_PATH."""

from __future__ import annotations

import os
import sys


def main() -> None:
    model = (os.environ.get("MODEL_PATH") or "").strip()
    if not model:
        raise SystemExit("MODEL_PATH is required")
    extra = sys.argv[1:]
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
        *extra,
    ]
    os.execvp(sys.executable, argv)


if __name__ == "__main__":
    main()
