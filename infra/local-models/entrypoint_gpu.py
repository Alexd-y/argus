"""GPU entrypoint: start vLLM OpenAI server for the baked MODEL_ID."""

from __future__ import annotations

import os
import sys


def main() -> None:
    model = (os.environ.get("MODEL_ID") or "").strip()
    if not model:
        raise SystemExit("MODEL_ID is required")
    argv = [
        sys.executable,
        "-m",
        "vllm.entrypoints.openai.api_server",
        "--model",
        model,
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
        *sys.argv[1:],
    ]
    os.execvp(sys.executable, argv)


if __name__ == "__main__":
    main()
