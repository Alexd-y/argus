"""CPU entrypoint: ensure GGUF, then exec llama_cpp.server."""
from __future__ import annotations

import os
import subprocess
import sys


def main() -> None:
    argv = sys.argv[1:]
    model: str | None = None
    i = 0
    while i < len(argv):
        if argv[i] == "--model" and i + 1 < len(argv):
            model = argv[i + 1]
            break
        i += 1
    if not model:
        q = (os.environ.get("WRB_CPU_QUANT") or "Q4_K_M").strip()
        model = f"/models/WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-{q}.gguf"
    os.environ["WRB_GGUF_PATH"] = model

    subprocess.run([sys.executable, "/opt/argus/ensure_gguf.py"], check=True)
    os.execvp(sys.executable, [sys.executable, "-m", "llama_cpp.server", *argv])


if __name__ == "__main__":
    main()
