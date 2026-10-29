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

    # Context window is tunable via WRB_N_CTX (default 8192) without rebuilding the
    # image, as long as the caller did not pass --n_ctx explicitly. The backend
    # adapter's WHITERABBITNEO_MAX_CONTEXT_TOKENS MUST match this value, or large
    # prompts overflow the served window and are rejected with HTTP 400.
    if not any(a in ("--n_ctx", "--n-ctx") for a in argv):
        n_ctx = (os.environ.get("WRB_N_CTX") or "8192").strip()
        argv = [*argv, "--n_ctx", n_ctx]

    # CPU throughput tuning. The scan wall-clock bottleneck was prompt eval on the
    # large analysis prompts: llama_cpp.server defaults to n_batch=512 and does not
    # pin batch threads, so a ~13k-token prompt ingested at ~10 tok/s (~22 min) on a
    # 32-vCPU host. Pin batch threads to all vCPUs and raise the batch so prompt
    # ingestion parallelises; generation threads default to the physical-core
    # estimate (HT gives little on the memory-bound decode). Each is env-tunable
    # (WRB_N_THREADS / WRB_N_THREADS_BATCH / WRB_N_BATCH) without another rebuild,
    # and only added when the caller did not pass it explicitly.
    _cpu = os.cpu_count() or 8
    _cpu_defaults = (
        ("--n_threads", os.environ.get("WRB_N_THREADS") or str(max(1, _cpu // 2))),
        ("--n_threads_batch", os.environ.get("WRB_N_THREADS_BATCH") or str(_cpu)),
        ("--n_batch", os.environ.get("WRB_N_BATCH") or "2048"),
    )
    for _flag, _val in _cpu_defaults:
        _val = (_val or "").strip()
        if _val and not any(a in (_flag, _flag.replace("_", "-")) for a in argv):
            argv = [*argv, _flag, _val]

    subprocess.run([sys.executable, "/opt/argus/ensure_gguf.py"], check=True)
    os.execvp(sys.executable, [sys.executable, "-m", "llama_cpp.server", *argv])


if __name__ == "__main__":
    main()
