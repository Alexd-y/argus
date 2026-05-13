# WhiteRabbitNeo 7B — основной AI пентеста ARGUS
# vLLM OpenAI-совместимый сервер с AWQ-квантованной моделью
#
# GPU (production): docker build --build-arg GPU_MODE=gpu
# CPU (dev/fallback): docker build --build-arg GPU_MODE=cpu

ARG GPU_MODE=gpu

# === GPU-режим: vLLM ===
FROM vllm/vllm-openai:latest AS gpu
ENV HF_HUB_ENABLE_HF_TRANSFER=1 \
    VLLM_MODEL=taico-ai/WhiteRabbitNeo-v3-7B
ENTRYPOINT ["python3", "-m", "vllm.entrypoints.openai.api_server"]
CMD ["--model", "taico-ai/WhiteRabbitNeo-v3-7B", \
     "--quantization", "awq", \
     "--max-model-len", "8192", \
     "--gpu-memory-utilization", "0.90", \
     "--dtype", "auto", \
     "--host", "0.0.0.0", \
     "--port", "8000"]

# === CPU-режим: llama-cpp-python (dev/fallback) ===
FROM python:3.12-slim AS cpu
COPY ensure_gguf.py entrypoint_cpu.py /opt/argus/
# slim: нет gcc (build-essential), git (CMake), libgomp (OpenMP в libllama.so при сборке).
# huggingface_hub — автозагрузка GGUF в пустой volume /models при первом старте.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential ca-certificates curl git libgomp1 \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir \
       "huggingface_hub>=0.23.0" \
       llama-cpp-python[server]==0.3.8 \
    && apt-get purge -y build-essential git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
ENV MODEL_PATH=/models/WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-Q4_K_M.gguf
ENTRYPOINT ["python3", "/opt/argus/entrypoint_cpu.py"]
CMD ["--model", "/models/WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-Q4_K_M.gguf", \
     "--n_ctx", "4096", \
     "--host", "0.0.0.0", \
     "--port", "8000"]

FROM ${GPU_MODE}
EXPOSE 8000
# CPU: первый старт может долго качать GGUF (~4 GiB); GPU: vLLM прогрев модели.
HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=900s \
    CMD curl -sf http://localhost:8000/v1/models || exit 1
