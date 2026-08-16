# Local orchestrator / fast models (Qwythos, Qwen, Gemma).
# GPU: docker build --build-arg GPU_MODE=gpu --build-arg MODEL_ID=<hf-or-path>
# CPU: docker build --build-arg GPU_MODE=cpu --build-arg MODEL_PATH=/models/model.gguf
#
# Weights are NOT fetched when this file is parsed. They load at image build
# (GPU vLLM) or first container start if the operator mounts a GGUF volume.

ARG GPU_MODE=cpu
ARG VLLM_IMAGE=vllm/vllm-openai:v0.8.5

FROM ${VLLM_IMAGE} AS gpu
ARG MODEL_ID=Qwen/Qwen2.5-3B-Instruct
ENV MODEL_ID=${MODEL_ID} \
    HF_HUB_ENABLE_HF_TRANSFER=1
COPY entrypoint_gpu.py /opt/argus/entrypoint_gpu.py
ENTRYPOINT ["python3", "/opt/argus/entrypoint_gpu.py"]

FROM python:3.12-slim AS cpu
ARG MODEL_PATH=/models/model.gguf
ENV MODEL_PATH=${MODEL_PATH} \
    N_CTX=4096
COPY entrypoint_cpu.py /opt/argus/entrypoint_cpu.py
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential ca-certificates curl git libgomp1 \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir llama-cpp-python[server]==0.3.8 \
    && apt-get purge -y build-essential git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["python3", "/opt/argus/entrypoint_cpu.py"]

FROM ${GPU_MODE}
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=120s \
    CMD curl -sf http://localhost:8000/v1/models || exit 1
