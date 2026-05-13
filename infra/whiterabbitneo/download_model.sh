#!/bin/bash
# WhiteRabbitNeo model downloader — run once before container start.
# Set HF_TOKEN env var to authenticate with HuggingFace.
#
# GPU mode: downloads WhiteRabbitNeo-7B-AWQ for vLLM
# CPU mode: downloads WhiteRabbitNeo-7B-Q4_K_M.gguf for llama.cpp
#
# Usage:
#   GPU: ./download_model.sh gpu /models
#   CPU: ./download_model.sh cpu /models

set -euo pipefail

MODE="${1:-cpu}"
MODEL_DIR="${2:-/models}"

download_awq() {
    local target="${MODEL_DIR}/WhiteRabbitNeo-7B-AWQ"
    if [ -f "${target}/config.json" ]; then
        echo "[WRB] AWQ model already present at ${target}, skipping download."
        return 0
    fi

    echo "[WRB] Downloading WhiteRabbitNeo-7B-AWQ (GPU/vLLM)..."
    mkdir -p "${target}"

    if command -v huggingface-cli >/dev/null 2>&1; then
        if [ -n "${HF_TOKEN:-}" ]; then
            huggingface-cli login --token "${HF_TOKEN}" 2>/dev/null || true
        fi
        huggingface-cli download WhiteRabbitNeo/WhiteRabbitNeo-7B-AWQ --local-dir "${target}" --local-dir-use-symlinks False
    else
        echo "[WRB] huggingface-cli not found, using Python HF API..."
        python3 -c "
import os, sys
from huggingface_hub import snapshot_download
snapshot_download(
    'WhiteRabbitNeo/WhiteRabbitNeo-7B-AWQ',
    local_dir='${target}',
    local_dir_use_symlinks=False,
    token=os.environ.get('HF_TOKEN'),
    resume_download=True,
)
"
    fi
    echo "[WRB] AWQ model download complete."
}

download_gguf() {
    local quant="${WRB_CPU_QUANT:-Q4_K_M}"
    local filename="WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-${quant}.gguf"
    local target="${MODEL_DIR}/${filename}"

    if [ -f "${target}" ] && [ "$(stat -c%s "${target}" 2>/dev/null || echo 0)" -gt 1000000000 ]; then
        echo "[WRB] GGUF model already present at ${target} (size ok), skipping download."
        return 0
    fi

    echo "[WRB] Downloading ${filename} for CPU/llama.cpp..."
    mkdir -p "${MODEL_DIR}"

    if command -v huggingface-cli >/dev/null 2>&1; then
        if [ -n "${HF_TOKEN:-}" ]; then
            huggingface-cli login --token "${HF_TOKEN}" 2>/dev/null || true
        fi
        local gguf_repo="${WRB_GGUF_REPO:-bartowski/WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-GGUF}"
        huggingface-cli download "${gguf_repo}" "${filename}" --local-dir "${MODEL_DIR}" --local-dir-use-symlinks False
    else
        echo "[WRB] huggingface-cli not found, using wget/curl from HF mirror..."
        local gguf_repo="${WRB_GGUF_REPO:-bartowski/WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-GGUF}"
        local hf_url="https://huggingface.co/${gguf_repo}/resolve/main/${filename}"
        if command -v wget >/dev/null 2>&1; then
            wget --header "Authorization: Bearer ${HF_TOKEN:-}" -O "${target}" "${hf_url}" || true
        elif command -v curl >/dev/null 2>&1; then
            curl -H "Authorization: Bearer ${HF_TOKEN:-}" -L -o "${target}" "${hf_url}" || true
        fi
    fi

    if [ -f "${target}" ]; then
        local sz
        sz=$(stat -c%s "${target}" 2>/dev/null || echo 0)
        echo "[WRB] GGUF model downloaded: ${target} (${sz} bytes)"
    else
        echo "[WRB] WARNING: GGUF model download may have failed. Check HF_TOKEN and network."
        return 1
    fi
}

case "${MODE}" in
    gpu|GPU)
        download_awq
        ;;
    cpu|CPU)
        download_gguf
        ;;
    *)
        echo "Usage: $0 {gpu|cpu} [model_dir]"
        exit 1
        ;;
esac

echo "[WRB] Model ready."
