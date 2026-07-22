"""Web Workbench — Decoder: chainable byte-exact transforms (WB-P3a).

Pure, offline encode/decode/hash pipeline for manual analysis. Keyed operations
resolve secrets via an injected resolver (``secret_ref`` only — never inline).
"""

from src.web_workbench.decoder.engine import (
    DecoderError,
    SecretResolver,
    TransformContext,
    TransformStep,
    available_operations,
    run_pipeline,
)

__all__ = [
    "DecoderError",
    "SecretResolver",
    "TransformContext",
    "TransformStep",
    "available_operations",
    "run_pipeline",
]
