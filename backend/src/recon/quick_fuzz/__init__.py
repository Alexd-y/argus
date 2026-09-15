"""Quick Fuzzer — lightweight pre-scan before full VULN_ANALYSIS.

Sends targeted HTTP payloads to endpoints discovered during RECON and
identifies quick-win candidates that fed into the VULN_ANALYSIS phase
for deep testing with heavy tools (nuclei, sqlmap, dalfox, etc.).
"""

from src.recon.quick_fuzz.detection_sigs import DETECTION_SIGNATURES
from src.recon.quick_fuzz.payload_registry import (
    BUILTIN_PAYLOAD_CATEGORIES,
    BUILTIN_PAYLOADS,
)

__all__ = [
    "BUILTIN_PAYLOADS",
    "BUILTIN_PAYLOAD_CATEGORIES",
    "DETECTION_SIGNATURES",
]
