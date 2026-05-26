"""Quick Fuzzer — lightweight pre-scan before full VULN_ANALYSIS.

Sends targeted HTTP payloads to endpoints discovered during RECON and
identifies quick-win candidates that fed into the VULN_ANALYSIS phase
for deep testing with heavy tools (nuclei, sqlmap, dalfox, etc.).
"""

from src.recon.quick_fuzz.payload_registry import (
    BUILTIN_PAYLOAD_CATEGORIES,
    BUILTIN_PAYLOADS,
)
from src.recon.quick_fuzz.detection_sigs import DETECTION_SIGNATURES

__all__ = [
    "BUILTIN_PAYLOAD_CATEGORIES",
    "BUILTIN_PAYLOADS",
    "DETECTION_SIGNATURES",
]