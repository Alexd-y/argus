"""Web Workbench — Intruder: attack strategies + processors + analysis (WB-P4a).

Pure, offline generation core. Payload sets are supplied by the caller and MUST
be materialised through the signed PayloadRegistry / PayloadBuilder (SI-5); this
package never sources payloads or performs any network I/O.
"""

from src.web_workbench.intruder.analysis import (
    AnalysisError,
    DedupResult,
    dedup,
    grep_extract,
    grep_match,
)
from src.web_workbench.intruder.engine import (
    IntruderRequest,
    generate_requests,
    planned_total,
)
from src.web_workbench.intruder.positions import (
    IntruderError,
    ParsedTemplate,
    parse_template,
)
from src.web_workbench.intruder.processors import (
    Processor,
    ProcessorError,
    apply_processors,
)
from src.web_workbench.intruder.strategies import (
    Strategy,
    iter_assignments,
    total_requests,
)

__all__ = [
    "AnalysisError",
    "DedupResult",
    "IntruderError",
    "IntruderRequest",
    "ParsedTemplate",
    "Processor",
    "ProcessorError",
    "Strategy",
    "apply_processors",
    "dedup",
    "generate_requests",
    "grep_extract",
    "grep_match",
    "iter_assignments",
    "parse_template",
    "planned_total",
    "total_requests",
]
