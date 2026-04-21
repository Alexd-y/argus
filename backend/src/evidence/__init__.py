"""Evidence persistence + redaction module.

Public surface:

* :class:`Redactor`, :class:`RedactionSpec`, :class:`RedactionReport`,
  :class:`RedactedContent`, :func:`default_specs` — binary-safe redaction.
* :class:`EvidencePipeline`, :class:`StorageUploaderProtocol`,
  :class:`EvidencePersistError` — redact → upload → audit.
"""

from src.evidence.pipeline import (
    EvidencePersistError,
    EvidencePipeline,
    StorageUploaderProtocol,
)
from src.evidence.redaction import (
    RedactedContent,
    RedactionReport,
    RedactionSpec,
    Redactor,
    default_specs,
)

__all__ = [
    "EvidencePersistError",
    "EvidencePipeline",
    "RedactedContent",
    "RedactionReport",
    "RedactionSpec",
    "Redactor",
    "StorageUploaderProtocol",
    "default_specs",
]
