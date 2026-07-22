"""Web Workbench — message editor: raw/pretty/hex views (WB-P3b).

Byte-exact raw fidelity: pretty/hex are read-only derived projections; the raw
bytes are preserved verbatim for faithful replay.
"""

from src.web_workbench.message_editor.engine import (
    HttpMessageError,
    RawHttpMessage,
    hex_dump,
    parse_request,
    parse_response,
    pretty_request,
    pretty_response,
)

__all__ = [
    "HttpMessageError",
    "RawHttpMessage",
    "hex_dump",
    "parse_request",
    "parse_response",
    "pretty_request",
    "pretty_response",
]
