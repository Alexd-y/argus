"""Trufflehog secrets scan adapter (secrets category §4.16)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class TrufflehogAdapter(ShellToolAdapter):
    """Adapter for ``trufflehog`` — file-system secret scanner.

    ``tool_id=trufflehog``, category=misc, requires_approval=False.
    Parser: :func:`src.sandbox.parsers.trufflehog_parser.parse_trufflehog_jsonl`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
